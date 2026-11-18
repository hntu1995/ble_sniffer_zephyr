/*
 * BLE advertising sniffer using the nRF52840 RADIO peripheral directly.
 *
 * Phase 1 listens to advertising channels 37/38/39 with a configurable dwell.
 * Register configuration mirrors Zephyr's own BLE controller:
 *   - S0 = LL header byte, LENGTH = PDU length, no S1
 *   - 4-byte access address (3-byte base + 1-byte prefix)
 *   - BLE CRC (3 bytes, address skipped), whitening enabled
 *   - FREQUENCY is the offset from 2400 MHz (ch37=2, ch38=26, ch39=80)
 *
 * The radio writes [LL header][length][payload] to RAM; the firmware prepends
 * the advertising AA and appends three placeholder CRC bytes for Wireshark.
 */

#include <zephyr/kernel.h>
#include <zephyr/irq.h>
#include <zephyr/sys/util.h>
#include <soc.h>
#include <string.h>

#include "radio_sniffer.h"
#include "sniffer_proto.h"

#define RING_SLOTS 64
#define RING_MASK (RING_SLOTS - 1)

struct sniff_slot {
	uint32_t total;
	uint8_t data[SNIFF_MAX_FRAME];
};

static struct sniff_slot ring[RING_SLOTS] __aligned(4);
static volatile uint32_t ring_head;
static volatile uint32_t ring_tail;
static volatile uint32_t drop_count;

/* Radio DMA target: [LL header][length][payload].
 * The extra 4 bytes are defensive padding: some nRF variants/erratas write
 * more than the logical PDU when a length field is corrupted.
 */
static uint8_t pkt_buf[2 + SNIFF_MAX_PDU_LEN + 4] __aligned(4);

static volatile bool rx_active;
static volatile uint8_t cur_channel = 37;
static uint32_t dwell_ms = 10;

static const uint8_t adv_channels[] = {37, 38, 39};
static const uint8_t adv_freq_offset[] = {2, 26, 80}; /* 2400 + x MHz */
static uint32_t hop_index;
static int64_t next_hop_ms;

static void packet_isr(void);

static void radio_clear_events(void)
{
	NRF_RADIO->EVENTS_END = 0;
	NRF_RADIO->EVENTS_ADDRESS = 0;
	NRF_RADIO->EVENTS_CRCOK = 0;
	NRF_RADIO->EVENTS_CRCERROR = 0;
	NRF_RADIO->EVENTS_DISABLED = 0;
}

static void push_packet(uint32_t ts_us, uint8_t rssi_sample, bool crc_ok)
{
	uint32_t plen = pkt_buf[1];
	uint32_t payload_len;
	uint32_t head = ring_head;

	if (plen > SNIFF_MAX_PDU_LEN) {
		return;
	}

	payload_len = 4U + 2U + plen + 3U;

	if ((head - ring_tail) >= RING_SLOTS) {
		drop_count++;
		return;
	}

	struct sniff_slot *slot = &ring[head & RING_MASK];
	struct sniff_frame_hdr *hdr = (struct sniff_frame_hdr *)slot->data;

	hdr->magic[0] = SNIFF_MAGIC0;
	hdr->magic[1] = SNIFF_MAGIC1;
	hdr->version = SNIFF_VERSION;
	hdr->type = SNIFF_TYPE_PACKET;
	hdr->payload_len = (uint16_t)payload_len;
	hdr->timestamp_us = ts_us;
	hdr->channel = cur_channel;
	hdr->rssi_dbm = (int8_t)-(int8_t)(rssi_sample & 0x7FU);
	hdr->flags = SNIFF_FLAG_CRC_CHECKED | SNIFF_FLAG_DEWHITENED |
		     SNIFF_FLAG_AA_VALID;
	if (crc_ok) {
		hdr->flags |= SNIFF_FLAG_CRC_OK;
	}
	hdr->reserved = 0;

	memcpy(&slot->data[SNIFF_HDR_SIZE], SNIFF_ADV_AA, 4);
	/* LL header + length + payload, exactly as received and dewhitened. */
	memcpy(&slot->data[SNIFF_HDR_SIZE + 4], pkt_buf, 2U + plen);
	/* CRC bytes are not written to RAM on RX; Wireshark is told the status. */
	memset(&slot->data[SNIFF_HDR_SIZE + 4 + 2 + plen], 0, 3);

	slot->total = SNIFF_HDR_SIZE + payload_len;
	/* Publish only after the slot is fully written. */
	__DMB();
	ring_head = head + 1U;
}

static void packet_isr(void)
{
	if (NRF_RADIO->EVENTS_END != 0U) {
		bool crc_ok = NRF_RADIO->EVENTS_CRCOK != 0U;
		bool crc_err = NRF_RADIO->EVENTS_CRCERROR != 0U;
		uint8_t rssi_sample;

		NRF_RADIO->EVENTS_END = 0;
		NRF_RADIO->EVENTS_CRCOK = 0;
		NRF_RADIO->EVENTS_CRCERROR = 0;

		/* Capture before doing any work so timestamps stay tight. */
		NRF_TIMER1->TASKS_CAPTURE[0] = 1;
		rssi_sample = (uint8_t)NRF_RADIO->RSSISAMPLE;

		if (crc_ok || crc_err) {
			push_packet(NRF_TIMER1->CC[0], rssi_sample, crc_ok);
		}
	}

	if (NRF_RADIO->EVENTS_DISABLED != 0U) {
		NRF_RADIO->EVENTS_DISABLED = 0;
		if (rx_active) {
			radio_clear_events();
			NRF_RADIO->PACKETPTR = (uint32_t)pkt_buf;
			NRF_RADIO->TASKS_RXEN = 1;
		}
	}
}

static void select_channel(uint8_t channel, uint8_t freq_offset)
{
	unsigned int key = irq_lock();

	rx_active = false;

	if (NRF_RADIO->STATE != 0U) {
		NRF_RADIO->EVENTS_DISABLED = 0;
		NRF_RADIO->TASKS_DISABLE = 1;
		for (volatile int i = 0; i < 20000; i++) {
			if (NRF_RADIO->EVENTS_DISABLED != 0U) {
				break;
			}
		}
		NRF_RADIO->EVENTS_DISABLED = 0;
	}

	cur_channel = channel;
	NRF_RADIO->FREQUENCY = freq_offset;
	NRF_RADIO->DATAWHITEIV = channel;
	NRF_RADIO->PACKETPTR = (uint32_t)pkt_buf;
	radio_clear_events();

	rx_active = true;
	NRF_RADIO->TASKS_RXEN = 1;

	irq_unlock(key);
}

void sniffer_init(void)
{
	/* 1 MHz timer (16 MHz / 2^4), 32-bit, free-running. */
	NRF_TIMER1->TASKS_STOP = 1;
	NRF_TIMER1->TASKS_CLEAR = 1;
	NRF_TIMER1->MODE = TIMER_MODE_MODE_Timer;
	NRF_TIMER1->BITMODE = TIMER_BITMODE_BITMODE_32Bit;
	NRF_TIMER1->PRESCALER = 4;
	NRF_TIMER1->TASKS_START = 1;

	radio_clear_events();

	NRF_RADIO->MODE = (RADIO_MODE_MODE_Ble_1Mbit << RADIO_MODE_MODE_Pos);
	NRF_RADIO->MODECNF0 = (RADIO_MODECNF0_DTX_Center << RADIO_MODECNF0_DTX_Pos);

	/* S0 = 1 byte (LL header), length = 8 bits, no S1, 8-bit preamble. */
	NRF_RADIO->PCNF0 = (1UL << RADIO_PCNF0_S0LEN_Pos) |
			   (8UL << RADIO_PCNF0_LFLEN_Pos) |
			   (0UL << RADIO_PCNF0_S1LEN_Pos) |
			   (0UL << RADIO_PCNF0_PLEN_Pos);

	/* MAXLEN 255, 3-byte base + 1-byte prefix, little endian, whitening. */
	NRF_RADIO->PCNF1 = (SNIFF_MAX_PDU_LEN << RADIO_PCNF1_MAXLEN_Pos) |
			   (0UL << RADIO_PCNF1_STATLEN_Pos) |
			   (3UL << RADIO_PCNF1_BALEN_Pos) |
			   (RADIO_PCNF1_ENDIAN_Little << RADIO_PCNF1_ENDIAN_Pos) |
			   (1UL << RADIO_PCNF1_WHITEEN_Pos);

	NRF_RADIO->TXADDRESS = 0;
	NRF_RADIO->RXADDRESSES = RADIO_RXADDRESSES_ADDR0_Msk;
	NRF_RADIO->BASE0 = 0x89BED600UL; /* 0x8E89BED6, LSB first on air */
	NRF_RADIO->PREFIX0 = 0x8EUL;

	NRF_RADIO->CRCCNF = (3UL << RADIO_CRCCNF_LEN_Pos) |
			    (RADIO_CRCCNF_SKIPADDR_Skip << RADIO_CRCCNF_SKIPADDR_Pos);
	NRF_RADIO->CRCPOLY = 0x00065BUL;
	NRF_RADIO->CRCINIT = 0x555555UL;

	NRF_RADIO->SHORTS = RADIO_SHORTS_READY_START_Msk |
			    RADIO_SHORTS_END_DISABLE_Msk |
			    RADIO_SHORTS_ADDRESS_RSSISTART_Msk |
			    RADIO_SHORTS_DISABLED_RSSISTOP_Msk;

	NRF_RADIO->INTENSET = RADIO_INTENSET_END_Msk |
			      RADIO_INTENSET_DISABLED_Msk;

	IRQ_CONNECT(RADIO_IRQn, 0, packet_isr, NULL, 0);
	irq_enable(RADIO_IRQn);
}

void sniffer_start(void)
{
	hop_index = 0;
	next_hop_ms = k_uptime_get();
}

void sniffer_tick(void)
{
	int64_t now = k_uptime_get();

	if (now >= next_hop_ms) {
		uint32_t idx = hop_index % ARRAY_SIZE(adv_channels);

		select_channel(adv_channels[idx], adv_freq_offset[idx]);
		hop_index++;
		next_hop_ms = now + dwell_ms;
	}
}

bool sniffer_dequeue(const uint8_t **data, uint16_t *len)
{
	uint32_t tail = ring_tail;
	struct sniff_slot *slot;

	if (tail == ring_head) {
		return false;
	}

	/* Make sure the slot contents are visible before reading them. */
	__DMB();
	slot = &ring[tail & RING_MASK];
	*data = slot->data;
	*len = (uint16_t)slot->total;
	ring_tail = tail + 1U;

	return true;
}

uint32_t sniffer_dropped(void)
{
	return drop_count;
}

void sniffer_set_dwell_ms(uint32_t ms)
{
	if (ms >= 1U) {
		dwell_ms = ms;
	}
}
