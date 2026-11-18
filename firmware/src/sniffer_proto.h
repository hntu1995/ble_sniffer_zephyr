/*
 * Wire protocol shared by the firmware and the host extcap.
 *
 * All multi-byte fields are little endian.
 */

#ifndef SNIFFER_PROTO_H_
#define SNIFFER_PROTO_H_

#include <stdint.h>

#define SNIFF_MAGIC0 0x5AU
#define SNIFF_MAGIC1 0xC3U
#define SNIFF_VERSION 1U

#define SNIFF_TYPE_PACKET 1U
#define SNIFF_TYPE_HELLO 2U

#define SNIFF_HDR_SIZE 14U

#define SNIFF_MAX_PDU_LEN 255U
/* AA (4) + LL header (1) + length (1) + payload (255) + CRC (3) */
#define SNIFF_MAX_PAYLOAD (4U + 2U + SNIFF_MAX_PDU_LEN + 3U)
#define SNIFF_MAX_FRAME (SNIFF_HDR_SIZE + SNIFF_MAX_PAYLOAD)

#define SNIFF_FLAG_CRC_OK (1U << 0)
#define SNIFF_FLAG_CRC_CHECKED (1U << 1)
#define SNIFF_FLAG_DEWHITENED (1U << 2)
#define SNIFF_FLAG_DIRECTION (1U << 3)
#define SNIFF_FLAG_AA_VALID (1U << 4)
#define SNIFF_FLAG_AUX_ADV (1U << 5)
#define SNIFF_FLAG_TRUNCATED (1U << 6)

struct sniff_frame_hdr {
	uint8_t magic[2];
	uint8_t version;
	uint8_t type;
	uint16_t payload_len;
	uint32_t timestamp_us;
	uint8_t channel;
	int8_t rssi_dbm;
	uint8_t flags;
	uint8_t reserved;
} __packed;

/* Advertising access address as it appears on air (LSB first). */
static const uint8_t SNIFF_ADV_AA[4] = {0xD6, 0xBE, 0x89, 0x8E};

#endif /* SNIFFER_PROTO_H_ */
