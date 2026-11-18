#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <string.h>

#include "stream.h"
#include "sniffer_proto.h"

BUILD_ASSERT(sizeof(struct sniff_frame_hdr) == SNIFF_HDR_SIZE,
	     "wire header must be packed");

static const struct device *cdc_uart;

void stream_init(const struct device *uart)
{
	cdc_uart = uart;
}

void stream_send(const uint8_t *data, size_t len)
{
	if (cdc_uart == NULL) {
		return;
	}

	for (size_t i = 0; i < len; i++) {
		/* Non-blocking: the CDC driver drops bytes when the host is
		 * not reading, which keeps the sniffer loop alive.
		 */
		uart_poll_out(cdc_uart, data[i]);
	}
}

void stream_send_hello(void)
{
	static const char hello[] = "nrf52840-ble-sniffer 1.0.0";
	struct sniff_frame_hdr hdr = {0};

	hdr.magic[0] = SNIFF_MAGIC0;
	hdr.magic[1] = SNIFF_MAGIC1;
	hdr.version = SNIFF_VERSION;
	hdr.type = SNIFF_TYPE_HELLO;
	hdr.payload_len = sizeof(hello) - 1U;

	stream_send((const uint8_t *)&hdr, sizeof(hdr));
	stream_send((const uint8_t *)hello, sizeof(hello) - 1U);
}
