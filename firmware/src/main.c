#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/drivers/clock_control.h>
#include <zephyr/drivers/clock_control/nrf_clock_control.h>

#include "radio_sniffer.h"
#include "stream.h"

#define SNIFFER_UART DEVICE_DT_GET(DT_ALIAS(sniffer_uart))

static void wait_for_dtr(const struct device *uart, uint32_t timeout_ms)
{
	int64_t deadline = k_uptime_get() + timeout_ms;

	while (k_uptime_get() < deadline) {
		uint32_t dtr = 0U;

		if (uart_line_ctrl_get(uart, UART_LINE_CTRL_DTR, &dtr) == 0 &&
		    dtr != 0U) {
			return;
		}
		k_sleep(K_MSEC(100));
	}
}

int main(void)
{
	const struct device *uart = SNIFFER_UART;
	const struct device *clock = DEVICE_DT_GET(DT_NODELABEL(clock));

	if (!device_is_ready(uart)) {
		printk("sniffer: CDC-ACM UART is not ready\n");
		return 0;
	}

	/* The radio and TIMER1 both need the 16/32 MHz high-frequency clock. */
	(void)clock_control_on(clock, CLOCK_CONTROL_NRF_SUBSYS_HF);

	sniffer_init();
	stream_init(uart);

	/* Give the host a moment to open the port, then stream regardless. */
	wait_for_dtr(uart, 5000);
	stream_send_hello();

	sniffer_start();

	for (;;) {
		const uint8_t *frame;
		uint16_t len;

		sniffer_tick();

		while (sniffer_dequeue(&frame, &len)) {
			stream_send(frame, len);
		}

		k_sleep(K_MSEC(1));
	}

	return 0;
}
