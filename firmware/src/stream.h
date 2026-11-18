#ifndef STREAM_H_
#define STREAM_H_

#include <stddef.h>
#include <stdint.h>

struct device;

void stream_init(const struct device *uart);

/** Write one already-framed record. Non-blocking (drops if USB TX is full). */
void stream_send(const uint8_t *data, size_t len);

/** Emit the hello frame so the host can confirm the firmware is alive. */
void stream_send_hello(void);

#endif /* STREAM_H_ */
