#ifndef RADIO_SNIFFER_H_
#define RADIO_SNIFFER_H_

#include <stdbool.h>
#include <stdint.h>

/** Configure the radio, timer and interrupt. Must be called once. */
void sniffer_init(void);

/** Begin scanning the advertising channels. */
void sniffer_start(void);

/** Advance the channel scheduler. Call from the main loop. */
void sniffer_tick(void);

/**
 * Pop one captured frame.
 *
 * The returned buffer stays valid until 64 further frames have been queued.
 *
 * @return true when a frame was returned.
 */
bool sniffer_dequeue(const uint8_t **data, uint16_t *len);

/** Number of frames dropped because the ring buffer was full. */
uint32_t sniffer_dropped(void);

/** Channel dwell time, default 10 ms. */
void sniffer_set_dwell_ms(uint32_t dwell_ms);

#endif /* RADIO_SNIFFER_H_ */
