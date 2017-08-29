/*
 * telemetry.h
 *
 *  Created on: 20 февр. 2017 г.
 *      Author: Chubuchnyy
 */

#ifndef CRYPTO_TELEMETRY_H_
#define CRYPTO_TELEMETRY_H_
#include <stdint.h>
#include <stdbool.h>
#define MAX_TELEMETRY_SIZE 99
#define MIN_TELEMETRY_SIZE 1
bool check_telemetry_status(void);
bool get_telemetry(uint32_t size, uint8_t * data, uint32_t cmd_id);
void statusCallback(void);
void sendTelemetryToHMI(uint8_t* data);
void WDT_UART(void);
void RESET_WDT_UART(void);

#endif /* CRYPTO_TELEMETRY_H_ */
