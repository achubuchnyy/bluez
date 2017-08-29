/*
 * crc16.h
 *
 *  Created on: 27 ���. 2016 �.
 *      Author: Chubuchnyy
 */

#ifndef CRYPTO_CRC16_H_
#define CRYPTO_CRC16_H_
#include <stdint.h>


uint16_t crc16_clc(uint8_t *data, uint16_t size);
uint8_t checkCRC16(uint8_t *data, uint16_t size);
void uint8TowriteBuffer(uint8_t* readbuf );
void readBufferTouint8(uint8_t* readbuf );

#endif /* CRYPTO_CRC16_H_ */
