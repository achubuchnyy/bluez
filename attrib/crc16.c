/*
 * crc16.c
 *
 *  Created on: 27 рту. 2016 у.
 *      Author: Chubuchnyy
 */
#include "crc16.h"
#define CRC16 0x8005


uint16_t crc16_clc(uint8_t *data, uint16_t size)
{
uint16_t out = 0;
int bits_read = 0;
int bit_flag;
int i;
	int j = 0x0001;
	uint16_t crc = 0;
    /* Sanity check:
    if(data == NULL)
        return 0;
*/
    while(size > 0)
    {
        bit_flag = out >> 15;

        /* Get next bit: */
        out <<= 1;
        out |= (*data >> bits_read) & 1; // item a) work from the least significant bits

        /* Increment bit counter: */
        bits_read++;
        if(bits_read > 7)
        {
            bits_read = 0;
            data++;
            size--;
        }
        /* Cycle check: */
        if(bit_flag)
            out ^= CRC16;
    }

    for (i = 0; i < 16; ++i) {
        bit_flag = out >> 15;
        out <<= 1;
        if(bit_flag)
            out ^= CRC16;
    }

    i = 0x8000;

    for (; i != 0; i >>=1, j <<= 1) {
        if (i & out) crc |= j;
    };

  // data[size]=(uint8_t)(crc&0x00FF);
   //data[size+1]=(uint8_t)((crc>>8)&0x00FF);
    return crc;
}


uint8_t checkCRC16(uint8_t *data, uint16_t size)
{uint8_t res=0;
	uint16_t crc = crc16_clc(data, size-2);

	if ((data[size-2]==(uint8_t)(crc&0x00FF))&&(data[size-1]==(uint8_t)((crc>>8)&0x00FF))) res=1;

return res;}



void uint8TowriteBuffer(uint8_t* readbuf )
{
	readbuf[16]=0x00;
	readbuf[17]=0x00;
	readbuf[18]=0x00;

	for(int i=0;i<7;i++)
	{
		readbuf[16]|=((readbuf[i]&0x80)>>(i+1));
		readbuf[17]|=((readbuf[i+7]&0x80)>>(i+1));
	}
	readbuf[18]|=((readbuf[14]&0x80)>>1);
	readbuf[18]|=((readbuf[15]&0x80)>>2);
	for(int i=0;i<16;i++)
	{
		readbuf[i]&=0x7F;
	}
}


void readBufferTouint8(uint8_t* readbuf )
{
	for(int i=0;i<7;i++)
		{
			readbuf[i]|=((readbuf[16]<<(i+1))&0x80);
			readbuf[i+7]|=((readbuf[17]<<(i+1))&0x80);
		}
		readbuf[14]|=((readbuf[18]<<1)&0x80);
		readbuf[15]|=((readbuf[18]<<2)&0x80);
}
