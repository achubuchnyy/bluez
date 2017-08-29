/*
 * keystore.h
 *
 *  Created on: 6 рту. 2016 у.
 *      Author: Chubuchnyy
 */

#ifndef CRYPTO_KEYSTORE_H_
#define CRYPTO_KEYSTORE_H_

#ifdef __cplusplus
extern "C"
{
#endif
#include <stdint.h>
#include <stdbool.h>


#define ERROR 1
#define FLASH_START 0x10//BLE_NVID_CUST_START
#define FLASH_STOP 0x1F//BLE_NVID_CUST_END

#define KEYSTORE_SIZE 4096
#define KEYSTORE_SECTORS_COUNT 0x0FU//(BLE_NVID_CUST_END-BLE_NVID_CUST_START)
#define KEYSTORE_SECTOR_SIZE 0xFFU//((KEYSTORE_SIZE) / (KEYSTORE_SECTORS_COUNT))

#define LEYLEN 36
#define KEY_ID_POS 0x05U
#define ID_SIZE 0x06U


#define USER_SPACE_START 0x40000
#define SECTOR_SIZE 0x1000
#define SUB_SECTOR_SIZE 0x100

typedef struct key_param_t
{
    uint8_t duration[2];
	uint32_t time_start;
	uint32_t time_end;
	uint8_t count[2];
	}key_param_t;

typedef struct key_t
{
	uint8_t nr;
	uint8_t id[6];
	uint8_t key[16];
	uint8_t type;
    uint8_t duration[2];
    uint8_t time_start[4];
    uint8_t time_end[4];
    uint8_t count[2];
	}key_t;


/*
 * For tfansform 8-bit to 7-bit data buffer
 * */
void uint8TowriteBuffer(uint8_t* readbuf );

/*
 * For tfansform 7-bit to 8-bit data buffer
 * */
void readBufferTouint8(uint8_t* readbuf );

uint8_t writeKeyToStore(uint8_t * buf);

/*
 * finde key in store
 * if key exist return TRUE
 * */
bool keystore_cmp_id(uint8_t *pData, key_t* key);

bool keystore_finde_validKey(key_t* key);

void strHexToByte(uint8_t* hexstring, uint8_t* byteArr);


bool read_key(uint8_t keyNr, uint8_t* key);

uint8_t keystore_erase(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_KEYSTORE_H_ */
