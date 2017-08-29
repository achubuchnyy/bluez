/*
 * key_validator.c
 *
 *  Created on: 22 сент. 2016 г.
 *      Author: Chubuchnyy
 */
#include "keystore.h"
#include "time_util.h"
#include "shell.h"
bool validateKey(key_t* key)
{
	bool res = false;
	uint32_t time_start = (uint32_t)key->time_start[0]|((uint32_t)key->time_start[1]<<8)|((uint32_t)key->time_start[2]<<16)|((uint32_t)key->time_start[3]<<24);
	uint32_t time_end =  (uint32_t)key->time_end[0]|((uint32_t)key->time_end[1]<<8)|((uint32_t)key->time_end[2]<<16)|((uint32_t)key->time_end[3]<<24);
	uint32_t timeNow=get_time_sec();
	if ((time_start < timeNow) && (time_end > timeNow)) res = true;

	/*ble_sys_printf("\r\nstart = %d: end = %d, now = %d",time_start,time_end, timeNow );*/
	return res;
}


/*
 *  uint8_t nr;
    uint8_t id[6];
    uint8_t key[16];
    uint8_t type;
    uint8_t duration[2];
    uint8_t time_start[4];
    uint8_t time_end[4];
    uint8_t count[2];
 * */
