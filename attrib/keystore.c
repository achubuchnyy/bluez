/*
 * keystore.c
 *
 *  Created on: 6 рту. 2016 у.
 *      Author: Chubuchnyy
 */

#include "ExtFlash.h"
#include "keystore.h"
#include "icall.h"
#include "shell.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
//#include "bcomdef.h"

//#include <ti/sysbios/BIOS.h>


//#include "shell.h"

//#include "ti\mw\extflash\ExtFlash.h"

//#include "osal_snv.h"
#define USER_SPACE_START 0x40000
#define SECTOR_SIZE 0x1000
#define SUB_SECTOR_SIZE 0x100
#define MAX_KEYS 100

void refreshKEY(key_t* key);
bool validateKey(key_t* key);


uint8_t keystore_erase(void)
{
	uint8_t ret=0;
		  ret = ExtFlash_open();
		    if (ret)
		    {
		    	for(int i=0;i<20;i++)
		    	  	{
		    			ExtFlash_erase(USER_SPACE_START+i*SECTOR_SIZE, SECTOR_SIZE);
		    	  	}
		        ExtFlash_close();
		    }
			return ret;
}


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



uint8_t writeKeyToStore(uint8_t * buf)
{
	static uint8_t nr=0;
	uint8_t res=0;
	nr=buf[0];
	res = ExtFlash_open();
		    if (res)
		    {
		    	ExtFlash_write(USER_SPACE_START+SUB_SECTOR_SIZE*nr, LEYLEN, buf);
		        ExtFlash_close();
		    }
	 return res;
}


bool read_key(uint8_t keyNr, uint8_t* key)
{
	uint8_t res=0;
	res = ExtFlash_open();
		    if (res)
		    {
		    	ExtFlash_read(USER_SPACE_START+SUB_SECTOR_SIZE*keyNr, LEYLEN, (uint8_t*)key);
		        ExtFlash_close();
		    }
	 return res;
}



bool keystore_cmp_id(uint8_t *pData, key_t* key)
{

	for (uint8_t i=0;i<100;i++) //read flash sectors
	{
		read_key(i,(uint8_t*)key);
		if(!strncmp(&(pData[KEY_ID_POS]),&(key->id[0]),ID_SIZE))
			{

			refreshKEY(key);
			return validateKey(key);


			}
	}
	return FALSE;
}

bool keystore_finde_validKey(key_t* key)
{

	for (uint8_t i=0;i<100;i++) //read flash sectors
		{
			read_key(i,(uint8_t*)key);


				refreshKEY(key);
				if( validateKey(key) ){ return TRUE;}


			}

return FALSE;
}


void strHexToByte(uint8_t * hexstring, uint8_t* byteArr)
{
	uint8_t *pos = hexstring;

	while( *pos )
	{
	  if( !((pos-hexstring)&1) )
		sscanf(pos,"%02x",&byteArr[(pos-hexstring)>>1]);
	  ++pos;
	}
}



