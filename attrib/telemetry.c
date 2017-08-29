/*
 * telemetry.c
 *
 *  Created on: 20 февр. 2017 г.
 *      Author: Chubuchnyy
 */
#include "telemetry.h"
#include "spp_ble_client.h"
#include "inc/sdi_task.h"
#include "inc/sdi_tl_uart.h"
#include <string.h>
#include "shell.h"
static uint8_t wdtUartCtr = 0;
uint8_t telemetryBufferRX[MAX_TELEMETRY_SIZE];
uint8_t telemetryBufferTX[MAX_TELEMETRY_SIZE];
static uint32_t cmdID = 0;
enum transferStatus
{
	READY,
	BUSY,
	ERROR,
	};
static uint8_t transfer_status = READY;
bool check_telemetry_status(void)
{

        if (transfer_status!=READY){
            RxActiveFlag = FALSE;
            RxActive = FALSE;
            return false;
        }
        return true;
    }

bool get_telemetry(uint32_t size, uint8_t * data, uint32_t cmd_id)
{
    uint8_t i=1;
	uint8_t *v;
	cmdID = cmd_id;
	RxActiveFlag = FALSE;
	RxActive = FALSE;
	if (transfer_status!=READY){
	   	return false;
	}

	if (size<MIN_TELEMETRY_SIZE ||
		size>MAX_TELEMETRY_SIZE){
		return false;
	}

	memset(&telemetryBufferRX[0],0,sizeof(telemetryBufferRX));
	v= data;
	telemetryBufferRX[0]=(uint8_t)(size & 0xFF);
	telemetryBufferRX[1]=*v;
	 while (i<size+1)
	 {
	  	if(i==sizeof(telemetryBufferRX)) return (false);
	  	telemetryBufferRX[++i]=*(++v);
	 }
		transfer_status = BUSY;

	return ble_send_telemetry(size+1,&telemetryBufferRX[0]);
}

void statusCallback(void)
{
    RxActiveFlag = TRUE;
    RxActive = TRUE;
    SDITLUART_readTransport();
	transfer_status = READY;

	ble_sys_printf ("\r\n!OK: ID = %d\r\n",cmdID);
}

void WDT_UART(void)
{
    if( ++wdtUartCtr>150){
        SDITLUART_readTransport();
        wdtUartCtr=0;
        ble_sys_printf ("\r\nWDT_UART");
    }
}

void RESET_WDT_UART(void)
{
    wdtUartCtr=0;
}
void sendTelemetryToHMI(uint8_t* data)
{uint8_t index = data[18]&0x0F;
static uint8_t size=0;
if (index>0){
    size+=14;
	memcpy( &telemetryBufferTX[(index-1)*14], data, 14);


	if (index ==0x01)
	{
		ble_sys_printf("\r\ntelemetry ");
		SDITask_sendToUART(&telemetryBufferTX[0],size);
		memset(&telemetryBufferTX[0],0,sizeof(telemetryBufferTX));
		size=0;
	}

}
};
