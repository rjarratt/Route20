/* ddcmp_circuit.c: DDCMP circuit
  ------------------------------------------------------------------------------

   Copyright (c) 2013, Robert M. A. Jarratt

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
   THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
   IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

   Except as contained in this notice, the name of the author shall not be
   used in advertising or otherwise to promote the sale, use or other dealings
   in this Software without prior written authorization from the author.

  ------------------------------------------------------------------------------*/

#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "platform.h"
#include "circuit.h"
#include "ddcmp_circuit.h"
#include "ddcmp_sock.h"
#include "timer.h"
#include "messages.h"

ddcmp_circuit_t *DdcmpCircuitCreateSocket(circuit_t *circuit, char *destinationHostName)
{
	ddcmp_circuit_t *ans = (ddcmp_circuit_t *)malloc(sizeof(ddcmp_circuit_t));
	ddcmp_sock_t *context = (ddcmp_sock_t *)malloc(sizeof(ddcmp_sock_t));
	
	context->destinationHostName = (char *)malloc(strlen(destinationHostName) + 1);
	strcpy(context->destinationHostName, destinationHostName);

	ans->circuit = circuit;
	ans->context = context;

	ans->Open = DdcmpSockOpen;
	ans->ReadPacket = DdcmpSockReadPacket;
	ans->WritePacket = DdcmpSockWritePacket;
	ans->Close = DdcmpSockClose;

	return ans;
}

int DdcmpCircuitOpen(circuit_t *circuit)
{
	ddcmp_circuit_t *context = (ddcmp_circuit_t *)circuit->context;
	return context->Open(context);
}

int DdcmpCircuitStart(circuit_t *circuit)
{
	//time_t now;
	//time(&now);
	//CreateTimer("AllRoutersHello", now, T3, circuit, HandleHelloTimer);
	return 0;
}

packet_t *DdcmpCircuitReadPacket(circuit_t *circuit)
{
	ddcmp_circuit_t *context = (ddcmp_circuit_t *)circuit->context;
	packet_t *ans;

	ans = context->ReadPacket(context);
	//if (ans != NULL)
	//{
	//	circuit->stats.validRawPacketsReceived++;
	//	if (!ans->IsDecnet(ans))
	//	{
	//		ans = NULL;
	//	}
	//	else
	//	{
	//		circuit->stats.decnetPacketsReceived++;
	//		if (!IsAddressedToThisNode(ans))
	//		{
	//			ans = NULL;
	//		}
	//		else
	//		{
	//			circuit->stats.decnetToThisNodePacketsReceived++;
	//		}
	//	}
	//}

	return ans;
}

int DdcmpCircuitWritePacket(circuit_t *circuit, decnet_address_t *from, decnet_address_t *to, packet_t *packet)
{
	int ans = 0;
	//int len;
	//ddcmp_circuit_t *context = (ddcmp_circuit_t *)circuit->context;
	//packet_t toSend;

	//toSend.rawLen = packet->payloadLen + 16;
	//toSend.rawData = (byte *)malloc(toSend.rawLen);
	//toSend.payloadLen = packet->payloadLen;
	//toSend.payload = toSend.rawData + 16;

	//SetDecnetAddress((decnet_ddcmp_address_t *)toSend.rawData, *to);
	//SetDecnetAddress((decnet_ddcmp_address_t *)&toSend.rawData[6], *from);
	//toSend.rawData[12] = 0x60;
	//toSend.rawData[13] = 0x03;
	//len = Uint16ToLittleEndian((uint16)packet->payloadLen);
	//memcpy(&toSend.rawData[14], &len, 2);
	//memcpy(toSend.payload, packet->payload, packet->payloadLen);
	//ans = context->WritePacket(context, &toSend);
	//free(toSend.rawData);
	//circuit->stats.packetsSent++;
	return ans;
}

void DdcmpCircuitClose(circuit_t *circuit)
{
	ddcmp_circuit_t *context = (ddcmp_circuit_t *)circuit->context;
	context->Close(context);
}
