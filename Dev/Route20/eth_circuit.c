/* eth_circuit.c: Ethernet circuit
  ------------------------------------------------------------------------------

   Copyright (c) 2012, Robert M. A. Jarratt

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
#include "eth_circuit.h"
#include "eth_pcap.h"
#include "eth_sock.h"
#include "timer.h"
#include "messages.h"
#include "decnet.h"
#include "node.h"

static void HandleHelloTimer(rtimer_t *timer, char *name, void *context);
static int IsAddressedToThisNode(packet_t * packet);

eth_circuit_t *EthCircuitCreatePcap(circuit_t *circuit)
{
	eth_circuit_t *ans = (eth_circuit_t *)malloc(sizeof(eth_circuit_t));
	eth_pcap_t *context = (eth_pcap_t *)malloc(sizeof(eth_pcap_t));

	ans->circuit = circuit;
	ans->context = context;

	ans->Open = EthPcapOpen;
	ans->ReadPacket = EthPcapReadPacket;
	ans->WritePacket = EthPcapWritePacket;
	ans->Close = EthPcapClose;

	return ans;
}

eth_circuit_t *EthCircuitCreateSocket(circuit_t *circuit, uint16 receivePort, char *destinationHostName, uint16 destinationPort)
{
	eth_circuit_t *ans = (eth_circuit_t *)malloc(sizeof(eth_circuit_t));
	eth_sock_t *context = (eth_sock_t *)malloc(sizeof(eth_sock_t));
	
	context->receivePort = receivePort;
	context->destinationPort = destinationPort;
	context->destinationHostName = (char *)malloc(strlen(destinationHostName) + 1);
	strcpy(context->destinationHostName, destinationHostName);

	ans->circuit = circuit;
	ans->context = context;

	ans->Open = EthSockOpen;
	ans->ReadPacket = EthSockReadPacket;
	ans->WritePacket = EthSockWritePacket;
	ans->Close = EthSockClose;

	return ans;
}

int EthCircuitOpen(circuit_t *circuit)
{
	eth_circuit_t *context = (eth_circuit_t *)circuit->context;
	return context->Open(context);
}

int EthCircuitUp(circuit_t *circuit)
{
	time_t now;
	time(&now);
	circuit->helloTimer = CreateTimer("AllRoutersHello", now, T3, circuit, HandleHelloTimer);
	return 0;
}

void EthCircuitDown(circuit_ptr circuit)
{
	StopTimer(circuit->helloTimer);
}

packet_t *EthCircuitReadPacket(circuit_t *circuit)
{
	eth_circuit_t *context = (eth_circuit_t *)circuit->context;
	packet_t *ans;

	ans = context->ReadPacket(context);
	if (ans != NULL)
	{
		circuit->stats.validRawPacketsReceived++;
		if (!ans->IsDecnet(ans))
		{
			ans = NULL;
		}
		else
		{
			circuit->stats.decnetPacketsReceived++;
			if (!IsAddressedToThisNode(ans))
			{
				ans = NULL;
			}
			else
			{
				circuit->stats.decnetToThisNodePacketsReceived++;
			}
		}
	}

	return ans;
}

int EthCircuitWritePacket(circuit_t *circuit, decnet_address_t *from, decnet_address_t *to, packet_t *packet)
{
	int ans;
	int len;
	eth_circuit_t *context = (eth_circuit_t *)circuit->context;
	packet_t toSend;

	toSend.rawLen = packet->payloadLen + 16;
	toSend.rawData = (byte *)malloc(toSend.rawLen);
	toSend.payloadLen = packet->payloadLen;
	toSend.payload = toSend.rawData + 16;

	SetDecnetAddress((decnet_eth_address_t *)toSend.rawData, *to);
	SetDecnetAddress((decnet_eth_address_t *)&toSend.rawData[6], *from);
	toSend.rawData[12] = 0x60;
	toSend.rawData[13] = 0x03;
	len = Uint16ToLittleEndian((uint16)packet->payloadLen);
	memcpy(&toSend.rawData[14], &len, 2);
	memcpy(toSend.payload, packet->payload, packet->payloadLen);
	ans = context->WritePacket(context, &toSend);
	free(toSend.rawData);
	circuit->stats.packetsSent++;
	return ans;
}

void EthCircuitClose(circuit_t *circuit)
{
	eth_circuit_t *context = (eth_circuit_t *)circuit->context;
	context->Close(context);
}

static void HandleHelloTimer(rtimer_t *timer, char *name, void *context)
{
	packet_t *packet;

	circuit_t *circuit = (circuit_t *)context;
	Log(LogEthInit, LogVerbose, "Sending Ethernet Hello to All Routers %s\n", circuit->name);
	packet = CreateEthernetHello(nodeInfo.address);
	circuit->WritePacket(circuit, &nodeInfo.address, &AllRoutersAddress, packet);
}

static int IsAddressedToThisNode(packet_t * packet)
{
	int ans = 0;
	if (packet->to.type == AllRouters && (nodeInfo.level == 1 || nodeInfo.level == 2))
	{
		ans = 1;
	}
	else if (packet->to.type == AllLevel2Routers && nodeInfo.level == 2)
	{
		ans = 1;
	}
	else if (packet->to.type == Node && CompareDecnetAddress(&nodeInfo.address, &packet->to))
	{
		ans = 1;
	}
	else if (packet->to.type == AllEndNodes && nodeInfo.level == 3)
	{
		ans = 1;
	}

	//if (!ans)
	//{
	//	Log(LogInfo, "Dropping packet addressed to ");
	//	LogDecnetAddress(LogInfo, &packet->to);
	//	DumpPacket(packet, ".");
	//}

	return ans;
}
