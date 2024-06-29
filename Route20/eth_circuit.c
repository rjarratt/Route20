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
#include "eth_pcap_line.h"
#include "eth_sock_line.h"
#include "timer.h"
#include "messages.h"
#include "decnet.h"
#include "node.h"

static void HandleLineNotifyData(line_t *line);
static void HandleHelloTimer(rtimer_t* timer, char* name, void* context);
static void HandleLevel2HelloTimer(rtimer_t* timer, char* name, void* context);
static int IsAddressedToThisNode(packet_t * packet);

eth_circuit_t *EthCircuitCreatePcap(circuit_t *circuit)
{
	eth_circuit_t *ans = (eth_circuit_t *)calloc(1, sizeof(eth_circuit_t));
	line_t *line = (line_t *)calloc(1, sizeof(line_t));
    LineCreateEthernetPcap(line, circuit->name, circuit, HandleLineNotifyData);

	ans->circuit = circuit;
	circuit->line = line;

	return ans;
}

eth_circuit_t *EthCircuitCreateSocket(circuit_t *circuit, uint16 receivePort, char *destinationHostName, uint16 destinationPort)
{
	eth_circuit_t *ans = (eth_circuit_t *)calloc(1, sizeof(eth_circuit_t));
	line_t *line = (line_t *)calloc(1, sizeof(line_t));
    LineCreateEthernetSocket(line, circuit->name, receivePort, destinationHostName, destinationPort, circuit, HandleLineNotifyData);

	ans->circuit = circuit;
	circuit->line = line;

	return ans;
}

int EthCircuitStart(circuit_t *circuit)
{
    line_t *line = GetLineFromCircuit(circuit); // TODO: is this now common to all circuit types? Need a bit of special stuff for init layer perhaps.
	return line->LineStart(line);
}

void EthCircuitUp(circuit_t *circuit)
{
	time_t now;
	time(&now);
	circuit->helloTimer = CreateTimer("AllRoutersHello", now, T3, circuit, HandleHelloTimer);

	if (nodeInfo.level == 2)
	{
		circuit->level2HelloTimer = CreateTimer("AllLevel2RoutersHello", now, T3, circuit, HandleLevel2HelloTimer);
	}
}

void EthCircuitDown(circuit_ptr circuit)
{
	StopTimer(circuit->helloTimer);

	if (nodeInfo.level == 2)
	{
		StopTimer(circuit->level2HelloTimer);
	}
}

packet_t *EthCircuitReadPacket(circuit_t *circuit)
{
	line_t *line = GetLineFromCircuit(circuit);
	packet_t *ans;
	int haveReadAPacket;

	do
	{
		ans = line->LineReadPacket(line);
		haveReadAPacket = ans != NULL;
		if (ans != NULL)
		{
			int disableLoopbackCheck = 0;
			if (!disableLoopbackCheck && CompareDecnetAddress(&nodeInfo.address, &ans->from))
			{
				Log(LogEthCircuit, LogDetail, "Discarding loopback packet on circuit %s\n", circuit->name);
				circuit->stats.loopbackPacketsReceived++;
				ans = NULL;
			}
			else
			{
				Log(LogEthCircuit, LogDetail, "Circuit %s received a valid raw packet, payload length=%d\n", circuit->name, ans->payloadLen);
				LogBytes(LogEthCircuit, LogVerbose, ans->payload, ans->payloadLen);
				circuit->stats.validRawPacketsReceived++;
				if (!ans->IsDecnet(ans))
				{
					Log(LogEthCircuit, LogDetail, "Discarding non-Decnet packet received on circuit %s\n", circuit->name);
					ans = NULL;
					circuit->stats.nonDecnetPacketsReceived++;
				}
				else
				{
					circuit->stats.decnetPacketsReceived++;
					if (!IsAddressedToThisNode(ans))
					{
						Log(LogEthCircuit, LogDetail, "Discarding packet not addressed to this node received on circuit %s\n", circuit->name);
						ans = NULL;
					}
					else
					{
						circuit->stats.decnetToThisNodePacketsReceived++;
					}
				}
			}
		}
	} while (haveReadAPacket && ans == NULL);

	return ans;
}

int EthCircuitWritePacket(circuit_t *circuit, decnet_address_t *from, decnet_address_t *to, packet_t *packet, int isHello)
{
	int ans;
	int len;
    line_t *line = GetLineFromCircuit(circuit);
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
	ans = line->LineWritePacket(line, &toSend);
	free(toSend.rawData);
	circuit->stats.packetsSent++;
	return ans;
}

void EthCircuitStop(circuit_t *circuit)
{
    line_t *line = GetLineFromCircuit(circuit);
	line->LineStop(line);
}

static void HandleLineNotifyData(line_t *line)
{
    circuit_t *circuit = GetCircuitFromLine(line);
    circuit->WaitEventHandler(circuit);
}

static void HandleHelloTimer(rtimer_t* timer, char* name, void* context) // TODO: This should probably move to the init layer.
{
	packet_t* packet;

	circuit_t* circuit = (circuit_t*)context;
	Log(LogEthCircuit, LogVerbose, "Sending Ethernet Hello to All Routers %s\n", circuit->name);
	packet = CreateEthernetHello(nodeInfo.address);
	circuit->WritePacket(circuit, &nodeInfo.address, &AllRoutersAddress, packet, 1);
}

static void HandleLevel2HelloTimer(rtimer_t* timer, char* name, void* context) // TODO: This should probably move to the init layer.
{
	packet_t* packet;

	circuit_t* circuit = (circuit_t*)context;
	Log(LogEthCircuit, LogVerbose, "Sending Ethernet Hello to All Level 2 Routers %s\n", circuit->name);
	packet = CreateEthernetHello(nodeInfo.address);
	circuit->WritePacket(circuit, &nodeInfo.address, &AllLevel2RoutersAddress, packet, 1);
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
