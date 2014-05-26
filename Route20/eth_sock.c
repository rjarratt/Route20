/* eth_sock.c: Ethernet sockets interface
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

#include <memory.h>
#include "platform.h"
#include "route20.h"
#include "socket.h"
#include "eth_decnet.h"
#include "eth_sock.h"
#include "dns.h"
#include "timer.h"

static void ProcessDnsTimer(rtimer_t *timer, char *name, void *context);
static void ProcessDnsResponse(byte *address, void *context);
static int  CheckSourceAddress(sockaddr_t *receivedFrom, eth_sock_t *context);

int EthSockOpen(eth_circuit_t *ethCircuit)
{
	int ans = 0;
	eth_sock_t *sockContext = (eth_sock_t *)ethCircuit->context;
	sockaddr_t *destinationAddress;

	destinationAddress = GetSocketAddressFromName(sockContext->destinationHostName, sockContext->destinationPort);

	if (destinationAddress != NULL)
	{
		ans = OpenUdpSocket(&sockContext->socket, ethCircuit->circuit->name, sockContext->receivePort);
		if (ans)
		{
			if (DnsConfig.dnsConfigured)
			{
				time_t now;

				time(&now);
				CreateTimer("DNS", now + DnsConfig.pollPeriod, DnsConfig.pollPeriod, ethCircuit, ProcessDnsTimer);
			}

			ethCircuit->circuit->waitHandle = sockContext->socket.waitHandle;
			RegisterEventHandler(ethCircuit->circuit->waitHandle, "EthSock Circuit", ethCircuit->circuit, ethCircuit->circuit->WaitEventHandler);
			memcpy(&sockContext->destinationAddress, destinationAddress, sizeof(sockContext->destinationAddress));
			QueueImmediate(ethCircuit->circuit, CircuitUp);
		}
	}
	else
	{
		Log(LogEthSock, LogError, "Cannot resolve address for %s, circuit not started.\n", sockContext->destinationHostName);
	}

	return ans;
}

packet_t *EthSockReadPacket(eth_circuit_t *ethCircuit)
{
	eth_sock_t *sockContext = (eth_sock_t *)ethCircuit->context;

	packet_t *packet = NULL;
	static packet_t sockPacket;
	sockaddr_t receivedFrom;

	if (ReadFromDatagramSocket(&sockContext->socket, &sockPacket, &receivedFrom))
	{
		if (CheckSourceAddress(&receivedFrom, sockContext))
		{
			if (EthValidPacket(&sockPacket))
			{
				GetDecnetAddress((decnet_eth_address_t *)&sockPacket.rawData[0], &sockPacket.to);
				GetDecnetAddress((decnet_eth_address_t *)&sockPacket.rawData[6], &sockPacket.from);
				sockPacket.IsDecnet = EthSockIsDecnet;
				if (CompareDecnetAddress(&nodeInfo.address, &sockPacket.from))
				{
					/*Log(LogVerbose, "Discarding loopback from %s\n", ethCircuit->circuit->name);*/
					ethCircuit->circuit->stats.loopbackPacketsReceived++;
					packet = NULL;
				}
				else
				{
					/*Log(LogInfo, "Not sock loopback on %s\n", ethCircuit->circuit->name);*/
					EthSetPayload(&sockPacket);
					packet = &sockPacket;
				}
			}
			else
			{
    			ethCircuit->circuit->stats.invalidPacketsReceived++;
				packet = NULL;
			}
		}
	}

	return packet;
}

int EthSockWritePacket(eth_circuit_t *ethCircuit, packet_t *packet)
{
	int ans;
	eth_sock_t *sockContext = (eth_sock_t *)ethCircuit->context;

	ans = SendToSocket(&sockContext->socket, &sockContext->destinationAddress, packet);

	return ans;
}

void EthSockClose(eth_circuit_t *ethCircuit)
{
	eth_sock_t *sockContext = (eth_sock_t *)ethCircuit->context;
	CloseSocket(&sockContext->socket);
}

static void ProcessDnsTimer(rtimer_t *timer, char *name, void *context)
{
	eth_circuit_t *ethCircuit = (eth_circuit_t *)context;
	eth_sock_t *sockContext = (eth_sock_t *)ethCircuit->context;
	DnsSendQuery(sockContext->destinationHostName, (uint16)ethCircuit->circuit->slot, ProcessDnsResponse, context);
}

static void ProcessDnsResponse(byte *address, void *context)
{
	eth_circuit_t *ethCircuit = (eth_circuit_t *)context;
	eth_sock_t *sockContext = (eth_sock_t *)ethCircuit->context;
	sockaddr_t *newAddress = GetSocketAddressFromIpAddress(address, sockContext->destinationPort);

	if (memcmp(&sockContext->destinationAddress, newAddress, sizeof(sockaddr_t)) != 0)
	{
	    Log(LogEthSock, LogInfo, "Changed IP address for %s\n", ethCircuit->circuit->name);
	    memcpy(&sockContext->destinationAddress, newAddress, sizeof(sockContext->destinationAddress));
	}
}

static int CheckSourceAddress(sockaddr_t *receivedFrom, eth_sock_t *context)
{
	int ans = 0;
	if (memcmp(receivedFrom, &context->destinationAddress, sizeof(sockaddr_t)) == 0)
	{
		ans = 1;
	}
	//else
	//{
	//	Log(LogError, "Security, dropping packet from unrecognised source\n");
	//}

	return ans;
}
