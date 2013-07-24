/* ddcmp_sock.c: DDCMP sockets interface
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

#define ENQ 5
#define MAX_DDCMP_MSG_LEN 8192

#include <memory.h>
#include "platform.h"
#include "route20.h"
#include "socket.h"
//#include "eth_decnet.h"
#include "ddcmp_sock.h"
#include "dns.h"
#include "timer.h"

static void ProcessDnsTimer(rtimer_t *timer, char *name, void *context);
static void ProcessDnsResponse(byte *address, void *context);
static int  CheckSourceAddress(sockaddr_t *receivedFrom, ddcmp_sock_t *context);

int DdcmpSockOpen(ddcmp_circuit_t *ddcmpCircuit)
{
	/* We don't actually open a socket here, but just do the necessary preparations for when the remote side connects to the listen port.
	   In this case that means just setting up the address of the peer for verification when the connection comes in. */

	int ans = 1;
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)ddcmpCircuit->context;
	sockaddr_t *destinationAddress;

	destinationAddress = GetSocketAddressFromName(sockContext->destinationHostName, 0);
	if (destinationAddress != NULL)
	{
		memcpy(&sockContext->destinationAddress, destinationAddress, sizeof(sockContext->destinationAddress));
	}
	else
	{
		Log(LogDdcmpSock, LogError, "Cannot resolve address for %s, circuit will not start until DNS can resolve the address.\n", sockContext->destinationHostName);
	}

	if (DnsConfig.dnsConfigured)
	{
		time_t now;

		time(&now);
		CreateTimer("DNS", now + DnsConfig.pollPeriod, DnsConfig.pollPeriod, ddcmpCircuit, ProcessDnsTimer);
	}

	// TODO: circuit state change on connect, or on DDCMP connect?
	//ethCircuit->circuit->state = CircuitUp;
	//CircuitStateChange(ethCircuit->circuit);

	return ans;
}

packet_t *DdcmpSockReadPacket(ddcmp_circuit_t *ddcmpCircuit)
{
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)ddcmpCircuit->context;

	packet_t *packet = NULL;
	static packet_t sockPacket;

	if (ReadFromStreamSocket(&sockContext->socket, &sockPacket))
	{
	//	if (CheckSourceAddress(&receivedFrom, sockContext))
	//	{
	//		if (EthValidPacket(&sockPacket))
	//		{
	//			GetDecnetAddress((decnet_eth_address_t *)&sockPacket.rawData[0], &sockPacket.to);
	//			GetDecnetAddress((decnet_eth_address_t *)&sockPacket.rawData[6], &sockPacket.from);
	//			sockPacket.IsDecnet = EthSockIsDecnet;
	//			if (CompareDecnetAddress(&nodeInfo.address, &sockPacket.from))
	//			{
	//				/*Log(LogInfo, "Discarding loopback from %s\n", ethCircuit->circuit->name);*/
	//				ethCircuit->circuit->stats.loopbackPacketsReceived++;
	//				packet = NULL;
	//			}
	//			else
	//			{
	//				/*Log(LogInfo, "Not sock loopback on %s\n", ethCircuit->circuit->name);*/
	//				EthSetPayload(&sockPacket);
	//				packet = &sockPacket;
	//			}
	//		}
	//		else
	//		{
 //   			ethCircuit->circuit->stats.invalidPacketsReceived++;
	//			packet = NULL;
	//		}
	//	}
	}

	return packet;
}

int DdcmpSockWritePacket(ddcmp_circuit_t *ddcmpCircuit, packet_t *packet)
{
	int ans = 0;
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)ddcmpCircuit->context;

	//ans = SendToSocket(&sockContext->socket, &sockContext->destinationAddress, packet);

	return ans;
}

void DdcmpSockClose(ddcmp_circuit_t *ddcmpCircuit)
{
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)ddcmpCircuit->context;
	CloseSocket(&sockContext->socket);
}

static void ProcessDnsTimer(rtimer_t *timer, char *name, void *context)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)context;
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)ddcmpCircuit->context;
	DnsSendQuery(sockContext->destinationHostName, (uint16)ddcmpCircuit->circuit->slot, ProcessDnsResponse, context);
}

static void ProcessDnsResponse(byte *address, void *context)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)context;
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)ddcmpCircuit->context;
	sockaddr_t *newAddress = GetSocketAddressFromIpAddress(address, 0);

	if (memcmp(&sockContext->destinationAddress, newAddress, sizeof(sockaddr_t)) != 0)
	{
	    Log(LogDdcmpSock, LogInfo, "Changed IP address for %s\n", ddcmpCircuit->circuit->name);
	    memcpy(&sockContext->destinationAddress, newAddress, sizeof(sockContext->destinationAddress));
	}
}

static int CheckSourceAddress(sockaddr_t *receivedFrom, ddcmp_sock_t *context)
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
