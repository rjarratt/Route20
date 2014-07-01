/* eth_sock_line.c: Ethernet sockets line
------------------------------------------------------------------------------

Copyright (c) 2014, Robert M. A. Jarratt

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
#include "eth_sock_line.h"
#include "dns.h"
#include "timer.h"

static void ProcessDnsTimer(rtimer_t *timer, char *name, void *context);
static void ProcessDnsResponse(byte *address, void *context);
static int  CheckSourceAddress(sockaddr_t *receivedFrom, eth_sock_t *context);

int EthSockLineStart(line_t *line)
{
	int ans = 0;
	eth_sock_t *sockContext = (eth_sock_t *)line->lineContext;
	sockaddr_t *destinationAddress;

	destinationAddress = GetSocketAddressFromName(sockContext->destinationHostName, sockContext->destinationPort);

	if (destinationAddress != NULL)
	{
		ans = OpenUdpSocket(&sockContext->socket, line->name, sockContext->receivePort);
		if (ans)
		{
			if (DnsConfig.dnsConfigured)
			{
				time_t now;

				time(&now);
				CreateTimer("DNS", now + DnsConfig.pollPeriod, DnsConfig.pollPeriod, line, ProcessDnsTimer);
			}

			line->waitHandle = sockContext->socket.waitHandle;
			RegisterEventHandler(line->waitHandle, "EthSock Line", line, line->LineWaitEventHandler);
			memcpy(&sockContext->destinationAddress, destinationAddress, sizeof(sockContext->destinationAddress));
			QueueImmediate(line, line->LineUp);
		}
	}
	else
	{
		Log(LogEthSockLine, LogError, "Cannot resolve address for %s, line not started.\n", sockContext->destinationHostName);
	}

    if (!ans)
    {
		Log(LogEthSockLine, LogError, "Could not open line for %s\n", sockContext->destinationHostName);
    }

	return ans;
}

void EthSockLineStop(line_t *line)
{
	eth_sock_t *sockContext = (eth_sock_t *)line->lineContext;
	CloseSocket(&sockContext->socket);
}

packet_t *EthSockLineReadPacket(line_t *line)
{
	packet_t *packet = NULL;

    eth_sock_t *sockContext = (eth_sock_t *)line->lineContext;
	static packet_t sockPacket;
	sockaddr_t receivedFrom;
	
	sockPacket.IsDecnet = EthSockIsDecnet;

	if (ReadFromDatagramSocket(&sockContext->socket, &sockPacket, &receivedFrom))
	{
		if (CheckSourceAddress(&receivedFrom, sockContext))
		{
			if (EthValidPacket(&sockPacket))
			{
                if (sockPacket.IsDecnet(&sockPacket))
                {
                    GetDecnetAddress((decnet_eth_address_t *)&sockPacket.rawData[0], &sockPacket.to);
                    GetDecnetAddress((decnet_eth_address_t *)&sockPacket.rawData[6], &sockPacket.from);
                    Log(LogEthSockLine, LogVerbose, "Packet from : ");LogDecnetAddress(LogEthSockLine, LogVerbose, &sockPacket.from);Log(LogEthSockLine, LogVerbose, " received on line %s\n", line->name);
                    line->stats.validPacketsReceived++;
                    EthSetPayload(&sockPacket);
                    packet = &sockPacket;
                }
                else
                {
                    Log(LogEthSockLine, LogVerbose, "Discarding valid non-DECnet packet from %s\n", line->name);
                }
			}
			else
			{
                Log(LogEthPcapLine, LogWarning, "Discarding invalid packet from %s\n", line->name);
                line->stats.invalidPacketsReceived++;
				packet = NULL;
			}
		}
	}

	return packet;
}

int EthSockLineWritePacket(line_t *line, packet_t *packet)
{
	int ans = 0;
	eth_sock_t *sockContext = (eth_sock_t *)line->lineContext;

	ans = SendToSocket(&sockContext->socket, &sockContext->destinationAddress, packet);

	return ans;
}

static void ProcessDnsTimer(rtimer_t *timer, char *name, void *context)
{
	line_t *line = (line_t *)context;
    circuit_t *circuit = (circuit_t *)line->notifyContext;
	eth_sock_t *sockContext = (eth_sock_t *)line->lineContext;
	DnsSendQuery(sockContext->destinationHostName, (uint16)circuit->slot, ProcessDnsResponse, context);
}

static void ProcessDnsResponse(byte *address, void *context)
{
	line_t *line = (line_t *)context;
	eth_sock_t *sockContext = (eth_sock_t *)line->lineContext;
	sockaddr_t *newAddress = GetSocketAddressFromIpAddress(address, sockContext->destinationPort);

	if (memcmp(&sockContext->destinationAddress, newAddress, sizeof(sockaddr_t)) != 0)
	{
	    Log(LogEthSockLine, LogInfo, "Changed IP address for %s\n", line->name);
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
