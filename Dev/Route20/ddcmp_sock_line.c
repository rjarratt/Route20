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

#include <stdlib.h>
#include <memory.h>
#include "platform.h"
#include "route20.h"
#include "socket.h"
#include "ddcmp.h"
#include "ddcmp_sock_line.h"
#include "dns.h"
#include "timer.h"

typedef struct
{
	rtimer_t *timer;
	void *timerContext;
	void (*timerHandler)(void *timerContext);
} ddcmp_sock_timer_t;

static void ProcessDnsTimer(rtimer_t *timer, char *name, void *context);
static void ProcessDnsResponse(byte *address, void *context); // TODO: This is duplicated in eth_sock_line.c as well.
static int  CheckSourceAddress(sockaddr_t *receivedFrom, ddcmp_sock_t *context);
static void DdcmpTimerHandler(rtimer_t *timer, char *name, void *context);
static void *DdcmpCreateOneShotTimer(void *timerContext, char *name, int seconds, void (*timerHandler)(void *timerContext));
static void DdcmpCancelOneShotTimer(void *timerHandle);
static void DdcmpSendData(void *context, byte *data, int length);
static int  DdcmpNotifyDataMessage(void *context, byte *data, int length);
static void DdcmpLog(LogLevel level, char *format, ...);

int DdcmpSockLineStart(line_t *line)
{
	/* We don't actually open a socket here, but just do the necessary preparations for when the remote side connects to the listen port.
	   In this case that means just setting up the address of the peer for verification when the connection comes in. */

	int ans = 1;
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)line->lineContext;
	sockaddr_t *destinationAddress;

	sockContext->bufferLength = 0;
	sockContext->bufferInUse = 0;

	memset(&sockContext->line, 0, sizeof(sockContext->line));
	sockContext->line.context = line;
    sockContext->line.name = sockContext->destinationHostName;
	sockContext->line.CreateOneShotTimer = DdcmpCreateOneShotTimer;
	sockContext->line.CancelOneShotTimer = DdcmpCancelOneShotTimer;
	sockContext->line.SendData = DdcmpSendData;
	sockContext->line.NotifyDataMessage = DdcmpNotifyDataMessage;
	sockContext->line.Log = DdcmpLog;

	destinationAddress = GetSocketAddressFromName(sockContext->destinationHostName, 0);
	if (destinationAddress != NULL)
	{
		memcpy(&sockContext->destinationAddress, destinationAddress, sizeof(sockContext->destinationAddress));
	}
	else
	{
		Log(LogDdcmpSock, LogError, "Cannot resolve address for %s, line will not start until DNS can resolve the address.\n", sockContext->destinationHostName);
	}

	if (DnsConfig.dnsConfigured)
	{
		time_t now;

		time(&now);
		CreateTimer("DNS", now + DnsConfig.pollPeriod, DnsConfig.pollPeriod, line, ProcessDnsTimer);
	}

    if (!ans)
    {
		Log(LogDdcmpSock, LogError, "Could not open circuit for %s\n", sockContext->destinationHostName);
    }

	return ans;
}

void DdcmpSockLineStop(line_t *line)
{
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)line->lineContext;
	CloseSocket(&sockContext->socket);
}

packet_t *DdcmpSockLineReadPacket(line_t *line)
{
	static packet_t sockPacket;
	byte buffer[MAX_DDCMP_BUFFER_LENGTH];
	int bufferLength;
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)line->lineContext;
	packet_t *packet = NULL;

	bufferLength = ReadFromStreamSocket(&sockContext->socket, buffer, MAX_DDCMP_BUFFER_LENGTH);

	if (bufferLength > 0)
	{
		Log(LogDdcmpSock, LogDetail, "Read %d bytes from DDCMP socket\n", bufferLength);
		LogBytes(LogDdcmpSock, LogVerbose, buffer, bufferLength);
		DdcmpProcessReceivedData(&sockContext->line, buffer, bufferLength);

		if (sockContext->bufferInUse)
		{
			sockPacket.rawData = sockContext->buffer;
			sockPacket.rawLen = sockContext->bufferLength;
			sockPacket.payload = sockContext->buffer;
			sockPacket.payloadLen = sockContext->bufferLength;
			sockPacket.IsDecnet = DdcmpSockIsDecnet;
			packet = &sockPacket;
			sockContext->bufferInUse = 0;
            line->stats.validPacketsReceived++;
        }
	}

	return packet;
}

int DdcmpSockLineWritePacket(line_t *line, packet_t *packet)
{
	int ans = 0;
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)line->lineContext;

    ans = DdcmpSendDataMessage(&sockContext->line, packet->payload, packet->payloadLen);

	return ans;
}

static void ProcessDnsTimer(rtimer_t *timer, char *name, void *context)
{
	line_t *line = (line_t *)context;
    circuit_t *circuit = GetCircuitFromLine(line);
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)line->lineContext;
	DnsSendQuery(sockContext->destinationHostName, (uint16)circuit->slot, ProcessDnsResponse, context);
}

static void ProcessDnsResponse(byte *address, void *context)
{
	line_t *line = (line_t *)context;
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)line->lineContext;
	sockaddr_t *newAddress = GetSocketAddressFromIpAddress(address, 0);

	if (memcmp(&sockContext->destinationAddress, newAddress, sizeof(sockaddr_t)) != 0)
	{
	    Log(LogDdcmpSock, LogInfo, "Changed IP address for %s\n", line->name);
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

static void DdcmpTimerHandler(rtimer_t *timer, char *name, void *context)
{
	ddcmp_sock_timer_t *sockTimerContext = (ddcmp_sock_timer_t *)context;
	sockTimerContext->timerHandler(sockTimerContext->timerContext);
	free(sockTimerContext);
}

static void *DdcmpCreateOneShotTimer(void *timerContext, char *name, int seconds, void (*timerHandler)(void *timerContext))
{
    ddcmp_sock_timer_t *sockTimerContext;
    time_t now;
	
	time(&now);

	sockTimerContext = (ddcmp_sock_timer_t *)malloc(sizeof(ddcmp_sock_timer_t));
	sockTimerContext->timerContext = timerContext;
	sockTimerContext->timerHandler = timerHandler;

	sockTimerContext->timer = CreateTimer(name, now + seconds, 0, sockTimerContext, DdcmpTimerHandler);

	return (void *)sockTimerContext;
}

static void DdcmpCancelOneShotTimer(void *timerHandle)
{
	ddcmp_sock_timer_t *sockTimerContext = (ddcmp_sock_timer_t *)timerHandle;
	StopTimer(sockTimerContext->timer);
	free(sockTimerContext);
}

static void DdcmpSendData(void *context, byte *data, int length)
{
    line_t *line = (line_t *)context;
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)line->lineContext;
	WriteToStreamSocket(&sockContext->socket, data, length);
}

static int DdcmpNotifyDataMessage(void *context, byte *data, int length)
{
    line_t *line = (line_t *)context;
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)line->lineContext;
	int ans = 0;
	if (sockContext->bufferInUse)
	{
		Log(LogDdcmpSock, LogError, "DDCMP overrun, previous message not read before next one delivered for line %s\n", line->name);
	}
	else
	{
		sockContext->bufferLength = (length <= MAX_DDCMP_DATA_LENGTH) ? length : MAX_DDCMP_DATA_LENGTH;
		memcpy(sockContext->buffer, data, sockContext->bufferLength);
		sockContext->bufferInUse = 1;
		ans = 1;
	}

	return ans;
}

static void DdcmpLog(LogLevel level, char *format, ...)
{
	va_list va;

	va_start(va, format);

	VLog(LogDdcmp, level, format, va);

	va_end(va);
}
