/* line.c: DECnet line
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

#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include "line.h"
#include "eth_pcap_line.h"
#include "eth_sock_line.h"
#include "ddcmp_sock_line.h"

static void LineUp(line_ptr line);
static void LineDown(line_ptr line);
static void LineWaitEventHandler(void *context);

// TODO: abstract properly by putting common functions for read/write etc which do logging, stats etc, then delegate to actual line implementations.

void LineCreateEthernetPcap(line_ptr line, char *name, void *notifyContext, void (*lineNotifyData)(line_ptr line))
{
	eth_pcap_t *context = (eth_pcap_t *)calloc(1, sizeof(eth_pcap_t));

	line->name = (char *)malloc(strlen(name)+1);
	strcpy(line->name, name);
	line->lineContext = (void *)context;
    line->notifyContext = notifyContext;
	line->lineState = LineStateOff;
    memset(&line->stats, 0, sizeof(line->stats));

	line->LineStart = EthPcapLineStart;
	line->LineStop = EthPcapLineStop;
    line->LineUp = LineUp;
    line->LineDown = LineDown;
	line->LineReadPacket = EthPcapLineReadPacket;
	line->LineWritePacket = EthPcapLineWritePacket;
	line->LineWaitEventHandler = LineWaitEventHandler;
    line->LineNotifyData = lineNotifyData;
}

void LineCreateEthernetSocket(line_ptr line, char *name, uint16 receivePort, char *destinationHostName, uint16 destinationPort, void *notifyContext, void (*lineNotifyData)(line_ptr line))
{
	eth_sock_t *context = (eth_sock_t *)calloc(1, sizeof(eth_sock_t));
	context->receivePort = receivePort;
	context->destinationPort = destinationPort;
	context->destinationHostName = (char *)malloc(strlen(destinationHostName) + 1);
	strcpy(context->destinationHostName, destinationHostName);

	line->name = (char *)malloc(strlen(name)+1);
	strcpy(line->name, name);
	line->lineContext = (void *)context;
    line->notifyContext = notifyContext;
	line->lineState = LineStateOff;
    memset(&line->stats, 0, sizeof(line->stats));

	line->LineStart = EthSockLineStart;
    line->LineStop = EthSockLineStop;
    line->LineUp = LineUp;
    line->LineDown = LineDown;
	line->LineReadPacket = EthSockLineReadPacket;
	line->LineWritePacket = EthSockLineWritePacket;
	line->LineWaitEventHandler = LineWaitEventHandler;
    line->LineNotifyData = lineNotifyData;
}

void LineCreateDdcmpSocket(line_ptr line, char *name, char *destinationHostName, uint16 destinationPort, int connectPoll, void *notifyContext, void (*lineNotifyData)(line_ptr line))
{
	ddcmp_sock_t *context = (ddcmp_sock_t *)calloc(1, sizeof(ddcmp_sock_t));
    InitialiseSocket(&context->socket, destinationHostName);
	
	context->destinationHostName = (char *)malloc(strlen(destinationHostName) + 1);
	context->destinationPort = destinationPort;
	strcpy(context->destinationHostName, destinationHostName);
    context->connectPoll = connectPoll;

	line->name = (char *)malloc(strlen(name)+1);
	strcpy(line->name, name);
	line->lineContext = (void *)context;
    line->notifyContext = notifyContext;
	line->lineState = LineStateOff;
    memset(&line->stats, 0, sizeof(line->stats));

	line->LineStart = DdcmpSockLineStart;
    line->LineOpen = DdcmpSockLineOpen;
    line->LineClosed = DdcmpSockLineClosed;
    line->LineStop = DdcmpSockLineStop;
    line->LineUp = LineUp;
    line->LineDown = LineDown;
	line->LineReadPacket = DdcmpSockLineReadPacket;
	line->LineWritePacket = DdcmpSockLineWritePacket;
	line->LineWaitEventHandler = LineWaitEventHandler;
    line->LineNotifyData = lineNotifyData;
}

static void LineUp(line_ptr line)
{
    Log(LogLine, LogInfo, "Line %s is up\n", line->name);
    line->lineState = LineStateUp;
    line->LineNotifyStateChange(line);
}

static void LineDown(line_ptr line)
{
    Log(LogLine, LogInfo, "Line %s is down\n", line->name);
    line->lineState = LineStateOff;
    line->LineNotifyStateChange(line);
}

static void LineWaitEventHandler(void *context)
{
    line_t *line = (line_t *)context;
    line->LineNotifyData(line);
}
