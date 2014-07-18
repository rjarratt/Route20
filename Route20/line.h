/* line.h: DECnet line
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

#include "packet.h"

#if !defined(LINE_H)

typedef struct line *line_ptr;

typedef enum
{
	LineStateOff,
	LineStateUp
} LineState;

typedef struct line_stats
{
	long          validPacketsReceived;
	long          invalidPacketsReceived; // TODO: not sure all scenarios covered for line stats, also no writing counters
} line_stats_t;

typedef struct line
{
	char              *name;
	void              *lineContext; /* internal context */
    void              *notifyContext; /* context for notify callbacks */
	int                waitHandle;
	LineState          lineState;
	line_stats_t       stats;

	int (*LineStart)(line_ptr line);
	int (*LineOpen)(line_ptr line);
    void (*LineClosed)(line_ptr line);
	void (*LineStop)(line_ptr line);
	void (*LineUp)(line_ptr line);
	void (*LineDown)(line_ptr line);
	packet_t *(*LineReadPacket)(line_ptr line);
	int (*LineWritePacket)(line_ptr line, packet_t *packet);
	void (*LineWaitEventHandler)(void *context);
    void (*LineNotifyStateChange)(line_ptr line); /* set by the init layers only */
    void (*LineNotifyData)(line_ptr line);
} line_t;

void LineCreateEthernetPcap(line_ptr line, char *name, void *notifyContext, void (*lineNotifyData)(line_ptr line));
void LineCreateEthernetSocket(line_ptr line, char *name, uint16 receivePort, char *destinationHostName, uint16 destinationPort, void *notifyContext, void (*lineNotifyData)(line_ptr line));
void LineCreateDdcmpSocket(line_ptr line, char *name, char *destinationHostName, uint16 destinationPort, int connectPoll, void *notifyContext, void (*lineNotifyData)(line_ptr line));

#define LINE_H
#endif
