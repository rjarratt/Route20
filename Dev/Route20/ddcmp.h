/* ddcmp.h: DDCMP protocol
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

#include "basictypes.h"

#if !defined(DDCMP_H)

#define MAX_DDCMP_BUFFER_LENGTH 8192

typedef struct ddcmp_line
{
	void *context; /* for callbacks */

	void *controlBlock;

	void *(*CreateOneShotTimer)(void *timerContext, char *name, int seconds, void (*timerHandler)(void *timerContext));
	void (*CancelOneShotTimer)(void *timerHandle);
	void (*SendData)(void *context, byte *data, int length);
	void (*NotifyHalt)(void *context);
	void (*NotifyDataMessage)(void *context, byte *data, int length);
    void (*Log)(LogLevel level, char *format, ...);
} ddcmp_line_t;

void DdcmpStart(ddcmp_line_t *ddcmpLine);
void DdcmpHalt(ddcmp_line_t *ddcmpLine);
void DdcmpProcessReceivedData(ddcmp_line_t *ddcmpLine, byte *data, int length, byte **payload, int *payloadLength);

#define DDCMP
#endif
