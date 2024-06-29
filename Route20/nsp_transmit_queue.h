/* nsp_transmit_queue.h: NSP transmit queue
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

#include "constants.h"
#include "basictypes.h"

#if !defined(NSP_TRANSMIT_QUEUE_H)

typedef struct transmit_queue_entry *transmit_queue_entry_ptr;

#pragma warning( disable: 4820 )
typedef struct transmit_queue_entry
{
	uint16  transmitSegmentNumber;
	char   *data[NSP_SEGMENT_SIZE];
	uint16    dataLength;
	transmit_queue_entry_ptr next; /* pints to the next entry towards the tail */
	
} transmit_queue_entry_t;

typedef struct
{
    transmit_queue_entry_ptr head; /* head is where the first entry in the queue is */
    transmit_queue_entry_ptr tail;
} transmit_queue_t;

void InitialiseTransmitQueue(transmit_queue_t *queue);
void TerminateTransmitQueue(transmit_queue_t *queue);
void EnqueueToTransmitQueue(transmit_queue_t *queue, uint16 transmitSegmentNumber, byte *data, uint16 dataLength);
int DequeueFromTransmitQueue(transmit_queue_t *queue, uint16 maxTransmitSegmentNumber, uint16 *nextTransmitSegmentNumber, byte *data, uint16 dataLength, uint16 *actualDataLength);

#define NSP_TRANSMIT_QUEUE_H
#endif
