/* nsp_transmit_queue.c: NSP transmit queue
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
#include "nsp_transmit_queue.h"

void InitialiseTransmitQueue(transmit_queue_t *queue)
{
	TerminateTransmitQueue(queue);
	queue->head = NULL;
	queue->tail = NULL;
}

void TerminateTransmitQueue(transmit_queue_t *queue)
{
	transmit_queue_entry_t *entry = queue->head;
	while (entry != NULL)
	{
        transmit_queue_entry_t *next = entry->next;
		free(entry);
		entry = next;
	}
}

void EnqueueToTransmitQueue(transmit_queue_t *queue, uint16 transmitSegmentNumber, byte *data, uint16 dataLength)
{
	transmit_queue_entry_t *entry = (transmit_queue_entry_t *)malloc(sizeof(transmit_queue_entry_t));
	memcpy(entry->data, data, dataLength > sizeof(entry->data) ? sizeof(entry->data) : dataLength);
	entry->dataLength = dataLength;
	entry->transmitSegmentNumber = transmitSegmentNumber;
	entry->next = NULL;

	if (queue->tail != NULL)
	{
		queue->tail->next = entry;
	}

	queue->tail = entry;

	if (queue->head == NULL)
	{
		queue->head = entry;
	}
}

int DequeueFromTransmitQueue(transmit_queue_t *queue, uint16 maxTransmitSegmentNumber, uint16 *nextTransmitSegmentNumber, byte *data, uint16 dataLength, uint16 *actualDataLength)
{
	int ans = 0;
	transmit_queue_entry_t *entry = queue->head;

	if (entry != NULL)
	{
		if (entry->transmitSegmentNumber <= maxTransmitSegmentNumber)
		{
			ans = 1;

			*actualDataLength = entry->dataLength <= dataLength ? entry->dataLength : dataLength;
			memcpy(data, entry->data, *actualDataLength);
			*nextTransmitSegmentNumber = entry->transmitSegmentNumber;
			queue->head = entry->next;
			if (queue->head == NULL)
			{
				queue->tail = NULL;
			}

			free(entry);
		}
	}

	return ans;
}