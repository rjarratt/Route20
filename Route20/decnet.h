/* decnet.h: DECnet types
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

#include "basictypes.h"
#include "logging.h"

#if !defined(DECNET_H)

#define MAX_NODE_NAME_LENGTH 6

typedef enum
{
	Node,
	AllRouters,
	AllLevel2Routers,
	AllEndNodes
} DecnetAddressType;

typedef struct
{
	DecnetAddressType type;
	int area;
	int node;
} decnet_address_t;

extern decnet_address_t AllEndNodesAddress;
extern decnet_address_t AllRoutersAddress;
extern decnet_address_t AllLevel2RoutersAddress;

uint16 GetDecnetId(decnet_address_t address);
void GetDecnetAddressFromId(byte *id, decnet_address_t *address);
int CompareDecnetAddress(decnet_address_t *address1, decnet_address_t *address2);
void LogDecnetAddress(LogSource source, LogLevel level, decnet_address_t *address);

#define DECNET_H
#endif
