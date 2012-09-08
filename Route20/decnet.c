/* decnet.c: DECnet types
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

#include "platform.h"
#include "decnet.h"

decnet_address_t AllEndNodesAddress = { AllEndNodes, 0, 0 };
decnet_address_t AllRoutersAddress  = { AllRouters, 0, 0 };

uint16 GetDecnetId(decnet_address_t address)
{
	return (uint16)(address.area * 1024 + address.node);
}

void GetDecnetAddressFromId(byte *id, decnet_address_t *address)
{
	address->type = Node;
	address->area = id[1] >> 2;
	address->node = ((id[1] % 4 ) << 8) | id[0];
}

int CompareDecnetAddress(decnet_address_t *address1, decnet_address_t *address2)
{
	return address1->type == address2->type && address1->area == address2->area && address1->node == address2->node;
}

void LogDecnetAddress(LogLevel level, decnet_address_t *address)
{
	if (address->type == AllRouters)
	{
		Log(level, "All Routers");
	}
	else if (address->type == AllLevel2Routers)
	{
		Log(level, "All Level 2 Routers");
	}
	else if (address->type == AllEndNodes)
	{
		Log(level, "All End Nodes");
	}
	else
	{
		Log(level, "%d.%d", address->area, address->node);
	}

}
