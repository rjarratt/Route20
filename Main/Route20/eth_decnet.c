/* eth_decnet.c: Ethernet DECnet definitions
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

#include "eth_decnet.h"

void SetDecnetAddress(decnet_eth_address_t *ethAddr, decnet_address_t address)
{
	if (address.type == AllRouters)
	{
	    ethAddr->id[0] = 0xAB;
	    ethAddr->id[1] = 0x00;
	    ethAddr->id[2] = 0x00;
	    ethAddr->id[3] = 0x03;
	    ethAddr->id[4] = 0x00;
	    ethAddr->id[5] = 0x00;
	}
	else if (address.type == AllLevel2Routers)
	{
	    ethAddr->id[0] = 0x09;
	    ethAddr->id[1] = 0x00;
	    ethAddr->id[2] = 0x2B;
	    ethAddr->id[3] = 0x02;
	    ethAddr->id[4] = 0x00;
	    ethAddr->id[5] = 0x00;
	}
	else if (address.type == AllEndNodes)
	{
	    ethAddr->id[0] = 0xAB;
	    ethAddr->id[1] = 0x00;
	    ethAddr->id[2] = 0x00;
	    ethAddr->id[3] = 0x04;
	    ethAddr->id[4] = 0x00;
	    ethAddr->id[5] = 0x00;
	}
	else
	{
		ethAddr->id[0] = (byte)'\xAA';
		ethAddr->id[1] = (byte)'\x00';
		ethAddr->id[2] = (byte)'\x04';
		ethAddr->id[3] = (byte)'\x00'; 
		ethAddr->id[4] = (byte)address.node;
		ethAddr->id[5] = (byte)address.area << 2 | (byte)(address.node >> 8);
	}
}

void GetDecnetAddress(decnet_eth_address_t *ethAddr, decnet_address_t *address)
{
	GetDecnetAddressFromId(&ethAddr->id[4], address);

	if (ethAddr->id[0] == 0xAB && ethAddr->id[1] == 0x00 && ethAddr->id[2] == 0x00)
	{
		if (ethAddr->id[3] == 0x03)
		{
			address->type = AllRouters;
		}
		else if (ethAddr->id[3] == 0x04)
		{
			address->type = AllEndNodes;
		}
	}
	else if (ethAddr->id[0] == 0x09 && ethAddr->id[1] == 0x00 && ethAddr->id[2] == 0x2B && ethAddr->id[3] == 0x02 && ethAddr->id[4] == 0x00 && ethAddr->id[5] == 0x00)
	{
		address->type = AllLevel2Routers;
	}
}
