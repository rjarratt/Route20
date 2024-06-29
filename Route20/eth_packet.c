/* eth_packet.h: Ethernet packet
  ------------------------------------------------------------------------------

   Copyright (c) 2012, Robert M. A. Jarratt
   Portions Johnny Billquist

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

#include "eth_packet.h"

static int GetEtherType(packet_t *packet, int type);

int EthPacketIsDecnet(packet_t *packet) /* johnny billquist code */
{
	return is_ethertype(packet, 0x6003);
}

static int GetEtherType(packet_t *packet, int type) /* johnny billquist code */
{
	int ans = (((byte)packet->data[13] == (byte)(type & 0xff)) &&
		((byte)packet->data[12] == (byte)(type >> 8)));
	return ans;
}

