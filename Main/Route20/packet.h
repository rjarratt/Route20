/* packet.h: Packet code
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
#include "decnet.h"

#if !defined(PACKET_H)

typedef struct packet
{
	decnet_address_t from;
	decnet_address_t to;
	int rawLen;
	int payloadLen;
	byte *rawData;
	byte *payload;
	int (*IsDecnet)(struct packet *);
} packet_t;

uint16 LittleEndianBytesToUint16(byte *);
uint16 BigEndianBytesToUint16(byte *);
uint16 Uint16ToLittleEndian(uint16);
uint16 Uint16ToBigEndian(uint16);
uint16 LittleEndianToUint16(uint16);
uint16 BigEndianToUint16(uint16);

int EthValidPacket(packet_t *packet);
int EthPcapIsDecnet(packet_t *packet);
int EthSockIsDecnet(packet_t *packet);
void EthSetPayload(packet_t *packet);
void DumpPacket(packet_t *packet, char *msg);

#define PACKET_H
#endif
