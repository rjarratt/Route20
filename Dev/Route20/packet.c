/* packet.h: Packet code
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

#include <stdio.h>
#include "packet.h"
#include "platform.h"

static int is_ethertype(packet_t *packet, int type);
static uint16 EthPayloadLen(packet_t *packet);

uint16 LittleEndianBytesToUint16(byte *ptr)
{
	uint16 temp = 0;

	temp = (ptr[1]) << 8;
	temp = temp | ((ptr[0]) & 0xFF);

	return temp;
}

uint16 BigEndianBytesToUint16(byte *ptr)
{
	uint16 temp = 0;

	temp = (ptr[0]) << 8;
	temp = temp | ((ptr[1]) & 0xFF);

	return temp;
}

uint16 Uint16ToLittleEndian(uint16 i)
{
	uint16 temp = 0;
	byte *ans = (byte *)&temp;

	*ans++ = i & 0xFF;
	*ans = i >> 8;

	return temp;
}

uint16 Uint16ToBigEndian(uint16 i)
{
	uint16 temp = 0;
	byte *ans = (byte *)&temp;

	*ans++ = i >> 8;
	*ans = i & 0xFF;

	return temp;
}

uint16 LittleEndianToUint16(uint16 i)
{
	return LittleEndianBytesToUint16((byte *)&i);
}

uint16 BigEndianToUint16(uint16 i)
{
	return BigEndianBytesToUint16((byte *)&i);
}

int EthValidPacket(packet_t *packet)
{
	int ans = 0;

	if (packet->rawData != NULL)
	{
		ans = packet->rawLen >= 16;
		if (!ans)
		{
			DumpPacket(LogMessages, LogError, "Malformed ethernet packet ignored.", packet);
		}
		else if (packet->IsDecnet(packet))
		{
			uint16 statedLen = EthPayloadLen(packet);
			ans = statedLen <= packet->rawLen - 16;
			if (!ans)
			{
				Log(LogMessages, LogError, "Ethernet payload length error, expected %d, was %d\n", statedLen, packet->rawLen - 16);
			    //DumpPacket(packet, ".");
			}
		}
	}

	return ans;
}

int EthPcapIsDecnet(packet_t *packet)
{
	return is_ethertype(packet, 0x0360); /* johnny billquist code */
}

int EthSockIsDecnet(packet_t *packet)
{
	return is_ethertype(packet, 0x0360); /* johnny billquist code */
}

int DdcmpSockIsDecnet(packet_t *packet)
{
	return 1;
}

void EthSetPayload(packet_t *packet)
{
	packet->payload = packet->rawData + 16;
	packet->payloadLen = EthPayloadLen(packet);
}

void DumpPacket(LogSource source, LogLevel level, char *msg, packet_t *packet)
{
	Log(source, level, "%s Packet raw length = %d Payload offset = %d, Payload length = %d\n", msg, packet->rawLen, packet->payload - packet->rawData, packet->payloadLen);
	LogBytes(source, level, packet->rawData, packet->rawLen);
}

static int is_ethertype(packet_t *packet, int type)
{
	uint16 actualType = LittleEndianBytesToUint16(&packet->rawData[12]);
	return type == actualType;
}

static uint16 EthPayloadLen(packet_t *packet)
{
	return LittleEndianBytesToUint16(&packet->rawData[14]);
}
