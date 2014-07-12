/* messages.c: DECnet messages
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

#include <memory.h>
#include <stdlib.h>
#include <string.h>
#include "messages.h"
#include "adjacency.h"
#include "decnet.h"
#include "routing_database.h"
#include "area_routing_database.h"
#include "platform.h"

#define LEVEL2_SEGMENT_OFFSET 4
#define PHASEII_MSGFLG 0x58

typedef struct
{
	int count;
	rslist_t *rslist;
} rslistargs_t;

static int PhaseIIMessageType(packet_t *packet);
static void SetMessageFlags(packet_t *packet, byte flags);
static int IsShortDataPacket(packet_t *packet);
static int IsLongDataPacket(packet_t *packet);
static int IsPadded(packet_t *packet);
static int IsFutureVersionDataMessage(packet_t *packet);
static void RemovePadding(packet_t *packet);
static int BuildRsListCallback(adjacency_t *adjacency, void *context);
static routing_segment_t *GetNextLevel2Segment(packet_t *packet, int *currentOffset);
static int CountLevel2RoutingSegments(packet_t *packet, int firstSegmentOffset);
static uint16 Checksum(uint16 initial, uint16 data[], int n);

byte MessageFlags(packet_t *packet)
{
	return (byte)packet->payload[0];
}

int ControlMessageType(packet_t *packet)
{
	return (MessageFlags(packet) & 0x0E) >> 1;
}

int IsPhaseIIMessage(packet_t *packet)
{
	return (byte)packet->payload[0] == PHASEII_MSGFLG;
}

int IsControlMessage(packet_t *packet)
{
	return MessageFlags(packet) & 0x01;
}

int IsInitializationMessage(packet_t *packet)
{
	return IsControlMessage(packet) && ControlMessageType(packet) == 0;
}

int IsPhaseIINodeInitializationMessage(packet_t *packet)
{
	return PhaseIIMessageType(packet) == 1;
}

int IsVerificationMessage(packet_t *packet)
{
	return IsControlMessage(packet) && ControlMessageType(packet) == 1;
}

int IsHelloAndTestMessage(packet_t *packet)
{
	return IsControlMessage(packet) && ControlMessageType(packet) == 2;
}

int IsLevel1RoutingMessage(packet_t *packet)
{
	return IsControlMessage(packet) && ControlMessageType(packet) == 3;
}

int IsLevel2RoutingMessage(packet_t *packet)
{
	return IsControlMessage(packet) && ControlMessageType(packet) == 4;
}

int IsEthernetRouterHelloMessage(packet_t *packet)
{
	return IsControlMessage(packet) && ControlMessageType(packet) == 5;
}

int IsEthernetEndNodeHelloMessage(packet_t *packet)
{
	return IsControlMessage(packet) && ControlMessageType(packet) == 6;
}

int IsDataMessage(packet_t *packet)
{
	return !IsControlMessage(packet) && !IsFutureVersionDataMessage(packet);
}

int GetMessageBody(packet_t *packet)
{
	int ans = 0;
	if (packet->payloadLen <= 0)
	{
		Log(LogMessages, LogError, "Invalid message length, no flags.\n");
	}
	else
	{
		ans = 1;
		if (IsPadded(packet))
		{
			RemovePadding(packet);
			ans = packet->payloadLen >= 0;
			if (!ans)
			{
		        Log(LogMessages, LogError, "Invalid message length, padding length error.\n");
			}
		}
	}

	if (!ans)
	{
        DumpPacket(LogMessages, LogError, "Invalid packet dump", packet);
	}

	return ans;
}

int GetRouterLevel(int iinfo)
{
	int temp = iinfo & 0x3;
	int ans = temp;
	if (temp == 1)
	{
		ans = 2;
	}
	else if (temp == 2)
	{
		ans = 1;
	}

	return ans;
}

AdjacencyType GetAdjacencyType(int iinfo)
{
    AdjacencyType at;
	
	switch (GetRouterLevel(iinfo & 0x03))
	{
	case 1:
		{
			at = Level1RouterAdjacency;
			break;
		}
	case 2:
		{
			at = Level2RouterAdjacency;
			break;
		}
	default:
		{
			at = EndnodeAdjacency;
			break;
		}
	}

	return at;
}

int VerificationRequired(int iinfo)
{
	return iinfo & 0x04;
}

int VersionSupported(byte tiver[3])
{
	int ans = 0;
	if (tiver[0] >= 2) /* greater than or equal to 2.0.0 */
	{
		ans = 1;
	}

	if (ans == 0)
	{
		Log(LogMessages, LogWarning, "Received message for unsupported routing specification version %d.%d.%d\n", tiver[0], tiver[1], tiver[2]);
	}

	return ans;
}

packet_t *CreateInitialization(decnet_address_t address)
{
    static initialization_msg_t msg;
    static packet_t ans;

	memset(&msg, 0, sizeof(msg));

    msg.flags = 0x01;
	msg.tiver[0] = 2;
	msg.tiver[1] = 0;
	msg.tiver[2] = 0;
	msg.srcnode = Uint16ToLittleEndian(GetDecnetId(nodeInfo.address));
	msg.tiinfo = 4 | ((nodeInfo.level == 2) ? 1 : 2); /* request verification */
	msg.blksize = Uint16ToLittleEndian(576);
	msg.timer = Uint16ToLittleEndian(T3);

	ans.payload = (byte *)&msg;
	ans.payloadLen = sizeof(initialization_msg_t);
	ans.rawData = ans.payload;
	ans.rawLen = ans.payloadLen;

	return &ans;
}

packet_t *CreateVerification(decnet_address_t address)
{
    static verification_msg_t msg;
    static packet_t ans;

	memset(&msg, 0, sizeof(msg));

    msg.flags = 0x03;
	msg.srcnode = Uint16ToLittleEndian(GetDecnetId(nodeInfo.address));
	msg.fcnvalLen = 0;

	ans.payload = (byte *)&msg;
	ans.payloadLen = sizeof(verification_msg_t) - sizeof(msg.fcnval) + msg.fcnvalLen;
	ans.rawData = ans.payload;
	ans.rawLen = ans.payloadLen;

	return &ans;
}

packet_t *CreateHelloAndTest(decnet_address_t address)
{
    static hello_and_test_msg_t msg;
    static packet_t ans;

	memset(&msg, 0, sizeof(msg));

    msg.flags = 0x05;
	msg.srcnode = Uint16ToLittleEndian(GetDecnetId(nodeInfo.address));
    msg.testdataLength = 0;

	ans.payload = (byte *)&msg;
	ans.payloadLen = sizeof(hello_and_test_msg_t);
	ans.rawData = ans.payload;
	ans.rawLen = ans.payloadLen;

	return &ans;
}

packet_t *CreateEthernetHello(decnet_address_t address)
{
	static ethernet_router_hello_t msg;
	static packet_t ans;
	rslistargs_t rslistArgs;

	memset(&msg, 0, sizeof(msg));

	msg.flags = 0x0B;
	msg.tiver[0] = 2;
	msg.tiver[1] = 0;
	msg.tiver[2] = 0;
	SetDecnetAddress(&msg.id, address);
	msg.iinfo = (nodeInfo.level == 2) ? 1 : 2;
	msg.blksize = Uint16ToLittleEndian(1498);
	msg.priority = nodeInfo.priority;
	msg.area = 0;
	msg.timer = Uint16ToLittleEndian(T3);
	msg.mpd = 0;

	rslistArgs.count = 0;
	rslistArgs.rslist = msg.rslist;
    Log(LogMessages, LogDetail, "Building Ethernet Hello with nodes:");
	ProcessRouterAdjacencies(BuildRsListCallback, &rslistArgs);
    Log(LogMessages, LogDetail, "\n");

	msg.elistLen = (byte)(rslistArgs.count * sizeof(rslist_t) + 8);
	msg.rslistlen = (byte)(rslistArgs.count * sizeof(rslist_t));

	ans.payload = (byte *)&msg;
	ans.payloadLen = sizeof(ethernet_router_hello_t) - (sizeof(msg.rslist) - msg.rslistlen);
	ans.rawData = ans.payload;
	ans.rawLen = ans.payloadLen;

	return &ans;
}

packet_t *CreateLevel1RoutingMessage(int from, int count)
{
	static single_segment_level1_routing_t msg;
	static packet_t ans;
	int i;

	memset(&msg, 0, sizeof(msg));

	msg.flags = 0x07;
	msg.srcNode = Uint16ToLittleEndian(GetDecnetId(nodeInfo.address));
	msg.res = 0;
	msg.count = Uint16ToLittleEndian((uint16)count);
	msg.start = Uint16ToLittleEndian((uint16)from);

	for(i = from; i < from + count; i++)
	{
		msg.rtginfo[i - from] = Uint16ToLittleEndian((uint16)((Minhop[i] << 10) | Mincost[i]));
	}

	msg.checksum = Uint16ToLittleEndian(Checksum(1, &msg.count, count + 2));

	ans.payload = (byte *)&msg;
	ans.payloadLen = sizeof(msg);
	ans.rawData = ans.payload;
	ans.rawLen = ans.payloadLen;

	return &ans;
}

packet_t *CreateLevel2RoutingMessage(void)
{
	static single_segment_level2_routing_t msg;
	static packet_t ans;
	int i;

	memset(&msg, 0, sizeof(msg));

	msg.flags = 0x09;
	msg.srcNode = Uint16ToLittleEndian(GetDecnetId(nodeInfo.address));
	msg.res = 0;
	msg.count = Uint16ToLittleEndian(NA);
	msg.start = Uint16ToLittleEndian(1);

	for(i = 1; i <= NA; i++)
	{
		msg.rtginfo[i - 1] = Uint16ToLittleEndian((uint16)((AMinhop[i] << 10) | AMincost[i]));
	}

	msg.checksum = Uint16ToLittleEndian(Checksum(1, &msg.count, NA + 2));

	ans.payload = (byte *)&msg;
	ans.payloadLen = sizeof(msg);
	ans.rawData = ans.payload;
	ans.rawLen = ans.payloadLen;

	return &ans;
}

int IsValidRouterHelloMessage(packet_t *packet)
{
	int ans = 0;

	if (packet->payloadLen < 19)
	{
		Log(LogMessages, LogError, "Router Hello message too short\n");
	}
	else
	{
		ethernet_router_hello_t *msg = (ethernet_router_hello_t *)packet->payload;
		if (packet->payloadLen < msg->elistLen + 19)
		{
		    Log(LogMessages, LogError, "Router Hello message too short for E-LIST.\n");
		}
		else if (msg->elistLen < 8)
		{
		    Log(LogMessages, LogError, "Router Hello message E-LIST is too short, length is %d.\n", msg->elistLen);
		}
		else
		{
			if (msg->rslistlen % 7 != 0)
			{
		        Log(LogMessages, LogError, "Router Hello message RS-LIST incomplete.\n");
			}
			else if (msg->elistLen != msg->rslistlen + 8)
			{
		        Log(LogMessages, LogError, "Router Hello message RS-LIST length mismatch.\n");
			}
			else
			{
				ans = 1;
			}
		}
	}

	if (!ans)
	{
		DumpPacket(LogMessages, LogError, "Bad packet dump. ", packet);
	}

	return ans;
}

int IsValidEndnodeHelloMessage(packet_t *packet)
{
	int valid = 0;

	if (packet->payloadLen < 32)
	{
		Log(LogMessages, LogError, "Endnode Hello message too short\n");
	}
	else
	{
		ethernet_endnode_hello_t *msg = (ethernet_endnode_hello_t *)packet->payload;
		if (packet->payloadLen < msg->dataLen + 32)
		{
		    Log(LogMessages, LogError, "Endnode Hello message too short for DATA.\n");
		}
		else
		{
			valid = 1;
		}
	}

	if (!valid)
	{
        DumpPacket(LogMessages, LogError, "Invalid packet dump", packet);
	}

	return valid;
}

void ExtractRoutingInfo(uint16 routingInfo, int *hops, int *cost)
{
	*hops = routingInfo >> 10;
	*cost = routingInfo & 0x03FF;
}

node_init_phaseii_t *ValidateAndParseNodeInitPhaseIIMessage(packet_t *packet)
{
	static node_init_phaseii_t msg;
	node_init_phaseii_t *ans = NULL;
	int valid = 0;
	byte nodenameLen = 0;
	byte sysverLen = 0;

	if (packet->payloadLen < 4)
	{
		Log(LogMessages, LogError, "Phase II Node Initialization message too short\n");
	}
	else
	{
		nodenameLen = packet->payload[3];
		if (nodenameLen > 6)
		{
		    Log(LogMessages, LogError, "Phase II Node Initialization node name too long\n");
		}
		else if (packet->payloadLen < 4 + nodenameLen + 15)
		{
		    Log(LogMessages, LogError, "Phase II Node Initialization message too short\n");
		}
		else
		{
			sysverLen = packet->payload[4 + nodenameLen + 14];
			if (sysverLen > 32)
			{
		        Log(LogMessages, LogError, "Phase II Node Initialization sysver too long\n");
			}
			else if (packet->payloadLen < 4 + nodenameLen + 15 + sysverLen)
			{
		        Log(LogMessages, LogError, "Phase II Node Initialization message too short\n");
			}
			else
			{
				valid = 1;
			}
		}
	}

	if (valid)
	{
	    int i = 0;
		valid = 0;

		memset(&msg, 0, sizeof(msg));
		msg.msgflg = packet->payload[i++];
		msg.starttype = packet->payload[i++];
		msg.nodeaddr = packet->payload[i++];
		strncpy(msg.nodename, (char *)&packet->payload[i + 1], nodenameLen);
		i += nodenameLen + 1;
		memcpy(&msg.functions, &packet->payload[i], 14);
		msg.blksize = LittleEndianToUint16(msg.blksize);
		msg.nspsize = LittleEndianToUint16(msg.nspsize);
		msg.maxlnks = LittleEndianToUint16(msg.maxlnks);
		strncpy(msg.sysver, (char *)&packet->payload[4 + nodenameLen + 15 + sysverLen], sysverLen);

		if (msg.nodeaddr <= 2 || msg.nodeaddr >= 241)
		{
			Log(LogMessages, LogError, "Phase II Node Initialization node address invalid\n");
		}
		else if (msg.functions != 0 && msg.functions != 7)
		{
			Log(LogMessages, LogError, "Phase II Node Initialization functions value invalid\n");
		}
		else if ((msg.requests & 0xF8) != 0)
		{
			Log(LogMessages, LogError, "Phase II Node Initialization requests value invalid\n");
		}
		else if (msg.nspsize > msg.blksize)
		{
			Log(LogMessages, LogError, "Phase II Node Initialization NSP size too big\n");
		}
		else if (msg.maxlnks > 4095)
		{
			Log(LogMessages, LogError, "Phase II Node Initialization max links too big\n");
		}
		else
		{
			valid = 1;
		}
	}

	if (valid)
	{
		ans = &msg;
	}
	else
	{
        DumpPacket(LogMessages, LogError, "Invalid packet dump", packet);
	}

	return ans;
}

int IsValidInitializationMessage(packet_t *packet)
{
    int valid = 0;
    if (packet->payloadLen < sizeof(initialization_msg_t))
    {
		Log(LogMessages, LogError, "Initialization message too short\n");
    }
    else
    {
        initialization_msg_t *msg = (initialization_msg_t *)packet->payload;
        if (msg->reserved != 0)
        {
		    Log(LogMessages, LogError, "Initialization message contains non-zero reserved field\n");
        }
        else
        {
            valid = 1;
        }
    }

	if (!valid)
	{
        DumpPacket(LogMessages, LogError, "Invalid packet dump", packet);
	}

    return valid;
}

int IsValidVerificationMessage(packet_t *packet)
{
    int valid = 0;
    verification_msg_t *msg;
    if (packet->payloadLen < (sizeof(verification_msg_t) - sizeof(msg->fcnval)))
    {
		Log(LogMessages, LogError, "Verification message too short\n");
    }
    else
    {
        msg = (verification_msg_t *)packet->payload;
        if (msg->fcnvalLen > sizeof(msg->fcnval))
        {
		    Log(LogMessages, LogError, "Verification message function value length too big\n");
        }
        else
        {
            valid = 1;
        }
    }

	if (!valid)
	{
        DumpPacket(LogMessages, LogError, "Invalid packet dump", packet);
	}

    return valid;
}


int IsValidHelloAndTestMessage(packet_t *packet)
{
    int valid = 0;
    if (packet->payloadLen < sizeof(hello_and_test_msg_t))
    {
		Log(LogMessages, LogError, "Hello And Test message too short\n");
    }
    else
    {
        hello_and_test_msg_t *msg = (hello_and_test_msg_t *)packet->payload;
        if (msg->testdataLength > 128)
        {
		    Log(LogMessages, LogError, "Hello And Test message contains too much test data\n");
        }
        else
        {
            int i;
            valid = 1;
            for (i = 0; i < msg->testdataLength; i++)
            {
                if (msg->testdata[i] != 0252)
                {
                    valid = 0;
		            Log(LogMessages, LogError, "Hello And Test message contains invalid test data\n");
                    break;
                }
            }
        }
    }

	if (!valid)
	{
        DumpPacket(LogMessages, LogError, "Invalid packet dump", packet);
	}

    return valid;
}

initialization_msg_t *ParseInitializationMessage(packet_t *packet)
{
    initialization_msg_t *msg = (initialization_msg_t *)packet->payload;
    msg->blksize = LittleEndianToUint16(msg->blksize);
    msg->timer = LittleEndianToUint16(msg->timer);
    return msg;
}

routing_msg_t *ParseRoutingMessage(packet_t *packet)
{
	routing_msg_t *msg = NULL;
	int segCount;
	int i;
	int currentOffset = LEVEL2_SEGMENT_OFFSET;
	uint16 calculatedChecksum = 1;
	uint16 actualChecksum;

	if (packet->payloadLen < 6)
	{
		Log(LogMessages, LogError, "Routing message too short\n");
	}
	else
	{
		segCount = CountLevel2RoutingSegments(packet, LEVEL2_SEGMENT_OFFSET);

		if (segCount >= 0)
		{
			msg = (routing_msg_t *)malloc(sizeof(routing_msg_t) + segCount * sizeof(routing_segment_t *));
			msg->rawData = (byte *)malloc(packet->payloadLen);
			memcpy(msg->rawData, packet->payload, packet->payloadLen);

			msg->flags = packet->payload[0];
			GetDecnetAddressFromId(&packet->payload[1], &msg->srcnode);
			msg->segmentCount = segCount;

			for (i = 0; i < msg->segmentCount; i++)
			{
				int j;
				uint16 count;

				msg->segments[i] = GetNextLevel2Segment(packet, &currentOffset);
				count = LittleEndianToUint16(msg->segments[i]->count);

				calculatedChecksum = Checksum(calculatedChecksum, (uint16 *)msg->segments[i], count + 2);

				msg->segments[i]->count = count;
				msg->segments[i]->start = LittleEndianToUint16(msg->segments[i]->start);
				for (j = 0; j < count; j++)
				{
					msg->segments[i]->rtginfo[j] = LittleEndianToUint16(msg->segments[i]->rtginfo[j]);
				}
			}

			actualChecksum = LittleEndianBytesToUint16(&packet->payload[currentOffset]);

			if (actualChecksum != calculatedChecksum)
			{
				Log(LogMessages, LogError, "Level 2 Routing Checksum error, expected %04X, was %04X\n", actualChecksum, calculatedChecksum);
				FreeRoutingMessage(msg);
				msg = NULL;
			}
		}
		else
		{
			Log(LogMessages, LogError, "Invalid routing message\n");
		}
	}

	if (msg == NULL)
	{
        DumpPacket(LogMessages, LogError, "Invalid packet dump", packet);
	}

	return msg;
}

void FreeRoutingMessage(routing_msg_t *msg)
{
	free(msg->rawData);
	free(msg);
}

int IsValidDataPacket(packet_t *packet)
{
	int ans = 0;
	if (IsShortDataPacket(packet))
	{
		short_data_packet_t *shortData = (short_data_packet_t *)packet->payload;
		if (packet->payloadLen >= sizeof(short_data_packet_hdr_t))
		{
			if ((shortData->header.flags & 0x60) == 0
				&&
				(shortData->header.forward & 0xC0) == 0)
			{
			    ans = 1;
			}
		}
	}
	else if (IsLongDataPacket(packet))
	{
		long_data_packet_t *longData = (long_data_packet_t *)packet->payload;
		if (packet->payloadLen >= sizeof(long_data_packet_hdr_t))
		{
			if ((longData->header.flags & 0x40) == 0
				&&
				longData->header.d_area == 0
				&&
				longData->header.d_subsarea == 0
				&&
				longData->header.s_area == 0
				&&
				longData->header.s_subsarea == 0
				&&
				longData->header.s_class == 0
				&&
				longData->header.nl2 == 0
				&&
				longData->header.pt == 0
				&&
				longData->header.d_id.id[0] == 0xAA
				&&
				longData->header.d_id.id[1] == 0x00
				&&
				longData->header.d_id.id[2] == 0x04
				&&
				longData->header.d_id.id[3] == 0x00
				&&
				longData->header.s_id.id[0] == 0xAA
				&&
				longData->header.s_id.id[1] == 0x00
				&&
				longData->header.s_id.id[2] == 0x04
				&&
				longData->header.s_id.id[3] == 0x00)
			{
			    ans = 1;
			}
		}
	}

	if (!ans)
	{
		Log(LogMessages, LogError, "Message format error, data packet header\n");
        DumpPacket(LogMessages, LogError, "Invalid packet dump", packet);
	}

	return ans;
}

int IsReturnToSender(byte flags)
{
	return (flags & 0x10) != 0;
}

int IsReturnToSenderRequest(byte flags)
{
	return (flags & 0x08) != 0;
}

void SetIntraEthernet(packet_t *packet)
{
	SetMessageFlags(packet, MessageFlags(packet) | 0x20);
}

void ClearIntraEthernet(packet_t *packet)
{
	SetMessageFlags(packet, MessageFlags(packet) & ~0x20);
}

void ExtractDataPacketData(packet_t *packet, decnet_address_t *srcNode, decnet_address_t *dstNode, byte *flags, int *visits, byte **data, int *dataLength)
{
	if (IsShortDataPacket(packet))
	{
		short_data_packet_t *shortData = (short_data_packet_t *)packet->payload;
		GetDecnetAddressFromId(shortData->header.srcNode, srcNode);
		GetDecnetAddressFromId(shortData->header.dstNode, dstNode);
		*flags = shortData->header.flags;
		*visits = shortData->header.forward & 0x3F;
		*data = (byte *)shortData->body;
		*dataLength = packet->payloadLen - sizeof(short_data_packet_hdr_t);
	}
	else
	{
		long_data_packet_t *longData = (long_data_packet_t *)packet->payload;
		GetDecnetAddress(&longData->header.s_id, srcNode);
		GetDecnetAddress(&longData->header.d_id, dstNode);
		*flags = longData->header.flags;
		*visits = longData->header.visit_ct;
		*data = (byte *)longData->body;
		*dataLength = packet->payloadLen - sizeof(long_data_packet_hdr_t);
	}
}

packet_t *CreateLongDataMessage(decnet_address_t *srcNode, decnet_address_t *dstNode, byte flags, int visits, byte *data, int dataLength)
{
	static long_data_packet_t msg;
	static packet_t ans;

	memset(&msg, 0, sizeof(msg));

	msg.header.flags = flags;
	SetDecnetAddress(&msg.header.d_id, *dstNode);
	SetDecnetAddress(&msg.header.s_id, *srcNode);
	msg.header.visit_ct = (byte)visits;
	memcpy(msg.body, data, dataLength);

	memcpy(&ans.from, &nodeInfo.address, sizeof(decnet_address_t));
	ans.payload = (byte *)&msg;
	ans.payloadLen = sizeof(long_data_packet_hdr_t) + dataLength;
	ans.rawData = ans.payload;
	ans.rawLen = ans.payloadLen;

	return &ans;
}

packet_t *CreateNodeInitPhaseIIMessage(decnet_address_t address, char *name)
{
	static node_init_phaseii_t msg;
	static packet_t pkt;
	packet_t *ans = NULL;

	if (address.node <= 1 || address.node >= 241)
	{
		Log(LogMessages, LogError, "router node address out of range for Phase II messages\n");
	}
	else
	{
		int sysverlen;
		msg.msgflg = PHASEII_MSGFLG;
		msg.starttype = 1;
		msg.nodeaddr = address.node & 0xFF;
		msg.nodenameLen = 5;
		memcpy(msg.nodename, name, strlen(name));
		msg.functions = 0x7;
		msg.requests = 0;
		msg.blksize = Uint16ToLittleEndian(4096);
		msg.nspsize = Uint16ToLittleEndian(256); // TODO: not sure what to set for NSP size
		msg.maxlnks = Uint16ToLittleEndian(4095);
		msg.routver[0] = 3;
		msg.routver[1] = 0;
		msg.routver[2] = 0;
		msg.commver[0] = 3;
		msg.commver[1] = 0;
		msg.commver[2] = 0;
		strcpy(msg.sysver, "user-mode DECnet router");
		sysverlen = strlen(msg.sysver);
		msg.sysverLen = (byte)sysverlen;

		memmove(msg.nodename + msg.nodenameLen, &msg.functions, 15 + sysverlen);

		pkt.payload = (byte *)&msg;
	    pkt.payloadLen = 4 + msg.nodenameLen + 15 + sysverlen;
        pkt.rawData = pkt.payload;
	    pkt.rawLen = pkt.payloadLen;

		ans = &pkt;
	}

	return ans;
}

static int PhaseIIMessageType(packet_t *packet)
{
	int ans = -1;
	if (packet->payloadLen > 1)
	{
		ans = packet->payload[1];
	}

	return ans;
}

static void SetMessageFlags(packet_t *packet, byte flags)
{
	packet->payload[0] = flags;
}

static int IsShortDataPacket(packet_t *packet)
{
	return (packet->payload[0] & 0x7)  == 2;
}

static int IsLongDataPacket(packet_t *packet)
{
	return (packet->payload[0] & 0x7)  == 6;
}

static int IsPadded(packet_t *packet)
{
	return (byte)packet->payload[0] & 0x80;
}

static int IsFutureVersionDataMessage(packet_t *packet)
{
    return MessageFlags(packet) & 0x40;
}

static void RemovePadding(packet_t *packet)
{
	int padding = (byte)packet->payload[0] & 0x7F;
	packet->payload += padding;
	packet->payloadLen -= padding;
	//Log(LogInfo, "Padding advanced by %d. Payload is now at %d. Raw is at %d\n", padding, packet->payload, packet->rawData);
}

static int BuildRsListCallback(adjacency_t *adjacency, void *context)
{
	rslistargs_t *rslistArgs = (rslistargs_t *)context;
	byte state;
	rslist_t *rslist = &rslistArgs->rslist[rslistArgs->count++];

    Log(LogMessages, LogDetail, " ");
    LogDecnetAddress(LogMessages, LogDetail, &adjacency->id);
    SetDecnetAddress(&rslist->router, adjacency->id);
	state = (adjacency->state == Up)? 0x80 : 0;
    Log(LogMessages, LogDetail, " %s", (adjacency->state == Up)? "Up" : "Down");
	rslist->priority_state = adjacency->priority | state;

	return 1;
}

static routing_segment_t *GetNextLevel2Segment(packet_t *packet, int *currentOffset)
{
	routing_segment_t *ans = NULL;
	if (*currentOffset < (packet->payloadLen - 2))
	{
		int segBytes = packet->payloadLen - 2 - *currentOffset;
		if (segBytes < 4)
		{
			Log(LogMessages, LogError, "Routing message segment header incorrect\n");
            DumpPacket(LogMessages, LogError, "Invalid packet dump", packet);
		}
		else
		{
		    int count = LittleEndianBytesToUint16(&packet->payload[*currentOffset]);
			int segLength = 4 + count * 2;
			if (segBytes < segLength)
			{
			    Log(LogMessages, LogError, "Routing message segment length incorrect\n");
                DumpPacket(LogMessages, LogError, "Invalid packet dump", packet);
			}
			else
			{
		        ans = (routing_segment_t *)&packet->payload[*currentOffset];
		        *currentOffset += segLength;
			}
		}
	}

	return ans;
}

static int CountLevel2RoutingSegments(packet_t *packet, int firstSegmentOffset)
{
	int ans = 0;
	int currentOffset = firstSegmentOffset;

	while (GetNextLevel2Segment(packet, &currentOffset) != NULL)
	{
		ans++;
	}

	if (currentOffset != packet->payloadLen - 2)
	{
		ans = -1;
	}

	return ans;
}

static uint16 Checksum(uint16 initial, uint16 data[], int n)
{
	int i;
	int sum;
	uint16 ans = initial;
	for (i = 0; i < n; i++)
	{
		uint16 temp = LittleEndianToUint16(data[i]);
		sum = ans + temp;
		if ((sum >> 16) != 0)
		{
			sum++;
		}

		ans = sum & 0xFFFF;
	}

	return ans;
}
