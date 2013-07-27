/* messages.h: DECnet messages
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
#include "packet.h"
#include "basictypes.h"
#include "eth_decnet.h"
#include "adjacency.h"

#if !defined(MESSAGES_H)

#pragma pack(push)
#pragma pack(1)

typedef struct
{
	uint16 count;
	uint16 start;
	uint16 rtginfo[];
} routing_segment_t;

/* variable length structures mean this structure cannot be specified as a direct mapping */
typedef struct
{
	byte                *rawData;
	byte                 flags;
	decnet_address_t     srcnode;
	int                  segmentCount;
	routing_segment_t    *segments[];
} routing_msg_t;

typedef struct
{
	byte          srcnode[2];
	byte          tiinfo;
	uint16        blksize;
	byte          tiver[3];
	uint16        timer;

} initialization_msg_t;

typedef struct
{
	byte   flags;
	uint16 srcNode;
	byte   res;
	uint16 count;
	uint16 start;
	uint16 rtginfo[LEVEL1_BATCH_SIZE];
	uint16 checksum;
} single_segment_level1_routing_t;

typedef struct
{
	byte   flags;
	uint16 srcNode;
	byte   res;
	uint16 count;
	uint16 start;
	uint16 rtginfo[NA];
	uint16 checksum;
} single_segment_level2_routing_t;

typedef struct
{
	byte                 flags;
	byte                 tiver[3];
	decnet_eth_address_t id;
	byte                 iinfo;
	uint16               blksize;
	byte                 priority;
	byte                 area;
	uint16               timer;
	byte                 mpd;
	byte                 elistLen;
	byte                 name[7];
	byte                 rslistlen;
	rslist_t             rslist[NBRA];
} ethernet_router_hello_t;

typedef struct
{
	byte                 flags;
	byte                 tiver[3];
	decnet_eth_address_t id;
	byte                 iinfo;
	uint16               blksize;
	byte                 area;
	byte                 seed[8];
	decnet_eth_address_t neighbor;
	uint16               timer;
	byte                 mpd;
	byte                 dataLen;
	byte                 data[127];
} ethernet_endnode_hello_t;

typedef struct
{
	byte flags;
	byte dstNode[2];
	byte srcNode[2];
	byte forward;
} short_data_packet_hdr_t;

typedef struct
{
	short_data_packet_hdr_t header;
	byte                    body[MAX_DATA_MESSAGE_BODY_SIZE];
} short_data_packet_t;

typedef struct
{
	byte                 flags;
	byte                 d_area;
	byte                 d_subsarea;
	decnet_eth_address_t d_id;
	byte                 s_area;
	byte                 s_subsarea;
	decnet_eth_address_t s_id;
	byte                 nl2;
	byte                 visit_ct;
	byte                 s_class;
	byte                 pt;
} long_data_packet_hdr_t;

typedef struct
{
	long_data_packet_hdr_t header;
	byte                   body[MAX_DATA_MESSAGE_BODY_SIZE];
} long_data_packet_t;

typedef struct
{
	byte                   padding;
	long_data_packet_hdr_t header;
	byte                   body[MAX_DATA_MESSAGE_BODY_SIZE];
} long_data_packet_padded_t;

#pragma pack(pop)

byte MessageFlags(packet_t *packet);
int ControlMessageType(packet_t *packet);
int IsControlMessage(packet_t *packet);
int IsInitializationMessage(packet_t *packet);
int IsVerificationMessage(packet_t *packet);
int IsHelloAndTestMessage(packet_t *packet);
int IsLevel1RoutingMessage(packet_t *packet);
int IsLevel2RoutingMessage(packet_t *packet);
int IsEthernetRouterHelloMessage(packet_t *packet);
int IsEthernetEndNodeHelloMessage(packet_t *packet);
int IsDataMessage(packet_t *packet);
int GetMessageBody(packet_t *packet);
int GetRouterLevel(int iinfo);

packet_t *CreateEthernetHello(decnet_address_t address);
packet_t *CreateLevel1RoutingMessage(int from, int count);
packet_t *CreateLevel2RoutingMessage(void);
packet_t *CreateLongDataMessage(decnet_address_t *srcNode, decnet_address_t *dstNode, byte flags, int visits, byte *data, int dataLength);

int IsValidRouterHelloMessage(packet_t *packet);
int IsValidEndnodeHelloMessage(packet_t *packet);
void ExtractRoutingInfo(uint16 routingInfo, int *hops, int *cost);
routing_msg_t *ParseRoutingMessage(packet_t *packet);
void FreeRoutingMessage(routing_msg_t *msg);
int IsValidDataPacket(packet_t *packet);
int IsReturnToSender(byte flags);
int IsReturnToSenderRequest(byte flags);
void SetIntraEthernet(packet_t *packet);
void ClearIntraEthernet(packet_t *packet);
void ExtractDataPacketData(packet_t *packet, decnet_address_t *srcNode, decnet_address_t *dstNode, byte *flags, int *visits, byte **data, int *dataLength);
packet_t *CreateLongDataMessage(decnet_address_t *srcNode, decnet_address_t *dstNode, byte flags, int visits, byte *data, int dataLength);

#define MESSAGES_H
#endif
