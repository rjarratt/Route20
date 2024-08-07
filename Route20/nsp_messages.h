/* nsp_messages.h: NSP messages
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
#include "packet.h"

#if !defined(NSP_MESSAGES_H)

#pragma pack(push)
#pragma pack(1)

typedef enum
{
	NoAck,
	Ack,
	Nak
} AckType;

typedef struct
{
	byte   msgFlg;
	uint16 dstAddr;
	uint16 srcAddr;
} nsp_header_t;

typedef struct
{
	nsp_header_t header;
	byte         services;
	byte         info;
	uint16       segSize;
	byte         dataCtl[64]; /* length is actually unknown */
	byte         dataCtlLength; /* not part of the wire format */
} nsp_connect_initiate_t;

typedef struct
{
	byte   msgFlg;
	uint16 dstAddr;
} nsp_connect_acknowledgement_t;


typedef struct
{
	nsp_header_t header;
	byte         services;
	byte         info;
	uint16       segSize;
	byte         dataCtl[17]; /* I-16 field, so up to 17 bytes including the length byte */
} nsp_connect_confirm_t;

typedef struct
{
	nsp_header_t header;
	uint16       reason;
	byte         dataCtl[17];
} nsp_disconnect_initiate_t;

typedef struct
{
	nsp_header_t header;
	uint16       reason;
} nsp_disconnect_confirm_t;

typedef struct
{
	nsp_header_t header;
	uint16       ackNum;
	uint16       ackDatOth; /* depending on which data ack it is ackdat or ackoth */
} nsp_data_acknowledgement_t;

typedef struct
{
	nsp_header_t header;
	AckType      ackNumType;
	uint16       ackNum;
	uint16       ackDat;
	AckType      ackDatType;
	uint16       segNum;
	byte         lsFlags;
	byte         fcVal;
} nsp_link_service_t;

typedef struct
{
	nsp_header_t header;
	AckType      ackNumType;
	uint16       ackNum;
	uint16       ackOth;
	AckType      ackOthType;
	uint16       segNum;
	uint16       dataLength;
	byte         data[4096];
} nsp_data_segment_t;

#pragma pack(pop)

int IsNspDataMessage(byte *nspPayload);

int IsConnectInitiateMessage(byte *nspPayload);
int IsRetransmittedConnectInitiateMessage(byte *nspPayload);
int IsDisconnectInitiateMessage(byte *nspPayload);
int IsDisconnectConfirmMessage(byte *nspPayload);
int IsDataAcknowledgementMessage(byte *nspPayload);
int IsInterruptMessage(byte *nspPayload);
int IsLinkServiceMessage(byte *nspPayload);
int IsOtherDataAcknowledgementMessage(byte *nspPayload);
int IsNoOperationMessage(byte *nspPayload);
int IsDisconnectCompleteMessage(nsp_disconnect_confirm_t* disconnectConfirm);
int IsDisconnectNoResourcesMessage(nsp_disconnect_confirm_t* disconnectConfirm);
int IsDisconnectNoLinkMessage(nsp_disconnect_confirm_t* disconnectConfirm);
int IsDisconnectDisconnectConfirmMessage(nsp_disconnect_confirm_t* disconnectConfirm);

nsp_header_t *ParseNspHeader(byte *nspPayload, uint16 nspPayloadLength);
nsp_connect_initiate_t *ParseConnectInitiate(byte *nspPayload, uint16 nspPayloadLength);
nsp_disconnect_initiate_t *ParseDisconnectInitiate(byte *nspPayload, uint16 nspPayloadLength);
nsp_disconnect_confirm_t* ParseDisconnectConfirm(byte* nspPayload, uint16 nspPayloadLength);
nsp_data_segment_t* ParseDataSegment(byte* nspPayload, uint16 nspPayloadLength);
nsp_link_service_t* ParseLinkService(byte* nspPayload, uint16 nspPayloadLength);
nsp_data_acknowledgement_t* ParseDataAcknowledgement(byte* nspPayload, uint16 nspPayloadLength);

packet_t *NspCreateConnectAcknowledgement(decnet_address_t *toAddress, uint16 dstAddr);
packet_t *NspCreateConnectConfirm(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, byte services, byte info, uint16 segSize, byte dataLen, byte *data);
packet_t *NspCreateDisconnectInitiate(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, uint16 reason, byte dataLen, byte* data);
packet_t *NspCreateDisconnectConfirm(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, uint16 reason);
packet_t *NspCreateDataAcknowledgement(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 ackNumber);
packet_t *NspCreateOtherDataAcknowledgement(decnet_address_t* toAddress, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 number);
packet_t *NspCreateDataMessage(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte *data, uint16 dataLength);
packet_t *NspCreateLinkServiceMessage(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte lsFlags, byte fcVal);


//int IsValidRouterHelloMessage(packet_t *packet);

#define NSP_MESSAGES_H
#endif
