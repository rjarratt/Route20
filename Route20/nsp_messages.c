/* nsp_messages.c: NSP messages
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
#include "basictypes.h"
#include "packet.h"
#include "messages.h"
#include "nsp.h"
#include "nsp_messages.h"

static byte NspMessageFlags(byte *nspPayload);
static AckType ParseAckNum(uint16 value, uint16* ackNum);
static AckType ParseAckOth(uint16 value, uint16* ackOth);

static byte NspMessageFlags(byte *nspPayload)
{
	return *nspPayload;
}

static AckType ParseAckNum(uint16 value, uint16* ackNum)
{
	AckType result = NoAck;
	byte qual = (value >> 12) & 7;
	if (value & 0x8000 && (qual == 0 || qual == 1))
	{
		*ackNum = value & 0xFFF;
		result = (qual == 0) ? Ack : Nak;
	}

	return result;
}

static AckType ParseAckOth(uint16 value, uint16* ackOth)
{
	AckType result = NoAck;
	byte qual = (value >> 12) & 7;
	if (value & 0x8000 && (qual == 2 || qual == 3))
	{
		*ackOth = value & 0xFFF;
		result = (qual == 2) ? Ack : Nak;
	}

	return result;
}

int IsNspDataMessage(byte *nspPayload)
{
	return (NspMessageFlags(nspPayload) & 0x9F) == 0;
}

int IsConnectInitiateMessage(byte *nspPayload)
{
	return NspMessageFlags(nspPayload) == 0x18;
}

int IsRetransmittedConnectInitiateMessage(byte *nspPayload)
{
	return NspMessageFlags(nspPayload) == 0x68;
}

int IsDisconnectInitiateMessage(byte *nspPayload)
{
	return NspMessageFlags(nspPayload) == 0x38;
}

int IsDisconnectConfirmMessage(byte *nspPayload)
{
	return NspMessageFlags(nspPayload) == 0x48;
}

int IsDataAcknowledgementMessage(byte *nspPayload)
{
	return NspMessageFlags(nspPayload) == 0x04;
}


int IsInterruptMessage(byte *nspPayload)
{
	return NspMessageFlags(nspPayload) == 0x30;
}


int IsLinkServiceMessage(byte *nspPayload)
{
	return NspMessageFlags(nspPayload) == 0x10;
}


int IsOtherDataAcknowledgementMessage(byte *nspPayload)
{
	return NspMessageFlags(nspPayload) == 0x14;
}

int IsNoOperationMessage(byte *nspPayload)
{
	return NspMessageFlags(nspPayload) == 0x08;
}

int IsDisconnectCompleteMessage(nsp_disconnect_confirm_t* disconnectConfirm)
{
	return disconnectConfirm->reason == REASON_DISCONNECT_COMPLETE;
}

int IsDisconnectNoResourcesMessage(nsp_disconnect_confirm_t* disconnectConfirm)
{
	return disconnectConfirm->reason == REASON_NO_RESOURCES;
}

int IsDisconnectNoLinkMessage(nsp_disconnect_confirm_t* disconnectConfirm)
{
	return disconnectConfirm->reason == REASON_NO_LINK_TERMINATE;
}

int IsDisconnectDisconnectConfirmMessage(nsp_disconnect_confirm_t* disconnectConfirm)
{
	return disconnectConfirm->reason != REASON_DISCONNECT_COMPLETE && disconnectConfirm->reason != REASON_NO_RESOURCES && disconnectConfirm->reason != REASON_NO_LINK_TERMINATE;
}


nsp_header_t *ParseNspHeader(byte *nspPayload, uint16 nspPayloadLength)
{
	nsp_header_t *header = (nsp_header_t *)nspPayload;
	header->srcAddr = LittleEndianBytesToUint16((byte *)&header->srcAddr);
	header->dstAddr = LittleEndianBytesToUint16((byte *)&header->dstAddr);

	return header;
}

nsp_connect_initiate_t *ParseConnectInitiate(byte *nspPayload, uint16 nspPayloadLength)
{
	nsp_connect_initiate_t *payload = (nsp_connect_initiate_t *)nspPayload;
	payload->segSize = LittleEndianBytesToUint16((byte *)&payload->segSize);
	payload->dataCtlLength = (byte)(nspPayloadLength - sizeof(nsp_connect_initiate_t) + sizeof(payload->dataCtl));
	if (payload->dataCtlLength > sizeof(payload->dataCtl))
	{
		Log(LogNspMessages, LogWarning, "Connect Initiate data truncated, max length is %d, received %d\n", sizeof(payload->dataCtl), payload->dataCtlLength);
		payload->dataCtlLength = sizeof(payload->dataCtl);
	}

	return payload;
}

nsp_disconnect_initiate_t* ParseDisconnectInitiate(byte* nspPayload, uint16 nspPayloadLength)
{
	nsp_disconnect_initiate_t* payload = (nsp_disconnect_initiate_t*)nspPayload;
	payload->reason = LittleEndianBytesToUint16((byte*)&payload->reason);

	return payload;
}

nsp_disconnect_confirm_t* ParseDisconnectConfirm(byte* nspPayload, uint16 nspPayloadLength)
{
	nsp_disconnect_confirm_t* payload = (nsp_disconnect_confirm_t*)nspPayload;
	payload->reason = LittleEndianBytesToUint16((byte*)&payload->reason);

	return payload;
}

nsp_data_segment_t* ParseDataSegment(byte* nspPayload, uint16 nspPayloadLength)
{
    // TODO: Implement a proper buffer pool, particularly for out of order messages
	static nsp_data_segment_t payload;
	uint16 nextValue;
	byte* ptr = nspPayload + sizeof(payload.header);
	memcpy(&payload, nspPayload, sizeof(payload.header));

	nextValue = LittleEndianBytesToUint16(ptr);
	ptr += sizeof(uint16);
	payload.ackNumType = ParseAckNum(nextValue, &payload.ackNum);
	if (payload.ackNumType != NoAck)
	{
		nextValue = LittleEndianBytesToUint16(ptr);
		ptr += sizeof(uint16);
	}

	payload.ackOthType = ParseAckNum(nextValue, &payload.ackOth);
	if (payload.ackOthType != NoAck)
	{
		nextValue = LittleEndianBytesToUint16(ptr);
		ptr += sizeof(uint16);
	}

	payload.segNum = nextValue;
	payload.dataLength = (uint16)(nspPayloadLength - (ptr - nspPayload));
	memcpy(payload.data, ptr, payload.dataLength);

	return &payload;
}


nsp_link_service_t* ParseLinkService(byte* nspPayload, uint16 nspPayloadLength)
{
	static nsp_link_service_t payload;
	uint16 nextValue;
	byte* ptr = nspPayload + sizeof(payload.header);
	memcpy(&payload, nspPayload, sizeof(payload.header));

	nextValue = LittleEndianBytesToUint16(ptr);
	ptr += sizeof(uint16);
	payload.ackNumType = ParseAckNum(nextValue, &payload.ackNum);
	if (payload.ackNum != NoAck)
	{
		nextValue = LittleEndianBytesToUint16(ptr);
		ptr += sizeof(uint16);
	}

	payload.ackDatType = ParseAckNum(nextValue, &payload.ackDat);
	if (payload.ackDat != NoAck)
	{
		nextValue = LittleEndianBytesToUint16(ptr);
		ptr += sizeof(uint16);
	}

	payload.segNum = nextValue;
	payload.lsFlags = *ptr++;
	payload.fcVal = (*ptr++) & 0xF;

	return &payload;
}
nsp_data_acknowledgement_t *ParseDataAcknowledgement(byte *nspPayload, uint16 nspPayloadLength)
{
	nsp_data_acknowledgement_t * payload = (nsp_data_acknowledgement_t *)nspPayload;
	payload->ackNum = LittleEndianBytesToUint16((byte *)&payload->ackNum);
	payload->ackDatOth = LittleEndianBytesToUint16((byte *)&payload->ackDatOth);

	return payload;
}

packet_t *NspCreateConnectAcknowledgement(decnet_address_t *toAddress, uint16 dstAddr)
{
	packet_t *ans;
	nsp_connect_acknowledgement_t payload;
	payload.msgFlg = 0x24;
	payload.dstAddr = Uint16ToLittleEndian(dstAddr);
	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte *)&payload, sizeof(payload));

	return ans;
}

packet_t *NspCreateConnectConfirm(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, byte services, byte info, uint16 segSize, byte dataLen, byte* data)
{
	packet_t *ans;
	nsp_connect_confirm_t payload;
	payload.header.msgFlg = 0x28;
	payload.header.srcAddr = Uint16ToLittleEndian(srcAddr);
	payload.header.dstAddr = Uint16ToLittleEndian(dstAddr);
	payload.services = services;
	payload.info = info;
	payload.segSize = Uint16ToLittleEndian(segSize);
	payload.dataCtl[0] = dataLen;
	memcpy(&payload.dataCtl[1], data, dataLen);
	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte *)&payload, sizeof(payload) - (sizeof(payload.dataCtl)-1-dataLen));

	return ans;
}

packet_t *NspCreateDisconnectInitiate(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, uint16 reason, byte dataLen, byte* data)
{
	packet_t *ans;
	nsp_disconnect_initiate_t payload;

	payload.header.msgFlg = 0x38;
	payload.header.srcAddr = Uint16ToLittleEndian(srcAddr);
	payload.header.dstAddr = Uint16ToLittleEndian(dstAddr);
	payload.reason = Uint16ToLittleEndian(reason);
	payload.dataCtl[0] = dataLen;
	memcpy(&payload.dataCtl[1], data, dataLen);
	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte *)&payload, sizeof(payload) - (sizeof(payload.dataCtl) - 1 - dataLen));

	return ans;
}

packet_t *NspCreateDisconnectConfirm(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, uint16 reason)
{
	packet_t *ans;
	nsp_disconnect_confirm_t payload;
	payload.header.msgFlg = 0x48;
	payload.header.srcAddr = Uint16ToLittleEndian(srcAddr);
	payload.header.dstAddr = Uint16ToLittleEndian(dstAddr);
	payload.reason = Uint16ToLittleEndian(reason);
	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte *)&payload, sizeof(payload));

	return ans;
}

packet_t *NspCreateDataAcknowledgement(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 ackNumber)
{
	packet_t *ans;
	nsp_data_acknowledgement_t payload;
	payload.header.msgFlg = 0x04;
	payload.header.srcAddr = Uint16ToLittleEndian(srcAddr);
	payload.header.dstAddr = Uint16ToLittleEndian(dstAddr);
	payload.ackNum = Uint16ToLittleEndian(0x8000 | (isAck ? 0 : 0x1000) | (ackNumber & 0x0FFF));
	payload.ackDatOth = Uint16ToLittleEndian(0x0000);
	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte *)&payload, sizeof(payload) - sizeof(payload.ackDatOth));

	return ans;
}

packet_t* NspCreateOtherDataAcknowledgement(decnet_address_t* toAddress, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 number)
{
	packet_t* ans;
	nsp_data_acknowledgement_t payload;
	payload.header.msgFlg = 0x14;
	payload.header.srcAddr = Uint16ToLittleEndian(srcAddr);
	payload.header.dstAddr = Uint16ToLittleEndian(dstAddr);
	payload.ackNum = Uint16ToLittleEndian(0x8000 | (isAck ? 0 : 0x1000) | (number & 0x0FFF));
	payload.ackDatOth = Uint16ToLittleEndian(0);
	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte*)&payload, sizeof(payload));

	return ans;
}

packet_t *NspCreateDataMessage(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte *data, uint16 dataLength)
{
	packet_t *ans;
	nsp_data_segment_t dataSegment;
	byte payload[sizeof(nsp_data_segment_t)];
	byte* ptr = payload;

	dataSegment.header.msgFlg = 0x60;
	dataSegment.header.srcAddr = Uint16ToLittleEndian(srcAddr);
	dataSegment.header.dstAddr = Uint16ToLittleEndian(dstAddr);
	dataSegment.ackNumType = NoAck;
	dataSegment.ackOthType = NoAck;
	dataSegment.segNum  = Uint16ToLittleEndian(seqNo & 0xFFF);

	memcpy(ptr, &dataSegment, sizeof(nsp_header_t));
	ptr += sizeof(nsp_header_t);
	memcpy(ptr, &dataSegment.segNum, sizeof(dataSegment.segNum));
	ptr += sizeof(dataSegment.segNum);
	memcpy(ptr, data, dataLength);

	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte *)&payload, sizeof(nsp_header_t) + sizeof(dataSegment.segNum) + dataLength);

	return ans;
}

packet_t *NspCreateLinkServiceMessage(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte lsFlags, byte fcVal)
{
	packet_t *ans;
	nsp_link_service_t linkService;
	byte payload[sizeof(nsp_data_segment_t)];
	byte *ptr = payload;

	linkService.header.msgFlg = 0x60;
	linkService.header.srcAddr = Uint16ToLittleEndian(srcAddr);
	linkService.header.dstAddr = Uint16ToLittleEndian(dstAddr);
	linkService.ackNumType = NoAck;
	linkService.ackDatType = NoAck;
	linkService.segNum = Uint16ToLittleEndian(seqNo & 0xFFF);
	linkService.lsFlags = lsFlags;
	linkService.fcVal = fcVal;

	memcpy(ptr, &linkService, sizeof(nsp_header_t));
	ptr += sizeof(nsp_header_t);
	memcpy(ptr, &linkService.segNum, sizeof(linkService.segNum));
	ptr += sizeof(linkService.segNum);
	*ptr++ = lsFlags;
	*ptr++ = fcVal;

	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte *)&payload, sizeof(nsp_header_t) + sizeof(linkService.segNum) + sizeof(linkService.lsFlags) + sizeof(linkService.fcVal));

	return ans;
}
