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

static byte NspMessageFlags(byte *nspPayload)
{
	return *nspPayload;
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


nsp_header_t *ParseNspHeader(byte *nspPayload, int nspPayloadLength)
{
	nsp_header_t *header = (nsp_header_t *)nspPayload;
	header->srcAddr = LittleEndianBytesToUint16((byte *)&header->srcAddr);
	header->dstAddr = LittleEndianBytesToUint16((byte *)&header->dstAddr);

	return header;
}

nsp_connect_initiate_t *ParseConnectInitiate(byte *nspPayload, int nspPayloadLength)
{
	nsp_connect_initiate_t *payload = (nsp_connect_initiate_t *)nspPayload;
	payload->segSize = LittleEndianBytesToUint16((byte *)&payload->segSize);
	payload->dataCtlLength = nspPayloadLength - sizeof(nsp_connect_initiate_t) + sizeof(payload->dataCtl);
	if (payload->dataCtlLength > sizeof(payload->dataCtl))
	{
		Log(LogNspMessages, LogWarning, "Connect Initiate data truncated, max length is %d, received %d\n", sizeof(payload->dataCtl), payload->dataCtlLength);
		payload->dataCtlLength = sizeof(payload->dataCtl);
	}

	return payload;
}

nsp_disconnect_initiate_t* ParseDisconnectInitiate(byte* nspPayload, int nspPayloadLength)
{
	nsp_disconnect_initiate_t* payload = (nsp_disconnect_initiate_t*)nspPayload;
	payload->reason = LittleEndianBytesToUint16((byte*)&payload->reason);

	return payload;
}

nsp_disconnect_confirm_t* ParseDisconnectConfirm(byte* nspPayload, int nspPayloadLength)
{
	nsp_disconnect_confirm_t* payload = (nsp_disconnect_confirm_t*)nspPayload;
	payload->reason = LittleEndianBytesToUint16((byte*)&payload->reason);

	return payload;
}

nsp_data_acknowledgement_t *ParseDataAcknowledgement(byte *nspPayload, int nspPayloadLength)
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
	payload.msgFlg = 0x28;
	payload.srcAddr = Uint16ToLittleEndian(srcAddr);
	payload.dstAddr = Uint16ToLittleEndian(dstAddr);
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

	payload.msgFlg = 0x38;
	payload.srcAddr = Uint16ToLittleEndian(srcAddr);
	payload.dstAddr = Uint16ToLittleEndian(dstAddr);
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
	payload.msgFlg = 0x48;
	payload.srcAddr = Uint16ToLittleEndian(srcAddr);
	payload.dstAddr = Uint16ToLittleEndian(dstAddr);
	payload.reason = Uint16ToLittleEndian(reason);
	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte *)&payload, sizeof(payload));

	return ans;
}

packet_t *NspCreateOtherDataAcknowledgement(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 number)
{
	packet_t *ans;
	nsp_data_acknowledgement_t payload;
	payload.msgFlg = 0x14;
	payload.srcAddr = Uint16ToLittleEndian(srcAddr);
	payload.dstAddr = Uint16ToLittleEndian(dstAddr);
	payload.ackNum = Uint16ToLittleEndian(0x8000 | isAck ? 0 : 0x1000 | (number & 0x0FFF));
	payload.ackDatOth = Uint16ToLittleEndian(0);
	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte *)&payload, sizeof(payload));

	return ans;
}

packet_t *NspCreateDataMessage(decnet_address_t *toAddress, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte *data, int dataLength)
{
	packet_t *ans;
	nsp_data_segment_t payload;
	payload.msgFlg = 0x60;
	payload.srcAddr = Uint16ToLittleEndian(srcAddr);
	payload.dstAddr = Uint16ToLittleEndian(dstAddr);
	payload.ackNum = Uint16ToLittleEndian(0x8001);
	payload.segNum  = Uint16ToLittleEndian(seqNo);
	memcpy(payload.data, data, dataLength);
	ans = CreateLongDataMessage(&nodeInfo.address, toAddress, 6, 0, (byte *)&payload, sizeof(payload) - sizeof(payload.data) + dataLength);

	return ans;
}