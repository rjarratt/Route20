/* nsp.c: NSP support
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
#include "platform.h"
#include "nsp.h"
#include "messages.h"
#include "nsp_messages.h"
#include "nsp_session_control_port_database.h"
#include "route20.h"
#include "forwarding.h" // TODO: remove when do proper layering

// TODO: On demand NspOpen?

#define INFO_V40 2

typedef struct
{
	decnet_address_t *node;
	uint16            locAddr;
	uint16            remAddr;
} PortSearchContext;

static void ProcessLinkActivity(decnet_address_t *from, nsp_header_t *);
static void ProcessLinkConnectionCompletionMessage(decnet_address_t *from, nsp_header_t *);
static void ProcessConnectInitiateMessage(decnet_address_t *from, nsp_connect_initiate_t *connectInitiate);
static void ProcessDisconnectInitiateMessage(decnet_address_t* from, nsp_disconnect_initiate_t* disconnectInitiate);
static void ProcessDisconnectConfirmMessage(decnet_address_t* from, nsp_disconnect_confirm_t* disconnectConfirm);
static void ProcessDataAcknowledgementMessage(decnet_address_t *from, nsp_data_acknowledgement_t *dataAcknowledgement);
static void ProcessDataSegmentMessage(decnet_address_t* from, nsp_header_t* header, nsp_data_segment_t* dataSegment);
static void ProcessLinkServiceMessage(decnet_address_t* from, nsp_link_service_t* linkService);

static void TransmitQueuedMessages(session_control_port_t *port);
static void HandleInactivityTimer(rtimer_t *timer, char *name, void *context);

static void ProcessDataAck(session_control_port_t* port, AckType ackNumType, uint16 ackNum);

static void SendConnectAcknowledgement(decnet_address_t *to, uint16 dstAddr); 
static void SendDisconnectInitiate(decnet_address_t* to, uint16 srcAddr, uint16 dstAddr, uint16 reason, byte dataLen, byte* data);
static void SendDisconnectConfirm(decnet_address_t* to, uint16 srcAddr, uint16 dstAddr, uint16 reason);
static void SendConnectConfirm(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, byte services, byte dataLen, byte* data);
static void SendDataAcknowledgement(decnet_address_t* to, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 number);
static void SendOtherDataAcknowledgement(decnet_address_t* to, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 number);
static void SendDataSegment(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte *data, int dataLength);
static void SendLinkService(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte lsFlags, byte fcVal);

static session_control_port_t *FindScpEntryForRemoteNodeConnection(decnet_address_t *node, uint16 locAddr, uint16 remAddr);
static int ScpEntryMatchesRemoteNodeConnection(session_control_port_t *entry, void *context);
static session_control_port_t *FindScpEntryForRemoteNode(decnet_address_t *node, uint16 remAddr);
static int ScpEntryMatchesRemoteNode(session_control_port_t *entry, void *context);
static void SetPortState(session_control_port_t *port, NspPortState newState);

static void LogMessage(decnet_address_t *from, void *message);
static void LogState(LogSource source, LogLevel level, NspPortState state);

static uint16 lastPort;

void NspInitialise(void)
{
	NspInitialiseScpDatabase();
	RoutingSetCallback(NspProcessPacket);
}

void NspInitialiseConfig(void)
{
	NspConfig.NSPInactTim = 30;
}

int NspOpen(void (*closeCallback)(uint16 srcAddr), void (*connectCallback)(decnet_address_t* remNode, uint16 locAddr, uint16 remAddr, byte* data, byte dataLength), void (*dataCallback)(uint16 locAddr, byte *data, uint16 dataLength))
{
	int ans = 0;
	session_control_port_t *port = NspFindFreeScpDatabaseEntry();
	if (port != NULL)
	{
		lastPort++;
		memset(port, 0, sizeof(*port));
		port->addrLoc = lastPort; // TODO: care with wrap around, 0 not allowed?
		SetPortState(port, NspPortStateOpen);
		InitialiseTransmitQueue(&port->transmit_queue);
		port->closeCallback = closeCallback;
		port->connectCallback = connectCallback;
		port->dataCallback = dataCallback;
		ans = port->addrLoc;
	}

	return ans;
}

void NspClose(uint16 locAddr)
{
	session_control_port_t* port = NspFindScpDatabaseEntryByLocalAddress(locAddr);

	if (port != NULL)
	{
		Log(LogNsp, LogInfo, "Closed NSP connection from ");
		LogDecnetAddress(LogNsp, LogInfo, &port->node);
		Log(LogNsp, LogInfo, " on port %d\n", port->addrLoc);

		SetPortState(port, NspPortStateClosed);
		port->addrRem = 0;
		memset(&port->node, 0, sizeof(port->node));
		TerminateTransmitQueue(&port->transmit_queue);

		if (port->inactivityTimer != NULL)
		{
			StopTimer(port->inactivityTimer);
		}
	}
}

int NspAccept(uint16 srcAddr, byte services, byte dataLen, byte* data)
{
	int ans = 0;
	session_control_port_t *port;

	port = NspFindScpDatabaseEntryByLocalAddress(srcAddr);
	if (port != NULL)
	{
		if (port->state == NspPortStateConnectReceived)
		{
			ans = 1;
		    SetPortState(port, NspPortStateConnectConfirm);
			SendConnectConfirm(&port->node, port->addrLoc, port->addrRem, services, dataLen, data);
			Log(LogNsp, LogInfo, "Opened NSP connection from ");
			LogDecnetAddress(LogNsp, LogInfo, &port->node);
			Log(LogNsp, LogInfo, " on port %hu\n", port->addrLoc);
		}
	}

	return ans;
}

int NspReject(decnet_address_t* dstNode, uint16 srcAddr, uint16 dstAddr, uint16 reason, byte dataLen, byte* data)
{
	int ans = 0;
	session_control_port_t* port;

	port = FindScpEntryForRemoteNode(dstNode, dstAddr);
	if (port != NULL)
	{
		if (port->state == NspPortStateConnectReceived)
		{
			ans = 1;
			SetPortState(port, NspPortStateDisconnectReject);
			SendDisconnectInitiate(&port->node, port->addrLoc, port->addrRem, reason, dataLen, data);
			Log(LogNsp, LogInfo, "Rejected NSP connection from ");
			LogDecnetAddress(LogNsp, LogInfo, &port->node);
			Log(LogNsp, LogInfo, " on port %hu, reason=%hu\n", port->addrLoc, reason);
		}
	}

	return ans;
}

void NspTransmit(uint16 srcAddr, byte *data, int dataLength)
{
	session_control_port_t *port;

	port = NspFindScpDatabaseEntryByLocalAddress(srcAddr);
	if (port != NULL)
	{
		port->numSent++;
		EnqueueToTransmitQueue(&port->transmit_queue, port->numSent, data, dataLength);
        TransmitQueuedMessages(port);
	}
}

void NspProcessPacket(decnet_address_t *from, byte *data, int dataLength)
{
	// TODO: validate NSP messages, see latter half of section 6.2
	// TODO: process "return to sender" messages, NSP spec p79

	nsp_header_t *header = ParseNspHeader(data, dataLength);

	// TODO: Make logging better so that all message details are logged in one place
	LogMessage(from, header);

	ProcessLinkActivity(from, header);
	ProcessLinkConnectionCompletionMessage(from, header);

	if (IsConnectInitiateMessage(data) || IsRetransmittedConnectInitiateMessage(data))
	{
		ProcessConnectInitiateMessage(from, ParseConnectInitiate(data, dataLength));
	}
	else if (IsDisconnectInitiateMessage(data))
	{
		ProcessDisconnectInitiateMessage(from, ParseDisconnectInitiate(data, dataLength));
	}
	else if (IsDisconnectConfirmMessage(data))
	{
		ProcessDisconnectConfirmMessage(from, ParseDisconnectConfirm(data, dataLength));
	}
	else if (IsNspDataMessage(data))
	{
		ProcessDataSegmentMessage(from, header, ParseDataSegment(data, dataLength));
	}
	else if (IsLinkServiceMessage(data))
	{
		// TODO: Actually process the Link Service Message (8.3.3)
		ProcessLinkServiceMessage(from, ParseLinkService(data, dataLength));
	}
	else if (IsDataAcknowledgementMessage(data))
	{
		ProcessDataAcknowledgementMessage(from, ParseDataAcknowledgement(data, dataLength));
	}
	else if (IsNoOperationMessage(data))
	{
	}
	else
	{
		// TODO: Interrupt Message
		// TODO: All other messages.
		Log(LogNsp, LogWarning, "Discarding unrecognised NSP message, msgflg=%02X\n", data[0]);
//
//		// Data Acknowledgement, Interrupt, Link Service, Other Data Ack && CC Set to RUN
//		// 117 msgflg layout lINK SERVICE, iNTERRUPT, Data Ack, Other-dATAT-ACK
//		packet_t *initiatePacket;
//		session_control_port_t *port;
//
//		port = FindScpEntryForRemoteNode(from, header->srcAddr);
//		initiatePacket = NspCreateDisconnectInitiate(from, lastPort, port->addrRem, 99);
////		SendPacket(from, initiatePacket);
	}
}

static void ProcessLinkActivity(decnet_address_t *from, nsp_header_t *header)
{

		session_control_port_t *port;

		port = FindScpEntryForRemoteNode(from, header->srcAddr);
		if (port != NULL)
		{
			if (port->inactivityTimer != NULL)
			{
				ResetTimer(port->inactivityTimer);
			}
		}
}

static void ProcessLinkConnectionCompletionMessage(decnet_address_t *from, nsp_header_t *header)
{
	time_t now;

	if (IsDataAcknowledgementMessage((byte *)header) || IsInterruptMessage((byte *)header) || IsLinkServiceMessage((byte *)header) || IsOtherDataAcknowledgementMessage((byte *)header))
	{
		session_control_port_t *port;

		port = FindScpEntryForRemoteNode(from, header->srcAddr);
		if (port != NULL)
		{
			if (port->state == NspPortStateConnectConfirm)
			{
				SetPortState(port, NspPortStateRunning);
				time(&now);
				port->inactivityTimer = CreateTimer("NSP Inactivity Timer", now + NspConfig.NSPInactTim, 0, port, HandleInactivityTimer);
			}
		}
	}
}

static void ProcessConnectInitiateMessage(decnet_address_t *from, nsp_connect_initiate_t *connectInitiate)
{
	/* Section 6.2 of NSP spec 

	   Bullet 4 not implemented, where ConnectInitiate has been returned, because the router does not initiate connections */

	//Log(LogNsp, LogVerbose, "Connect Initiate data is ");
	//LogBytes(LogNsp, LogVerbose, connectInitiate->dataCtl, connectInitiate->dataCtlLength);
	//Log(LogNsp, LogVerbose, "\n");

	if (connectInitiate->header.dstAddr == 0)
	{
		session_control_port_t *port;
		port = FindScpEntryForRemoteNode(from, connectInitiate->header.srcAddr);
		if (port == NULL)
		{
			port = NspFindOpenScpDatabaseEntry();
		}

		if (port != NULL)
		{
			switch (port->state)
			{
				case NspPortStateOpen:
				{
					port->addrRem = connectInitiate->header.srcAddr;
					memcpy(&port->node, from, sizeof(decnet_address_t));
					SetPortState(port, NspPortStateConnectReceived);
					SendConnectAcknowledgement(from, connectInitiate->header.srcAddr);
					break;
				}
				case NspPortStateConnectReceived:
				case NspPortStateConnectConfirm:
				case NspPortStateDisconnectReject:
				{
					SendConnectAcknowledgement(from, connectInitiate->header.srcAddr);
					break;
				}
				default:
				{
					break;
				}
			}

			port->connectCallback(from, port->addrLoc, port->addrRem, connectInitiate->dataCtl, connectInitiate->dataCtlLength);
		}
		else
		{
			SendDisconnectConfirm(from, connectInitiate->header.dstAddr, connectInitiate->header.srcAddr, REASON_NO_RESOURCES);
		}
	}

}

static void ProcessDisconnectInitiateMessage(decnet_address_t *from, nsp_disconnect_initiate_t *disconnectInitiate)
{
	session_control_port_t *port;

	port = FindScpEntryForRemoteNodeConnection(from, disconnectInitiate->header.dstAddr, disconnectInitiate->header.srcAddr);
	if (port != NULL)
	{
		switch (port->state)
		{
		case NspPortStateConnectInitiate:
		case NspPortStateConnectDelivered:
			{
				SendDisconnectConfirm(from, disconnectInitiate->header.dstAddr, disconnectInitiate->header.srcAddr, disconnectInitiate->reason);
			    SetPortState(port, NspPortStateRejected);
				break;
			}
		case NspPortStateRejected:
			{
				SendDisconnectConfirm(from, disconnectInitiate->header.dstAddr, disconnectInitiate->header.srcAddr, disconnectInitiate->reason);
				break;
			}
		case NspPortStateRunning:
			{
				SendDisconnectConfirm(from, disconnectInitiate->header.dstAddr, disconnectInitiate->header.srcAddr, disconnectInitiate->reason);
			    SetPortState(port, NspPortStateDisconnectNotification);
				break;
			}
		case NspPortStateDisconnectInitiate:
		case NspPortStateDisconnectComplete:
			{
				SendDisconnectConfirm(from, disconnectInitiate->header.dstAddr, disconnectInitiate->header.srcAddr, disconnectInitiate->reason);
			    SetPortState(port, NspPortStateDisconnectComplete);
				break;
			}
		case NspPortStateDisconnectNotification:
			{
				SendDisconnectConfirm(from, disconnectInitiate->header.dstAddr, disconnectInitiate->header.srcAddr, disconnectInitiate->reason);
				break;
			}
        default:
            {
                break;
            }
		}

		port->closeCallback(port->addrLoc);
	}
}

static void ProcessDisconnectConfirmMessage(decnet_address_t* from, nsp_disconnect_confirm_t* disconnectConfirm)
{
	session_control_port_t* port;
	port = FindScpEntryForRemoteNodeConnection(from, disconnectConfirm->header.dstAddr, disconnectConfirm->header.srcAddr);

	if (port != NULL)
	{
		if (IsDisconnectNoResourcesMessage(disconnectConfirm))
		{
			switch (port->state)
			{
				case NspPortStateConnectInitiate:
				{
					SetPortState(port, NspPortStateNoResources);
					// TODO: Section 6.4.1 says we must do UPDATE-DELAY
					break;
				}
				default:
				{
					break;
				}
			}
		}
		else if (IsDisconnectCompleteMessage(disconnectConfirm))
		{
			// TODO: Section 6.4.1 says we should stop TIMERcon and others 
			switch (port->state)
			{
				case NspPortStateDisconnectReject:
				{
					SetPortState(port, NspPortStateDisconnectRejectComplete);
					break;
				}
				case NspPortStateDisconnectInitiate:
				{
					SetPortState(port, NspPortStateDisconnectComplete);
					break;
				}
				default:
				{
					break;
				}
			}
		}
		else if (IsDisconnectNoLinkMessage(disconnectConfirm))
		{
			switch (port->state)
			{
				case NspPortStateConnectConfirm:
				case NspPortStateRunning:
				case NspPortStateDisconnectReject:
				case NspPortStateDisconnectInitiate:
				{
					SetPortState(port, NspPortStateClosedNotification);
					break;
				}
				default:
				{
					break;
				}
			}
		}
		else if (IsDisconnectDisconnectConfirmMessage(disconnectConfirm))
		{
			switch (port->state)
			{
				case NspPortStateConnectInitiate:
				{
					SetPortState(port, NspPortStateRejected);
					// TODO: Section 6.4.1 says we must do UPDATE-DELAY
					break;
				}
				case NspPortStateConnectConfirm:
				case NspPortStateRunning:
				{
					SetPortState(port, NspPortStateClosedNotification);
					// TODO: Section 6.4.1 says we must do stop some timers
					break;
				}
				default:
				{
					break;
				}
			}
		}

		port->closeCallback(port->addrLoc);
	}
}

static void ProcessDataAcknowledgementMessage(decnet_address_t *from, nsp_data_acknowledgement_t *dataAcknowledgement)
{
	session_control_port_t *port;

	port = FindScpEntryForRemoteNode(from, dataAcknowledgement->header.srcAddr);
	if (port != NULL)
	{
		uint16 ackDataField;
		int isAck;
		uint16 ackNum;

		if (dataAcknowledgement->header.msgFlg == 4)
		{
			ackDataField = dataAcknowledgement->ackNum;
		}
		else
		{
			ackDataField = dataAcknowledgement->ackDatOth;
		}

		isAck = (ackDataField & 0x1000) == 0;
		ackNum = ackDataField & 0xFFF;
		if (isAck)
		{
			ProcessDataAck(port, Ack, ackNum);
		}
		else
		{
			// TODO: Implement NAK processing
            Log(LogNspMessages, LogError, "NAK of segment %d - NOT IMPLEMENTED\n", ackNum);
		}
	}
}

static void ProcessDataSegmentMessage(decnet_address_t *from, nsp_header_t *header, nsp_data_segment_t* dataSegment)
{
	session_control_port_t *port;

	// TODO: Missing check for state of connection
	port = FindScpEntryForRemoteNodeConnection(from, header->dstAddr, header->srcAddr);
	if (port != NULL)
	{
		if (dataSegment->ackNumType == Ack)
		{
			ProcessDataAck(port, dataSegment->ackNumType, dataSegment->ackNum);
		}

		// TODO: Keep actual record of segment numbers in the port details and process acks properly including the delayed ack
		SendDataAcknowledgement(from, port->addrLoc, port->addrRem, 1, dataSegment->segNum);
		// TODO: Must process BOM and EOM flags, see 8.3.1.
		port->dataCallback(port->addrLoc, dataSegment->data, dataSegment->dataLength);
	}
}

static void ProcessLinkServiceMessage(decnet_address_t* from, nsp_link_service_t* linkService)
{
	session_control_port_t* port;

	// TODO: Missing check for state of connection
	port = FindScpEntryForRemoteNodeConnection(from, linkService->header.dstAddr, linkService->header.srcAddr);
	if (port != NULL)
	{
		SendOtherDataAcknowledgement(from, port->addrLoc, port->addrRem, 1, linkService->segNum);
	}
}
static void TransmitQueuedMessages(session_control_port_t *port)
{
	// TODO: NAK and retransmit after timeout
	byte data[NSP_SEGMENT_SIZE];
	int dataLength;
	uint16 transmitSegmentNumber;

	while (DequeueFromTransmitQueue(&port->transmit_queue, port->flowRemDat + 1, &transmitSegmentNumber, data, sizeof(data), &dataLength))
	{
        SendDataSegment(&port->node, port->addrLoc, port->addrRem, transmitSegmentNumber, data, dataLength);
	}
}

static void HandleInactivityTimer(rtimer_t *timer, char *name, void *context)
{
	session_control_port_t *port = context;
	Log(LogNsp, LogWarning, "No activity detected on port for ");
	LogDecnetAddress(LogNsp, LogWarning, &port->node);
	Log(LogNsp, LogWarning, "\n");
	SendLinkService(&port->node, port->addrLoc, port->addrRem, port->numDat++, 0, 1);
}

static void ProcessDataAck(session_control_port_t* port, AckType ackNumType, uint16 ackNum)
{
	if (ackNumType == Ack)
	{
		Log(LogNspMessages, LogVerbose, "ACK of segment %hu\n", ackNum);
		port->flowRemDat = ackNum;
		TransmitQueuedMessages(port);
	}
}

static void SendConnectAcknowledgement(decnet_address_t *to, uint16 dstAddr)
{
	packet_t *ackPacket;
	Log(LogNspMessages, LogVerbose, "Sending ConnectAcknowledgement\n");
	ackPacket = NspCreateConnectAcknowledgement(to, dstAddr);
	SendPacket(NULL, to, ackPacket);
}

static void SendDisconnectInitiate(decnet_address_t* to, uint16 srcAddr, uint16 dstAddr, uint16 reason, byte dataLen, byte* data)
{
	packet_t* diPacket;
    Log(LogNspMessages, LogVerbose, "Sending DisconnectInitiate, reason=%d\n", reason);
	diPacket = NspCreateDisconnectInitiate(to, srcAddr, dstAddr, reason, dataLen, data);
	SendPacket(NULL, to, diPacket);
}

static void SendDisconnectConfirm(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, uint16 reason)
{
	packet_t *confirmPacket;

	if (reason == REASON_NO_RESOURCES)
	{
		Log(LogNspMessages, LogVerbose, "Sending NoResources\n");
	}
	else if (reason == REASON_DISCONNECT_COMPLETE)
	{
		Log(LogNspMessages, LogVerbose, "Sending DisconnectComplete\n");
	}
	else if (reason == REASON_NO_LINK_TERMINATE)
	{
		Log(LogNspMessages, LogVerbose, "Sending NoLink\n");
	}
	else
	{
		Log(LogNspMessages, LogVerbose, "Sending DisconnectConfirm\n");
	}

	confirmPacket = NspCreateDisconnectConfirm(to, srcAddr, dstAddr, reason);
	SendPacket(NULL, to, confirmPacket);
}

static void SendConnectConfirm(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, byte services, byte dataLen, byte *data)
{
	packet_t *confirmPacket;
	Log(LogNspMessages, LogVerbose, "Sending ConnectConfirm\n");
	confirmPacket = NspCreateConnectConfirm(to, srcAddr, dstAddr, services, INFO_V40, NSP_SEGMENT_SIZE, dataLen, data);
	SendPacket(NULL, to, confirmPacket);
}

static void SendDataAcknowledgement(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 number)
{
	packet_t *confirmPacket;
	// TODO: Drive this from port object, including other ack if needed
	Log(LogNspMessages, LogVerbose, "Sending DataAcknowledgement with %s of segment %d\n", (isAck)? "Ack": "Nak", number & 0xFFF);
	confirmPacket = NspCreateDataAcknowledgement(to, srcAddr, dstAddr, isAck, number);
	SendPacket(NULL, to, confirmPacket);
}

static void SendOtherDataAcknowledgement(decnet_address_t* to, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 number)
{
	packet_t* confirmPacket;
	// TODO: Drive this from port object, including other ack if needed
	Log(LogNspMessages, LogVerbose, "Sending OtherDataAcknowledgement with %s of segment %d\n", (isAck) ? "Ack" : "Nak", number & 0xFFF);
	confirmPacket = NspCreateOtherDataAcknowledgement(to, srcAddr, dstAddr, isAck, number);
	SendPacket(NULL, to, confirmPacket);
}

static void SendDataSegment(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte *data, int dataLength)
{
	packet_t *confirmPacket;
	Log(LogNspMessages, LogVerbose, "Sending DataSegment number %d\n", seqNo);
    confirmPacket = NspCreateDataMessage(to, srcAddr, dstAddr, seqNo, data, dataLength);
	SendPacket(NULL, to, confirmPacket);
}

static void SendLinkService(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte lsFlags, byte fcVal)
{
	packet_t *packet;
	Log(LogNspMessages, LogVerbose, "Sending LinkService number %d\n", seqNo);
	packet = NspCreateLinkServiceMessage(to, srcAddr, dstAddr, seqNo, lsFlags, fcVal);
	SendPacket(NULL, to, packet);
}

static session_control_port_t *FindScpEntryForRemoteNodeConnection(decnet_address_t *node, uint16 locAddr, uint16 remAddr)
{
	PortSearchContext cxt;
	cxt.node = node;
	cxt.locAddr = locAddr;
	cxt.remAddr = remAddr;
	return NspFindScpDatabaseEntry(ScpEntryMatchesRemoteNodeConnection, &cxt);
}

static int ScpEntryMatchesRemoteNodeConnection(session_control_port_t *entry, void *context)
{
	PortSearchContext *searchContext = (PortSearchContext *)context;
	return CompareDecnetAddress(&entry->node, searchContext->node) && entry->addrLoc == searchContext->locAddr && entry->addrRem == searchContext->remAddr;
}


static session_control_port_t *FindScpEntryForRemoteNode(decnet_address_t *node, uint16 remAddr)
{
	PortSearchContext cxt;
	cxt.node = node;
	cxt.remAddr = remAddr;
	return NspFindScpDatabaseEntry(ScpEntryMatchesRemoteNode, &cxt);
}

static int ScpEntryMatchesRemoteNode(session_control_port_t *entry, void *context)
{
	PortSearchContext *searchContext = (PortSearchContext *)context;
	return entry->state != NspPortStateOpen && CompareDecnetAddress(&entry->node, searchContext->node) && entry->addrRem == searchContext->remAddr;
}

static void SetPortState(session_control_port_t *port, NspPortState newState)
{
	port->state = newState;
	Log(LogNsp, LogVerbose, "Port %d is now ", port->addrLoc);
	LogState(LogNsp, LogVerbose, newState);
	Log(LogNsp, LogVerbose, "\n");
}

static void LogMessage(decnet_address_t *from, void *message)
{
	nsp_header_t *header = (nsp_header_t *)message;
	char *messageName;
	switch (header->msgFlg) // TODO: Centralise translation of message flags with an enum etc
	{
		case 0x00:
		case 0x20:
		case 0x40:
		case 0x60:
		{
			messageName = "Data Segment";
			break;
		}
		case 0x18:
		{
			messageName = "Connect Initiate";
			break;
		}
		case 0x68:
		{
			messageName = "Retransmitted Connect Initiate";
			break;
		}
	case 0x38:
		{
			messageName = "Disconnect Initiate";
			break;
		}
	case 0x48:
		{
			messageName = "Disconnect Confirm";
			break;
		}
	case 0x04:
		{
			messageName = "Data Acknowledgement";
			break;
		}
	case 0x30:
		{
			messageName = "Interrupt";
			break;
		}
	case 0x10:
		{
			messageName = "Link Service";
			break;
		}
	case 0x14:
		{
			messageName = "Other Data Acknowledgement";
			break;
		}
	default:
		{
			messageName = "Other";
			break;
		}
	}

	Log(LogNspMessages, LogVerbose, "%s(0x%02x) from ", messageName, header->msgFlg);
	LogDecnetAddress(LogNspMessages, LogVerbose, from);
	Log(LogNspMessages, LogVerbose, " src=%hu dst=%hu\n", header->srcAddr, header->dstAddr);
}

static void LogState(LogSource source, LogLevel level, NspPortState state)
{
	static char *stateString[] =
	{
		"Open",
		"ConnectReceived",
		"DisconnectReject",
		"DisconnectRejectComplete",
		"ConnectConfirm",
		"ConnectInitiate",
		"NoResources",
		"NoCommunication",
		"ConnectDelivered",
		"Rejected",
		"Running",
		"DisconnectInitiate",
		"DisconnectComplete",
		"DisconnectNotification",
		"Closed",
		"ClosedNotification"
	};

	Log(source, level, "%s", stateString[(int)state]);
}