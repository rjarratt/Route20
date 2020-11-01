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

#define INFO_V40 2

#define NO_RESOURCES 1
#define DISCONNECT_COMPLETE 42
#define NO_LINK_TERMINATE 41

typedef struct
{
	decnet_address_t *node;
	uint16            locAddr;
	uint16            remAddr;
} PortSearchContext;

static void ProcessLinkConnectionCompletion(decnet_address_t *from, nsp_header_t *);
static void ProcessConnectInitiate(decnet_address_t *from, nsp_connect_initiate_t *connectInitiate);
static void ProcessDisconnectInitiate(decnet_address_t *from, nsp_disconnect_initiate_t *disconnectInitiate);
/* TODO: must add ProcessDisconnectConfirm */
static void ProcessDataAcknowledgement(decnet_address_t *from, nsp_data_acknowledgement_t *dataAcknowledgement);
static void ProcessDataMessage(decnet_address_t *from, nsp_header_t *header, byte *data, int dataLength);

static void TransmitQueuedMessages(session_control_port_t *port);

static void SendConnectAcknowledgement(decnet_address_t *to, uint16 dstAddr); 
static void SendDisconnectInitiate(decnet_address_t* to, uint16 srcAddr, uint16 dstAddr, uint16 reason, byte dataLen, byte* data);
static void SendDisconnectConfirm(decnet_address_t* to, uint16 srcAddr, uint16 dstAddr, uint16 reason);
static void SendConnectConfirm(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, byte services, byte dataLen, byte* data);
static void SendOtherDataAcknowledgement(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 number);
static void SendDataSegment(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte *data, int dataLength);

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

int NspOpen(void (*closeCallback)(uint16 srcAddr), void (*connectCallback)(decnet_address_t* remNode, uint16 locAddr, uint16 remAddr, byte* data, int dataLength), void (*dataCallback)(uint16 locAddr, byte *data, int dataLength))
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
		port->transmitSegNum++;
		EnqueueToTransmitQueue(&port->transmit_queue, port->transmitSegNum, data, dataLength);
        TransmitQueuedMessages(port);
	}
}

void NspProcessPacket(decnet_address_t *from, byte *data, int dataLength)
{
	// TODO: validate NSP messages, see latter half of section 6.2
	// TODO: process "return to sender" messages, NSP spec p79

	nsp_header_t *header = ParseNspHeader(data, dataLength);

	LogMessage(from, header);

	ProcessLinkConnectionCompletion(from, header);

	if (IsConnectInitiateMessage(data) || IsRetransmittedConnectInitiateMessage(data))
	{
		ProcessConnectInitiate(from, ParseConnectInitiate(data, dataLength));
	}
	else if (IsDisconnectInitiateMessage(data))
	{
		ProcessDisconnectInitiate(from, ParseDisconnectInitiate(data, dataLength));
	}
	else if (IsDisconnectConfirmMessage(data))
	{
	}
	else if (IsNspDataMessage(data))
	{
		ProcessDataMessage(from, header, data, dataLength);
	}
	else if (IsDataAcknowledgementMessage(data))
	{
		ProcessDataAcknowledgement(from, ParseDataAcknowledgement(data, dataLength));
	}
	else if (IsNoOperationMessage(data))
	{
	}
	else
	{
		Log(LogNsp, LogWarning, "Discarding unrecognised NSP message\n");
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

static void ProcessLinkConnectionCompletion(decnet_address_t *from, nsp_header_t *header)
{
	if (IsDataAcknowledgementMessage((byte *)header) || IsInterruptMessage((byte *)header) || IsLinkServiceMessage((byte *)header) || IsOtherDataAcknowledgementMessage((byte *)header))
	{
		session_control_port_t *port;

		port = FindScpEntryForRemoteNode(from, header->srcAddr);
		if (port != NULL)
		{
			if (port->state == NspPortStateConnectConfirm)
			{
				SetPortState(port, NspPortStateRunning);
			}
		}
	}
}

static void ProcessConnectInitiate(decnet_address_t *from, nsp_connect_initiate_t *connectInitiate)
{
	/* Section 6.2 of NSP spec 

	   Bullet 4 not implemented, where ConnectInitiate has been returned, because the router does not initiate connections */

	if (connectInitiate->dstAddr == 0)
	{
		session_control_port_t *port;
		port = FindScpEntryForRemoteNode(from, connectInitiate->srcAddr);
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
					port->addrRem = connectInitiate->srcAddr;
					memcpy(&port->node, from, sizeof(decnet_address_t));
					SetPortState(port, NspPortStateConnectReceived);
					SendConnectAcknowledgement(from, connectInitiate->srcAddr);
					break;
				}
				case NspPortStateConnectReceived:
				case NspPortStateConnectConfirm:
				case NspPortStateDisconnectReject:
				{
					SendConnectAcknowledgement(from, connectInitiate->srcAddr);
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
			SendDisconnectConfirm(from, connectInitiate->dstAddr, connectInitiate->srcAddr, NO_RESOURCES);
		}
	}

}

static void ProcessDisconnectInitiate(decnet_address_t *from, nsp_disconnect_initiate_t *disconnectInitiate)
{
	session_control_port_t *port;

	port = FindScpEntryForRemoteNodeConnection(from, disconnectInitiate->dstAddr, disconnectInitiate->srcAddr);
	if (port != NULL)
	{
		switch (port->state)
		{
		case NspPortStateConnectInitiate:
		case NspPortStateConnectDelivered:
			{
				SendDisconnectConfirm(from, disconnectInitiate->dstAddr, disconnectInitiate->srcAddr, disconnectInitiate->reason);
			    SetPortState(port, NspPortStateRejected);
				break;
			}
		case NspPortStateRejected:
			{
				SendDisconnectConfirm(from, disconnectInitiate->dstAddr, disconnectInitiate->srcAddr, disconnectInitiate->reason);
				break;
			}
		case NspPortStateRunning:
			{
				SendDisconnectConfirm(from, disconnectInitiate->dstAddr, disconnectInitiate->srcAddr, disconnectInitiate->reason);
			    SetPortState(port, NspPortStateDisconnectNotification);
				break;
			}
		case NspPortStateDisconnectInitiate:
		case NspPortStateDisconnectComplete:
			{
				SendDisconnectConfirm(from, disconnectInitiate->dstAddr, disconnectInitiate->srcAddr, disconnectInitiate->reason);
			    SetPortState(port, NspPortStateDisconnectComplete);
				break;
			}
		case NspPortStateDisconnectNotification:
			{
				SendDisconnectConfirm(from, disconnectInitiate->dstAddr, disconnectInitiate->srcAddr, disconnectInitiate->reason);
				break;
			}
        default:
            {
                break;
            }
		}

		Log(LogNsp, LogInfo, "Closed NSP connection from ");
		LogDecnetAddress(LogNsp, LogInfo, &port->node);
		Log(LogNsp, LogInfo, " on port %d\n", port->addrLoc);

		SetPortState(port, NspPortStateClosed);
		port->addrRem = 0;
		memset(&port->node, 0, sizeof(port->node));
		port->closeCallback(port->addrLoc);
		TerminateTransmitQueue(&port->transmit_queue);
	}
}

static void ProcessDataAcknowledgement(decnet_address_t *from, nsp_data_acknowledgement_t *dataAcknowledgement)
{
	session_control_port_t *port;

	port = FindScpEntryForRemoteNode(from, dataAcknowledgement->srcAddr);
	if (port != NULL)
	{
		uint16 ackDataField;
		int isAck;
		uint16 ackNum;

		if (dataAcknowledgement->msgFlg == 4)
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
            Log(LogNspMessages, LogVerbose, "ACK of segment %d\n", ackNum);
		    port->flowRem = ackNum;
		    TransmitQueuedMessages(port);
		}
		else
		{
			// TODO: Implement NAK processing
            Log(LogNspMessages, LogError, "NAK of segment %d - NOT IMPLEMENTED\n", ackNum);
		}
	}
}

static void ProcessDataMessage(decnet_address_t *from, nsp_header_t *header, byte *data, int dataLength)
{
	session_control_port_t *port;

	port = FindScpEntryForRemoteNodeConnection(from, header->dstAddr, header->srcAddr);
	if (port != NULL)
	{
		port->dataCallback(port->addrLoc, data + 9, dataLength - 9);
	}
}

static void TransmitQueuedMessages(session_control_port_t *port)
{
	// TODO: NAK and retransmit after timeout
	byte data[NSP_SEGMENT_SIZE];
	int dataLength;
	uint16 transmitSegmentNumber;

	while (DequeueFromTransmitQueue(&port->transmit_queue, port->flowRem + 1, &transmitSegmentNumber, data, sizeof(data), &dataLength))
	{
        SendDataSegment(&port->node, port->addrLoc, port->addrRem, transmitSegmentNumber, data, dataLength);
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

	if (reason == NO_RESOURCES)
	{
		Log(LogNspMessages, LogVerbose, "Sending NoResources\n");
	}
	else if (reason == DISCONNECT_COMPLETE)
	{
		Log(LogNspMessages, LogVerbose, "Sending DisconnectComplete\n");
	}
	else if (reason == NO_LINK_TERMINATE)
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

static void SendOtherDataAcknowledgement(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, int isAck, uint16 number)
{
	packet_t *confirmPacket;
	Log(LogNspMessages, LogVerbose, "Sending OtherDataAcknowledgement\n");
	confirmPacket = NspCreateOtherDataAcknowledgement(to, srcAddr, dstAddr, isAck, number);
	SendPacket(NULL, to, confirmPacket);
}

static void SendDataSegment(decnet_address_t *to, uint16 srcAddr, uint16 dstAddr, uint16 seqNo, byte *data, int dataLength)
{
	packet_t *confirmPacket;
	Log(LogNspMessages, LogVerbose, "Sending DataSegment\n");
    confirmPacket = NspCreateDataMessage(to, srcAddr, dstAddr, seqNo, data, dataLength);
	SendPacket(NULL, to, confirmPacket);
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

	Log(LogNspMessages, LogVerbose, "%s from ", messageName);
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