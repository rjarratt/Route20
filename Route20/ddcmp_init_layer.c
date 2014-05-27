/* ddcmp_init_layer.c: Ethernet initialization layer
------------------------------------------------------------------------------

Copyright (c) 2013, Robert M. A. Jarratt

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
#include "basictypes.h"
#include "platform.h"
#include "route20.h"
#include "socket.h"
#include "decnet.h"
#include "platform.h"
#include "circuit.h"
#include "ddcmp_init_layer.h"
#include "ddcmp_circuit.h"
#include "ddcmp_sock.h"
#include "messages.h"
#include "timer.h"

typedef enum
{
	DdcmpInitUndefinedEvent,
    DdcmpInitNRIVREvent, /* NRI with verification requested */
    DdcmpInitNRINVEvent, /* NRI with verification not requested */
    DdcmpInitNRVEvent,
    DdcmpInitRTEvent,
    DdcmpInitSCEvent,
    DdcmpInitSTEEvent,
    DdcmpInitOPOEvent,
    DdcmpInitOPFEvent,
    DdcmpInitIMEvent,
    DdcmpInitRCEvent,
    DdcmpInitCDCEvent,
    DdcmpInitCUCEvent
} DdcmpInitEvent;

typedef struct
{
	DdcmpInitEvent evt;
	DdcmpInitState currentState;
	DdcmpInitState newState;
	int (*action)(circuit_t *circuit);
} state_table_entry_t;

typedef struct
{
    ddcmp_circuit_t *ddcmpCircuit;
    DdcmpInitEvent evt; 
} queued_ddcmp_init_event_t;

static circuit_t * ddcmpCircuits[NC];
static int ddcmpCircuitCount;

static void DdcmpInitCircuitUp(ddcmp_circuit_t *ddcmpCircuit);
static void DdcmpInitCircuitDown(ddcmp_circuit_t *ddcmpCircuit);
static void DdcmpInitNotifyRunning(void *context);
static void DdcmpInitNotifyHalt(void *context);

static socket_t * TcpAcceptCallback(sockaddr_t *receivedFrom);
static void TcpConnectCallback(socket_t *sock);
static void TcpDisconnectCallback(socket_t *sock);
static ddcmp_circuit_t *FindCircuit(socket_t *sock);

static void QueueEvent(ddcmp_circuit_t *ddcmpCircuit, DdcmpInitEvent evt);
static void ProcessEvent(ddcmp_circuit_t *ddcmpCircuit, DdcmpInitEvent evt);
static void ProcessQueuedEvent(queued_ddcmp_init_event_t *  queuedEvt);
static int IssueReinitializeCommandAndStartRecallTimerAction(circuit_t *circuit);
static int IssueStopAction(circuit_t *circuit);
static int SendInitMessageAction(circuit_t *circuit);
static int SendVerifyMessageAction(circuit_t *circuit);

static char * lineStateString[] =
{
	"Run",
	"Circuit Rejected",
	"Data Link Start",
	"Routing Layer Initialize",
	"Routing Layer Verify",
    "Routing Layer Complete",
    "Off",
    "Halt"
};

static char * lineEventString[] =
{
	"Undefined",
    "New Routing Layer Init (with verification) message received",
    "New Routing Layer Init (without verification) message received",
    "New Routing Layer Verification message received",
    "Routing Layer timed out",
    "Start Complete notification",
    "Start Notification Error",
    "Operator turned circuit on",
    "Operator turned circuit off",
    "Invalid message received",
    "Received Reject Complete",
    "Received Circuit Down Complete",
    "Received Circuit Up Complete"
};

static state_table_entry_t stateTable[] =
{
    { DdcmpInitNRIVREvent, DdcmpInitRUState, DdcmpInitCRState, NULL },
    { DdcmpInitNRIVREvent, DdcmpInitCRState, DdcmpInitCRState, NULL },
    { DdcmpInitNRIVREvent, DdcmpInitDSState, DdcmpInitDSState, NULL },
    { DdcmpInitNRIVREvent, DdcmpInitRIState, DdcmpInitRVState, SendVerifyMessageAction },
    { DdcmpInitNRIVREvent, DdcmpInitRVState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitNRIVREvent, DdcmpInitRCState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitNRIVREvent, DdcmpInitOFState, DdcmpInitOFState, NULL },
    { DdcmpInitNRIVREvent, DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitNRINVEvent, DdcmpInitRUState, DdcmpInitCRState, NULL },
    { DdcmpInitNRINVEvent, DdcmpInitCRState, DdcmpInitCRState, NULL },
    { DdcmpInitNRINVEvent, DdcmpInitDSState, DdcmpInitDSState, NULL },
    { DdcmpInitNRINVEvent, DdcmpInitRIState, DdcmpInitRVState, NULL },
    { DdcmpInitNRINVEvent, DdcmpInitRVState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitNRINVEvent, DdcmpInitRCState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitNRINVEvent, DdcmpInitOFState, DdcmpInitOFState, NULL },
    { DdcmpInitNRINVEvent, DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitNRVEvent,   DdcmpInitRUState, DdcmpInitCRState, NULL },
    { DdcmpInitNRVEvent,   DdcmpInitCRState, DdcmpInitCRState, NULL },
    { DdcmpInitNRVEvent,   DdcmpInitDSState, DdcmpInitDSState, NULL },
    { DdcmpInitNRVEvent,   DdcmpInitRIState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitNRVEvent,   DdcmpInitRVState, DdcmpInitRCState, NULL },
    { DdcmpInitNRVEvent,   DdcmpInitRCState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitNRVEvent,   DdcmpInitOFState, DdcmpInitOFState, NULL },
    { DdcmpInitNRVEvent,   DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitRTEvent,    DdcmpInitRUState, DdcmpInitRUState, NULL },
    { DdcmpInitRTEvent,    DdcmpInitCRState, DdcmpInitCRState, NULL },
    { DdcmpInitRTEvent,    DdcmpInitDSState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitRTEvent,    DdcmpInitRIState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitRTEvent,    DdcmpInitRVState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitRTEvent,    DdcmpInitRCState, DdcmpInitRCState, NULL },
    { DdcmpInitRTEvent,    DdcmpInitOFState, DdcmpInitOFState, NULL },
    { DdcmpInitRTEvent,    DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitSCEvent,    DdcmpInitRUState, DdcmpInitCRState, NULL },
    { DdcmpInitSCEvent,    DdcmpInitCRState, DdcmpInitCRState, NULL },
    { DdcmpInitSCEvent,    DdcmpInitDSState, DdcmpInitRIState, SendInitMessageAction },
    { DdcmpInitSCEvent,    DdcmpInitRIState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitSCEvent,    DdcmpInitRVState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitSCEvent,    DdcmpInitRCState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitSCEvent,    DdcmpInitOFState, DdcmpInitOFState, NULL },
    { DdcmpInitSCEvent,    DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitSTEEvent,   DdcmpInitRUState, DdcmpInitCRState, NULL },
    { DdcmpInitSTEEvent,   DdcmpInitCRState, DdcmpInitCRState, NULL },
    { DdcmpInitSTEEvent,   DdcmpInitDSState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitSTEEvent,   DdcmpInitRIState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitSTEEvent,   DdcmpInitRVState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitSTEEvent,   DdcmpInitRCState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitSTEEvent,   DdcmpInitOFState, DdcmpInitOFState, NULL },
    { DdcmpInitSTEEvent,   DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitOPOEvent,   DdcmpInitRUState, DdcmpInitRUState, NULL },
    { DdcmpInitOPOEvent,   DdcmpInitCRState, DdcmpInitCRState, NULL },
    { DdcmpInitOPOEvent,   DdcmpInitDSState, DdcmpInitDSState, NULL },
    { DdcmpInitOPOEvent,   DdcmpInitRIState, DdcmpInitRIState, NULL },
    { DdcmpInitOPOEvent,   DdcmpInitRVState, DdcmpInitRVState, NULL },
    { DdcmpInitOPOEvent,   DdcmpInitRCState, DdcmpInitRCState, NULL },
    { DdcmpInitOPOEvent,   DdcmpInitOFState, DdcmpInitCRState, NULL },
    { DdcmpInitOPOEvent,   DdcmpInitHAState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },

    { DdcmpInitOPFEvent,   DdcmpInitRUState, DdcmpInitOFState, IssueStopAction },
    { DdcmpInitOPFEvent,   DdcmpInitCRState, DdcmpInitOFState, NULL },
    { DdcmpInitOPFEvent,   DdcmpInitDSState, DdcmpInitHAState, IssueStopAction },
    { DdcmpInitOPFEvent,   DdcmpInitRIState, DdcmpInitHAState, IssueStopAction },
    { DdcmpInitOPFEvent,   DdcmpInitRVState, DdcmpInitHAState, IssueStopAction },
    { DdcmpInitOPFEvent,   DdcmpInitRCState, DdcmpInitHAState, IssueStopAction },
    { DdcmpInitOPFEvent,   DdcmpInitOFState, DdcmpInitOFState, NULL },
    { DdcmpInitOPFEvent,   DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitIMEvent,    DdcmpInitRUState, DdcmpInitCRState, NULL },
    { DdcmpInitIMEvent,    DdcmpInitCRState, DdcmpInitCRState, NULL },
    { DdcmpInitIMEvent,    DdcmpInitDSState, DdcmpInitDSState, NULL },
    { DdcmpInitIMEvent,    DdcmpInitRIState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitIMEvent,    DdcmpInitRVState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitIMEvent,    DdcmpInitRCState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitIMEvent,    DdcmpInitOFState, DdcmpInitOFState, NULL },
    { DdcmpInitIMEvent,    DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitRCEvent,    DdcmpInitRUState, DdcmpInitCRState, NULL },
    { DdcmpInitRCEvent,    DdcmpInitCRState, DdcmpInitCRState, NULL },
    { DdcmpInitRCEvent,    DdcmpInitDSState, DdcmpInitDSState, NULL },
    { DdcmpInitRCEvent,    DdcmpInitRIState, DdcmpInitRIState, NULL },
    { DdcmpInitRCEvent,    DdcmpInitRVState, DdcmpInitRVState, NULL },
    { DdcmpInitRCEvent,    DdcmpInitRCState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitRCEvent,    DdcmpInitOFState, DdcmpInitOFState, NULL },
    { DdcmpInitRCEvent,    DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitCDCEvent,   DdcmpInitRUState, DdcmpInitRUState, NULL },
    { DdcmpInitCDCEvent,   DdcmpInitCRState, DdcmpInitDSState, IssueReinitializeCommandAndStartRecallTimerAction },
    { DdcmpInitCDCEvent,   DdcmpInitDSState, DdcmpInitDSState, NULL },
    { DdcmpInitCDCEvent,   DdcmpInitRIState, DdcmpInitRIState, NULL },
    { DdcmpInitCDCEvent,   DdcmpInitRVState, DdcmpInitRVState, NULL },
    { DdcmpInitCDCEvent,   DdcmpInitRCState, DdcmpInitRCState, NULL },
    { DdcmpInitCDCEvent,   DdcmpInitOFState, DdcmpInitHAState, NULL },
    { DdcmpInitCDCEvent,   DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitCUCEvent,   DdcmpInitRUState, DdcmpInitRUState, NULL },
    { DdcmpInitCUCEvent,   DdcmpInitCRState, DdcmpInitCRState, NULL },
    { DdcmpInitCUCEvent,   DdcmpInitDSState, DdcmpInitDSState, NULL },
    { DdcmpInitCUCEvent,   DdcmpInitRIState, DdcmpInitRIState, NULL },
    { DdcmpInitCUCEvent,   DdcmpInitRVState, DdcmpInitRVState, NULL },
    { DdcmpInitCUCEvent,   DdcmpInitRCState, DdcmpInitRUState, NULL },
    { DdcmpInitCUCEvent,   DdcmpInitOFState, DdcmpInitOFState, NULL },
    { DdcmpInitCUCEvent,   DdcmpInitHAState, DdcmpInitHAState, NULL },

    { DdcmpInitUndefinedEvent, 0, 0, NULL }
};

void DdcmpInitLayerStart(circuit_t circuits[], int circuitCount)
{
	int i;

	for(i = 1; i <= circuitCount; i++)
	{
		if (circuits[i].circuitType == DDCMPCircuit)
		{
            ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuits[i].context;
           	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)ddcmpCircuit->context;
            sockContext->line.NotifyRunning = DdcmpInitNotifyRunning;
            sockContext->line.NotifyHalt = DdcmpInitNotifyHalt;
		    ddcmpCircuits[ddcmpCircuitCount++] = &circuits[i];
		}
	}

	SetTcpAcceptCallback(TcpAcceptCallback);
	SetTcpConnectCallback(TcpConnectCallback);
	SetTcpDisconnectCallback(TcpDisconnectCallback);
}

void DdcmpInitLayerStop(void)
{
	int i;

	StopAllAdjacencies(DDCMPCircuit);

	for(i = 0; i < ddcmpCircuitCount; i++)
	{
		circuit_t *circuit = ddcmpCircuits[i];
		ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
//		ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;
		circuit->Close(circuit);
        ProcessEvent(ddcmpCircuit, DdcmpInitOPFEvent);
		//DdcmpHalt(&ddcmpSock->line);
	}
}

void DdcmpInitLayerCircuitUpComplete(circuit_ptr circuit)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
    CircuitUpComplete(circuit);
    ProcessEvent(ddcmpCircuit, DdcmpInitCUCEvent);
}

void DdcmpInitLayerCircuitDownComplete(circuit_ptr circuit)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
    CircuitDownComplete(circuit);
    ProcessEvent(ddcmpCircuit, DdcmpInitCDCEvent);
}

void DdcmpInitProcessInitializationMessage(circuit_t *circuit, initialization_msg_t *msg)
{
    AdjacencyType at;
    decnet_address_t from;
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
    int valid = 0;

    GetDecnetAddressFromId((byte *)&msg->srcnode, &from);
    
    //Log(LogMessages, LogVerbose, "Initialization. From ");
    //LogDecnetAddress(LogMessages, LogVerbose, &from);
    //Log(LogMessages, LogVerbose, " Node: %d", msg->tiinfo & 0x03);
    //Log(LogMessages, LogVerbose, " Verify: %s", (msg->tiinfo & 0x04) ? "Y" : "N");
    //Log(LogMessages, LogVerbose, " Block Req: %s", (msg->tiinfo & 0x08) ? "Y" : "N");
    //Log(LogMessages, LogVerbose, " Block size %d, Ver %d.%d.%d", msg->blksize, msg->tiver[0], msg->tiver[1], msg->tiver[2]);
    //Log(LogMessages, LogVerbose, " Timer: %d\n", msg->timer);

    if (from.node > NN)
    {
        Log(LogDdcmpInit, LogError, "Initialization received for node number outside maximum allowed\n");
    }
    else if (nodeInfo.level == 1 && nodeInfo.address.area != from.area)
    {
        Log(LogDdcmpInit, LogError, "Initialization received from another area when configured as Level 1 router\n");
    }
    else if (nodeInfo.level == 2 && (GetRouterLevel(msg->tiinfo) == 1 && nodeInfo.address.area != from.area))
    {
        Log(LogDdcmpInit, LogError, "Initialization received from non Level 2 node in another area\n");
    }
    else if (0) /* TODO: spec section 7.5 has some conditions on block size */
    {
        Log(LogDdcmpInit, LogError, "Initialization received for invalid block size\n");
    }
    else if (VersionSupported(msg->tiver))
    {
        Log(LogDdcmpInit, LogVerbose, "Initialization received\n");

        // TODO: Check possible DDCMP seq no wrap error causing circuit to drop

        valid = 1;
    }

	if (valid)
	{
		memcpy( &circuit->adjacentNode, &from, sizeof(decnet_address_t)); 
	}

    at = GetAdjacencyType(msg->tiinfo);
    if (valid && VerificationRequired(msg->tiinfo))
    {
        ProcessEvent(ddcmpCircuit, DdcmpInitNRIVREvent);
	    InitialiseCircuitAdjacency(&from, circuit, at, msg->timer);
    }
    else if (valid)
    {
        ProcessEvent(ddcmpCircuit, DdcmpInitNRINVEvent);
    	InitialiseCircuitAdjacency(&from, circuit, at, msg->timer);
    }
    else
    {
        DdcmpInitProcessInvalidMessage(circuit);
    }
}

void DdcmpInitProcessVerificationMessage(circuit_t *circuit, verification_msg_t *msg)
{
    decnet_address_t from;
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
	//int i;

	//Log(LogMessages, LogVerbose, "Verification function value:");
	//for (i = 0; i < msg->fcnvalLen; i++)
	//{
	//    Log(LogMessages, LogVerbose, " %02X", msg->fcnval[i]);
	//}
	//Log(LogMessages, LogVerbose, "\n");

    GetDecnetAddressFromId((byte *)&msg->srcnode, &from);
    ProcessEvent(ddcmpCircuit, DdcmpInitNRVEvent);
}

void DdcmpInitProcessPhaseIINodeInitializationMessage(circuit_t *circuit, node_init_phaseii_t *msg)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
	ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;
	packet_t *pkt;
	if (msg->requests & 0x01)
	{
		// TODO: implement verification message required
	}

	pkt = CreateNodeInitPhaseIIMessage(nodeInfo.address, nodeInfo.name);
	if (pkt != NULL)
	{
		DdcmpSendDataMessage(&ddcmpSock->line, pkt->payload, pkt->payloadLen);
	}
}

void DdcmpInitProcessInvalidMessage(circuit_t *circuit)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
    ProcessEvent(ddcmpCircuit, DdcmpInitIMEvent);
	DdcmpInitCircuitDown(ddcmpCircuit);
}

void DdcmpInitProcessCircuitRejectComplete(circuit_t *circuit)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
	ProcessEvent(ddcmpCircuit, DdcmpInitRCEvent);
}

static void DdcmpInitCircuitUp(ddcmp_circuit_t *ddcmpCircuit)
{
	QueueImmediate(ddcmpCircuit->circuit, CircuitUp);
}

static void DdcmpInitCircuitDown(ddcmp_circuit_t *ddcmpCircuit)
{
	QueueImmediate(ddcmpCircuit->circuit, CircuitDown);
}

static void DdcmpInitNotifyRunning(void *context)
{
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)context;
	Log(LogDdcmpInit, LogDetail, "DDCMP line %s running\n", sockContext->ddcmpCircuit->circuit->name);
    ProcessEvent(sockContext->ddcmpCircuit, DdcmpInitSCEvent);
}

static void DdcmpInitNotifyHalt(void *context)
{
	ddcmp_sock_t *sockContext = (ddcmp_sock_t *)context;
	Log(LogDdcmpInit, LogDetail, "DDCMP line %s halted\n", sockContext->ddcmpCircuit->circuit->name);
    ProcessEvent(sockContext->ddcmpCircuit, DdcmpInitOPFEvent); // TODO: Not sure this is the right event for this situation
	//DdcmpStart(&sockContext->line); // TODO: Not sure if should restart
}

static socket_t * TcpAcceptCallback(sockaddr_t *receivedFrom)
{
	int i;
	socket_t *ans = NULL;
	sockaddr_in_t *receivedFromIn = (sockaddr_in_t *)receivedFrom;

	for(i = 0; i < ddcmpCircuitCount; i++)
	{
		ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)ddcmpCircuits[i]->context;
		ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;

		sockaddr_in_t *destinationAddressIn = (sockaddr_in_t *)&ddcmpSock->destinationAddress;

		if (memcmp(&receivedFromIn->sin_addr, &destinationAddressIn->sin_addr, sizeof(struct in_addr)) == 0)
		{
			if (ddcmpSock->socket.socket == INVALID_SOCKET)
			{
			   ans = &ddcmpSock->socket;
			}
			else
			{
	            Log(LogDdcmpInit, LogWarning, "Cannot accept a second connection from same source address on DDCMP line %s\n", ddcmpCircuit->circuit->name);
			}
			break;
		}
	}

	return ans;
}

static void TcpConnectCallback(socket_t *sock)
{
	ddcmp_circuit_t *ddcmpCircuit = FindCircuit(sock);
    if (ddcmpCircuit != NULL)
    {
        ddcmpCircuit->circuit->waitHandle = sock->waitHandle;
        Log(LogDdcmpInit, LogInfo, "DDCMP line %s has been opened\n", ddcmpCircuit->circuit->name);
        RegisterEventHandler(ddcmpCircuit->circuit->waitHandle, "DDCMP Circuit", ddcmpCircuit->circuit, ddcmpCircuit->circuit->WaitEventHandler);
        ProcessEvent(ddcmpCircuit, DdcmpInitOPOEvent);
	}
}

static void TcpDisconnectCallback(socket_t *sock)
{
    ddcmp_circuit_t *ddcmpCircuit = FindCircuit(sock);
    if (ddcmpCircuit != NULL)
    {
        Log(LogDdcmpInit, LogInfo, "DDCMP line %s has been closed\n", ddcmpCircuit->circuit->name);
		ProcessEvent(ddcmpCircuit, DdcmpInitOPFEvent);
        DeregisterEventHandler(ddcmpCircuit->circuit->waitHandle);
    }
}

static ddcmp_circuit_t *FindCircuit(socket_t *sock)
{
    ddcmp_circuit_t * ans = NULL;
	int i;

	for(i = 0; i < ddcmpCircuitCount; i++)
	{
		ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)ddcmpCircuits[i]->context;
		ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;

		if (sock == &ddcmpSock->socket)
		{
            ans = ddcmpCircuit;
			break;
		}
	}

    return ans;
}

static void QueueEvent(ddcmp_circuit_t *ddcmpCircuit, DdcmpInitEvent evt)
{
    queued_ddcmp_init_event_t *queuedEvt = (queued_ddcmp_init_event_t *)malloc(sizeof(queued_ddcmp_init_event_t));
    queuedEvt->ddcmpCircuit = ddcmpCircuit;
    queuedEvt->evt = evt;
    QueueImmediate(queuedEvt, ProcessQueuedEvent);
}

static void ProcessEvent(ddcmp_circuit_t *ddcmpCircuit, DdcmpInitEvent evt)
{
	state_table_entry_t *entry;
	int i = 0;
	int match;

	do
	{
		entry = &stateTable[i++];
		match = entry->evt == DdcmpInitUndefinedEvent || (entry->evt == evt && entry->currentState == ddcmpCircuit->state);
	}
	while (!match);

	if (entry->evt != DdcmpInitUndefinedEvent)
	{
		int ok = 1;
		int stateChanging = ddcmpCircuit->state != entry->newState;

		if (stateChanging)
		{
			Log(LogDdcmpInit, LogVerbose, "%s. Changing DDCMP circuit state from %s to %s\n", lineEventString[(int)entry->evt], lineStateString[(int)ddcmpCircuit->state], lineStateString[(int)entry->newState]);
		}

		ddcmpCircuit->state = entry->newState;

        if (entry->action != NULL)
        {
            ok = entry->action(ddcmpCircuit->circuit);
        }

		if (stateChanging)
		{
            if (entry->newState == DdcmpInitRCState)
            {
	            DdcmpInitCircuitUp(ddcmpCircuit);
            }
            else if (entry->newState == DdcmpInitCRState || entry->newState == DdcmpInitOFState)
            {
	            DdcmpInitCircuitDown(ddcmpCircuit);
            }
		}
	}
}

static void ProcessQueuedEvent(queued_ddcmp_init_event_t *queuedEvt)
{
    ProcessEvent(queuedEvt->ddcmpCircuit, queuedEvt->evt);
    free(queuedEvt);
}

static void HandleRecallTimer(rtimer_t *timer, char *name, void *context)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)context;
	ddcmpCircuit->recallTimer = NULL;
	if (ddcmpCircuit->state != DdcmpInitRUState)
	{
		Log(LogDdcmpInit, LogVerbose, "Recall timer timed out for %s.\n", ddcmpCircuit->circuit->name);
		ProcessEvent(ddcmpCircuit, DdcmpInitRTEvent);
	}
}

static int IssueReinitializeCommandAndStartRecallTimerAction(circuit_t *circuit)
{
	time_t now;
    ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
    ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;

	if (ddcmpCircuit->recallTimer == NULL)
	{
		Log(LogDdcmpInit, LogDetail, "Starting DDCMP line %s\n", ddcmpCircuit->circuit->name);
		DdcmpStart(&ddcmpSock->line);

		time(&now);
		ddcmpCircuit->recallTimer = CreateTimer("Recall timer", now + RECALL_TIMER, 0, ddcmpCircuit, HandleRecallTimer);
	}
	else
	{
		Log(LogDdcmpInit, LogVerbose, "Skipping reinitialize for %s because recall timer is active, will reinitialize in the timer handler.\n", ddcmpCircuit->circuit->name);
	}
    return 1;
}

static int IssueStopAction(circuit_t *circuit)
{
    ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
    ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;
    Log(LogDdcmpInit, LogDetail, "Stopping DDCMP line %s\n", ddcmpCircuit->circuit->name);
    DdcmpHalt(&ddcmpSock->line);
    return 1;
}

static int SendInitMessageAction(circuit_t *circuit)
{
    packet_t *pkt = CreateInitialization(nodeInfo.address);
    Log(LogDdcmpInit, LogDetail, "Sending Initialization message on %s\n", circuit->name);
    circuit->WritePacket(circuit, NULL, NULL, pkt);
    return 1;
}

static int SendVerifyMessageAction(circuit_t *circuit)
{
    packet_t *packet = CreateVerification(nodeInfo.address);
    Log(LogDdcmpInit, LogDetail, "Sending verification message\n");
    circuit->WritePacket(circuit, NULL, NULL, packet);
    return 1;
}


