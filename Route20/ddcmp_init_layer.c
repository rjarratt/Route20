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
#include "adjacency.h"
#include "platform.h"
#include "circuit.h"
#include "ddcmp_init_layer.h"
#include "ddcmp_circuit.h"
#include "ddcmp_sock.h"
#include "messages.h"
#include "timer.h"

static circuit_t * ddcmpCircuits[NC];
static int ddcmpCircuitCount;

static socket_t * TcpAcceptCallback(sockaddr_t *receivedFrom);
static void TcpConnectCallback(socket_t *sock);
static void TcpDisconnectCallback(socket_t *sock);
static ddcmp_circuit_t *FindCircuit(socket_t *sock);
static void HandleHelloAndTestTimer(rtimer_t *timer, char *name, void *context);
static void StopTimerIfRunning(ddcmp_circuit_t *ddcmpCircuit);

void DdcmpInitLayerStart(circuit_t circuits[], int circuitCount)
{
	int i;

	for(i = 1; i <= circuitCount; i++)
	{
		if (circuits[i].circuitType == DDCMPCircuit)
		{
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
	//packet_t *packet;

	StopAllAdjacencies(); // TODO: should only stop those on the DDCMP circuits

	for(i = 0; i < ddcmpCircuitCount; i++)
	{
		circuit_t *circuit = ddcmpCircuits[i];
		ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
		ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;
		circuit->Close(circuit);
		DdcmpHalt(&ddcmpSock->line);
	}
}

void DdcmpInitProcessInitializationMessage(circuit_t *circuit, initialization_msg_t *msg)
{
    decnet_address_t from;
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
    GetDecnetAddressFromId((byte *)&msg->srcnode, &from);
    
    Log(LogMessages, LogVerbose, "Initialization. From ");
    LogDecnetAddress(LogMessages, LogVerbose, &from);
    Log(LogMessages, LogVerbose, " Node: %d", msg->tiinfo & 0x03);
    Log(LogMessages, LogVerbose, " Verify: %s", (msg->tiinfo & 0x04) ? "Y" : "N");
    Log(LogMessages, LogVerbose, " Block Req: %s", (msg->tiinfo & 0x08) ? "Y" : "N");
    Log(LogMessages, LogVerbose, " Block size %d, Ver %d.%d.%d", msg->blksize, msg->tiver[0], msg->tiver[1], msg->tiver[2]);
    Log(LogMessages, LogVerbose, " Timer: %d\n", msg->timer);

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
        packet_t *packet = CreateVerification(nodeInfo.address);
        Log(LogDdcmpInit, LogInfo, "Initialization received\n");
        if (msg->tiinfo & 0x04)
        {
            time_t now;
            Log(LogDdcmpInit, LogInfo, "Sending verification message\n");
            circuit->WritePacket(circuit, NULL, NULL, packet);

            StopTimerIfRunning(ddcmpCircuit);
            time(&now);
            ddcmpCircuit->helloTimer = CreateTimer("HelloAndTest", now, T3, circuit, HandleHelloAndTestTimer);
            // TODO: Full init layer state table handling
            // TODO: Check we get HelloAndTest from peer and close circuit if we don't (check spec for how to detect)
            // TODO: Adjacency handling
            // TODO: Check possible DDCMP seq no wrap error causing circuit to drop
        }
    }
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
			ans = &ddcmpSock->socket;
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
		ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;
        ddcmpCircuit->circuit->waitHandle = sock->waitHandle;
        RegisterEventHandler(ddcmpCircuit->circuit->waitHandle, ddcmpCircuit->circuit, ddcmpCircuit->circuit->WaitEventHandler);
        Log(LogDdcmpInit, LogInfo, "Starting DDCMP line %s\n", ddcmpCircuit->circuit->name);
        DdcmpStart(&ddcmpSock->line);
	}
}

static void TcpDisconnectCallback(socket_t *sock)
{
    ddcmp_circuit_t *ddcmpCircuit = FindCircuit(sock);
    if (ddcmpCircuit != NULL)
    {
		ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;
        DdcmpHalt(&ddcmpSock->line);
        StopTimerIfRunning(ddcmpCircuit);
        DeregisterEventHandler(ddcmpCircuit->circuit->waitHandle);
        Log(LogDdcmpInit, LogInfo, "DDCMP line %s has been closed\n", ddcmpCircuit->circuit->name);
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

static void HandleHelloAndTestTimer(rtimer_t *timer, char *name, void *context)
{
	packet_t *packet;
	circuit_t *circuit = (circuit_t *)context;
	Log(LogDdcmpInit, LogInfo, "Sending Hello And Test on %s\n", circuit->name);
	packet = CreateHelloAndTest(nodeInfo.address);
	circuit->WritePacket(circuit, NULL, NULL, packet);
}

static void StopTimerIfRunning(ddcmp_circuit_t *ddcmpCircuit)
{
    if (ddcmpCircuit->helloTimer != NULL)
    {
        StopTimer(ddcmpCircuit->helloTimer);
        ddcmpCircuit->helloTimer = NULL;
    }
}

