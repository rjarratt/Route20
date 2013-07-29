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

static circuit_t * ddcmpCircuits[NC];
static int ddcmpCircuitCount;

static socket_t * TcpAcceptCallback(sockaddr_t *receivedFrom);
static void TcpConnectCallback(socket_t *sock);

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

void DdcmpInitProcessPhaseIINodeInitializationMessage(circuit_t *circuit, node_init_phaseii_t *msg)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
	ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;
	packet_t *pkt;
	if (msg->requests & 0x01)
	{
		// TODO: implement verification message required
	}

	pkt = CreateNodeInitPhaseIIMessage(nodeInfo.address);
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
	int i;

	for(i = 0; i < ddcmpCircuitCount; i++)
	{
		ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)ddcmpCircuits[i]->context;
		ddcmp_sock_t *ddcmpSock = (ddcmp_sock_t *)ddcmpCircuit->context;

		if (sock == &ddcmpSock->socket)
		{
			ddcmpCircuit->circuit->waitHandle = sock->waitHandle;
			RegisterEventHandler(ddcmpCircuit->circuit->waitHandle, ddcmpCircuit->circuit, ddcmpCircuit->circuit->WaitEventHandler);
			DdcmpStart(&ddcmpSock->line);
			break;
		}
	}
}
