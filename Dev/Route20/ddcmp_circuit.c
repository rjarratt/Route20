/* ddcmp_circuit.c: DDCMP circuit
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

#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "platform.h"
#include "circuit.h"
#include "ddcmp_circuit.h"
#include "ddcmp_init_layer.h"
#include "ddcmp_sock.h"
#include "timer.h"
#include "messages.h"

static void DdcmpCircuitRejectionCompleteCallback(void *context);
static void HandleHelloAndTestTimer(rtimer_t *timer, char *name, void *context);
static void StopTimerIfRunning(ddcmp_circuit_t *ddcmpCircuit);
static void StartTimer(ddcmp_circuit_t *ddcmpCircuit);

ddcmp_circuit_t *DdcmpCircuitCreateSocket(circuit_t *circuit, char *destinationHostName)
{
	ddcmp_circuit_t *ans = (ddcmp_circuit_t *)calloc(1, sizeof(ddcmp_circuit_t));
	ddcmp_sock_t *context = (ddcmp_sock_t *)calloc(1, sizeof(ddcmp_sock_t));
	context->socket.socket = INVALID_SOCKET;
	
    context->ddcmpCircuit = ans;
	context->destinationHostName = (char *)calloc(1, strlen(destinationHostName) + 1);
	strcpy(context->destinationHostName, destinationHostName);

	ans->circuit = circuit;
	ans->context = context;
    ans->state = DdcmpInitHAState;

	ans->Open = DdcmpSockOpen;
	ans->ReadPacket = DdcmpSockReadPacket;
	ans->WritePacket = DdcmpSockWritePacket;
	ans->Close = DdcmpSockClose;

	return ans;
}

int DdcmpCircuitOpen(circuit_t *circuit)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
	return ddcmpCircuit->Open(ddcmpCircuit);
}

int DdcmpCircuitUp(circuit_t *circuit)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
	StartTimer(ddcmpCircuit);
	return 1;
}

void DdcmpCircuitDown(circuit_ptr circuit)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
	StopTimerIfRunning(ddcmpCircuit);
}

packet_t *DdcmpCircuitReadPacket(circuit_t *circuit)
{
	ddcmp_circuit_t *context = (ddcmp_circuit_t *)circuit->context;
	packet_t *ans;

	ans = context->ReadPacket(context);
	if (ans != NULL)
	{
		circuit->stats.validRawPacketsReceived++;
		// TODO: Decide if the following commented code is needed.
		//if (!ans->IsDecnet(ans))
		//{
		//	ans = NULL;
		//}
		//else
		//{
		//	circuit->stats.decnetPacketsReceived++;
		//	if (!IsAddressedToThisNode(ans))
		//	{
		//		ans = NULL;
		//	}
		//	else
		//	{
		//		circuit->stats.decnetToThisNodePacketsReceived++;
		//	}
		//}
	}

	return ans;
}

int DdcmpCircuitWritePacket(circuit_t *circuit, decnet_address_t *from, decnet_address_t *to, packet_t *packet)
{
	int ans = 0;
	ddcmp_circuit_t *context = (ddcmp_circuit_t *)circuit->context;
    ans = context->WritePacket(context, packet);
	circuit->stats.packetsSent++;
	return ans;
}

void DdcmpCircuitClose(circuit_t *circuit)
{
	ddcmp_circuit_t *context = (ddcmp_circuit_t *)circuit->context;
	context->Close(context);
}

void DdcmpCircuitReject(circuit_ptr circuit)
{
    QueueImmediate(circuit, DdcmpCircuitRejectionCompleteCallback);
}

static void DdcmpCircuitRejectionCompleteCallback(void *context)
{
    DdcmpInitProcessCircuitRejectComplete((circuit_ptr)context);
}

static void HandleHelloAndTestTimer(rtimer_t *timer, char *name, void *context)
{
	packet_t *packet;
	circuit_t *circuit = (circuit_t *)context;
	Log(LogDdcmpInit, LogDetail, "Sending Hello And Test on %s\n", circuit->name);
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

static void StartTimer(ddcmp_circuit_t *ddcmpCircuit)
{
    time_t now;
    time(&now);
    StopTimerIfRunning(ddcmpCircuit);
    ddcmpCircuit->helloTimer = CreateTimer("HelloAndTest", now, T3, ddcmpCircuit->circuit, HandleHelloAndTestTimer);
}
