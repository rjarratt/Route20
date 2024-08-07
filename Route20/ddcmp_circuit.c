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
#include "line.h"
#include "circuit.h"
#include "ddcmp_circuit.h"
#include "ddcmp_init_layer.h"
#include "ddcmp_sock_line.h"
#include "timer.h"
#include "messages.h"

static void HandleLineNotifyData(line_t *line);
static void DdcmpCircuitRejectionCompleteCallback(void *context);
static void HandleHelloAndTestTimer(rtimer_t *timer, char *name, void *context);
static void StopTimerIfRunning(ddcmp_circuit_t *ddcmpCircuit);
static void StartTimer(ddcmp_circuit_t *ddcmpCircuit);

ddcmp_circuit_t *DdcmpCircuitCreateSocket(circuit_t *circuit, char *destinationHostName, uint16 destinationPort, int connectPoll)
{
	ddcmp_circuit_t *ans = (ddcmp_circuit_t *)calloc(1, sizeof(ddcmp_circuit_t));
	line_t *line = (line_t *)malloc(sizeof(line_t));
    LineCreateDdcmpSocket(line, circuit->name, destinationHostName, destinationPort, connectPoll, circuit, HandleLineNotifyData);

	ans->circuit = circuit;
	circuit->line = line;
    ans->state = DdcmpInitHAState;

	return ans;
}

int DdcmpCircuitStart(circuit_t *circuit)
{
    line_t *line = GetLineFromCircuit(circuit);
	return line->LineStart(line);
}

void DdcmpCircuitUp(circuit_t *circuit)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
	StartTimer(ddcmpCircuit);
}

void DdcmpCircuitDown(circuit_ptr circuit)
{
	ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
	StopTimerIfRunning(ddcmpCircuit);
}

packet_t *DdcmpCircuitReadPacket(circuit_t *circuit)
{
    line_t *line = GetLineFromCircuit(circuit);
	packet_t *ans;

	ans = line->LineReadPacket(line);
	if (ans != NULL)
	{
		circuit->stats.validRawPacketsReceived++;
		if (!ans->IsDecnet(ans))
		{
			ans = NULL;
		}
		else
		{
            memcpy(&ans->from, &circuit->adjacentNode, sizeof(decnet_address_t));
			circuit->stats.decnetPacketsReceived++;
			circuit->stats.decnetToThisNodePacketsReceived++;
		}
	}

	return ans;
}

int DdcmpCircuitWritePacket(circuit_t *circuit, decnet_address_t *from, decnet_address_t *to, packet_t *packet, int isHello)
{
	int ans = 0;
    line_t *line = GetLineFromCircuit(circuit);
    ans = line->LineWritePacket(line, packet);
	circuit->stats.packetsSent++;
	if (circuit->state == CircuitStateUp && !isHello)
	{
	    ResetTimer(circuit->helloTimer); /* no need to send Hello and Test if we have recently sent a message */
	}

	return ans;
}

void DdcmpCircuitStop(circuit_t *circuit)
{
    // TODO: Lot of duplication now in these functions
    line_t *line = GetLineFromCircuit(circuit);
	line->LineStop(line);
}

void DdcmpCircuitReject(circuit_ptr circuit)
{
    QueueImmediate(circuit, DdcmpCircuitRejectionCompleteCallback);
}

ddcmp_circuit_t *GetDdcmpCircuitForLine(line_t *line)
{
    circuit_t *circuit = GetCircuitFromLine(line);
    ddcmp_circuit_t *ddcmpCircuit = (ddcmp_circuit_t *)circuit->context;
    return ddcmpCircuit;
}

static void HandleLineNotifyData(line_t *line)
{
    circuit_t *circuit = GetCircuitFromLine(line);
    circuit->WaitEventHandler(circuit);
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
	circuit->WritePacket(circuit, NULL, NULL, packet, 1);
}

static void StopTimerIfRunning(ddcmp_circuit_t *ddcmpCircuit)
{
    if (ddcmpCircuit->circuit->helloTimer != NULL)
    {
        StopTimer(ddcmpCircuit->circuit->helloTimer);
        ddcmpCircuit->circuit->helloTimer = NULL;
    }
}

static void StartTimer(ddcmp_circuit_t *ddcmpCircuit)
{
    time_t now;
    time(&now);
    StopTimerIfRunning(ddcmpCircuit);
    ddcmpCircuit->circuit->helloTimer = CreateTimer("HelloAndTest", now, T3, ddcmpCircuit->circuit, HandleHelloAndTestTimer);
}
