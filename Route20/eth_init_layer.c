/* eth_init_layer.c: Ethernet initialization layer
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

#include <stdlib.h>
#include "constants.h"
#include "decnet.h"
#include "eth_init_layer.h"
#include "timer.h"
#include "adjacency.h"
#include "platform.h"
#include "circuit.h"
#include "eth_circuit.h"
#include "messages.h"

static circuit_t * ethCircuits[NC];
static int ethCircuitCount;

typedef struct
{
	circuit_t *circuit;
	time_t lastUpdate;
	int couldBeDesignatedRouter;
} check_designated_router_t;

static int drDelayExpired;
static time_t startTime;
static void HandleDesignatedRouterTimer(rtimer_t *timer, char *name, void *context);
static void HandleDesignatedRouterHelloTimer(rtimer_t *timer, char *name, void *context);
static int CheckDesignatedRouterCallback(adjacency_t *adjacency, void *context);
static void HandleLineNotifyStateChange(line_t *line);

int EthInitLayerStart(circuit_t circuits[], int circuitCount)
{
    int ans = 1;
	int i;

	for(i = 1; i <= circuitCount; i++)
	{
		if (circuits[i].circuitType == EthernetCircuit)
		{
            circuit_t *circuit = &circuits[i];
            line_t *line = GetLineFromCircuit(circuit);

            line->LineNotifyStateChange = HandleLineNotifyStateChange;

            ans &= circuit->Start(circuit); // TODO: should start lines, when lines open then should open circuit.
		    ethCircuits[ethCircuitCount++] = circuit;
		}
	}

	time(&startTime);
	drDelayExpired = 0;
	if (ans && ethCircuitCount > 0)
    {
        CreateTimer("DesignatedRouter", startTime + DRDELAY, 0, NULL, HandleDesignatedRouterTimer);
    }

    return ans;
}

void EthInitLayerStop(void)
{
	int i;
	packet_t *packet;

	StopAllAdjacencies(EthernetCircuit);

	for(i = 0; i < ethCircuitCount; i++)
	{
		circuit_t *circuit = ethCircuits[i];
	    Log(LogEthInit, LogVerbose, "Sending Ethernet Hello to stop all adjacencies to All Routers %s\n", circuit->name);
		packet = CreateEthernetHello(nodeInfo.address);
		circuit->WritePacket(circuit, &nodeInfo.address, &AllRoutersAddress, packet, 1);

		if (nodeInfo.level == 2)
		{
			Log(LogEthInit, LogVerbose, "Sending Ethernet Hello to stop all adjacencies to All Level 2 Routers %s\n", circuit->name);
			circuit->WritePacket(circuit, &nodeInfo.address, &AllLevel2RoutersAddress, packet, 1);
		}

		CircuitDown(circuit);
		circuit->Stop(circuit);
	}
}

void EthInitLayerCircuitUpComplete(circuit_ptr circuit)
{
    CircuitUpComplete(circuit);
}

void EthInitLayerCircuitDownComplete(circuit_ptr circuit)
{
    CircuitDownComplete(circuit);
}

void EthInitLayerAdjacencyUpComplete(adjacency_t *adjacency)
{
    AdjacencyUpComplete(adjacency);
}

void EthInitLayerAdjacencyDownComplete(adjacency_t *adjacency)
{
    AdjacencyDownComplete(adjacency);
}

void EthInitCheckDesignatedRouter(void)
{
	int i;
	check_designated_router_t checkdr;
	eth_circuit_t *ethCircuit;

	for(i = 0; i < ethCircuitCount; i++)
	{
		checkdr.circuit = ethCircuits[i];
		checkdr.lastUpdate = 0;
		checkdr.couldBeDesignatedRouter = 1;

		ethCircuit = (eth_circuit_t *)checkdr.circuit->context;

		ProcessRouterAdjacencies(CheckDesignatedRouterCallback, &checkdr);

		if (drDelayExpired && ethCircuit->isDesignatedRouter != checkdr.couldBeDesignatedRouter)
		{
			ethCircuit->isDesignatedRouter = checkdr.couldBeDesignatedRouter;

			if (ethCircuit->isDesignatedRouter)
			{
				time_t now;

				Log(LogEthInit, LogInfo, "Now the designated router on circuit %s\n", checkdr.circuit->name);
				time(&now);

    			CreateTimer("AllEndNodesHello", now, T3, checkdr.circuit, HandleDesignatedRouterHelloTimer);
			}
			else
			{
				Log(LogEthInit, LogInfo, "No longer the designated router on circuit %s\n", checkdr.circuit->name);
			}
		}
	}
}

static void HandleDesignatedRouterTimer(rtimer_t *timer, char *name, void *context)
{
	drDelayExpired = 1;
	EthInitCheckDesignatedRouter();
}

static void HandleDesignatedRouterHelloTimer(rtimer_t * timer, char *name, void *context)
{
	packet_t *packet;
	time_t now;
	circuit_t *circuit = (circuit_t *)context;
	eth_circuit_t *ethCircuit = (eth_circuit_t *)circuit->context;

	if (ethCircuit->isDesignatedRouter)
	{
		time(&now);
	    Log(LogEthInit, LogVerbose, "Sending Ethernet Hello to All End Nodes %s\n", circuit->name);
		packet = CreateEthernetHello(nodeInfo.address);
		circuit->WritePacket(circuit, &nodeInfo.address, &AllEndNodesAddress, packet, 1);
	}
	else
	{
		StopTimer(timer);
	}
}

static int CheckDesignatedRouterCallback(adjacency_t *adjacency, void *context)
{
	check_designated_router_t *checkdr = (check_designated_router_t *)context;

	if (adjacency->circuit == checkdr->circuit)
	{
		if (adjacency->lastHeardFrom > checkdr->lastUpdate)
		{
			checkdr->lastUpdate = adjacency->lastHeardFrom;
		}

		if (adjacency->id.area == nodeInfo.address.area)
		{
			if (adjacency->priority < nodeInfo.priority)
			{
				checkdr->couldBeDesignatedRouter = 1;
			}
			else if (adjacency->priority == nodeInfo.priority)
			{
				checkdr->couldBeDesignatedRouter = adjacency->id.node < nodeInfo.address.node;
			}
			else
			{
				checkdr->couldBeDesignatedRouter = 0;
			}
		}
	}

	return 1;
}

static void HandleLineNotifyStateChange(line_t *line)
{
    circuit_t *circuit = GetCircuitFromLine(line);
    if (line->lineState == LineStateUp)
    {
        QueueImmediate(circuit, (void (*)(void *))CircuitUp);
    }
    else
    {
        QueueImmediate(circuit, (void (*)(void *))CircuitDown);
    }
}


