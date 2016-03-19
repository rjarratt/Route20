/* circuit.c: DECnet circuit
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
#include <string.h>
#include "platform.h"
#include "constants.h"
#include "node.h"
#include "circuit.h"
#include "eth_circuit.h"
#include "ddcmp_circuit.h"

int numEthPcapCircuits = 0;
int numEthSockCircuits = 0;
int numDdcmpCircuits = 0;

static void (*stateChangeCallback)(circuit_t *circuit);
static int FirstLevel1Node(void);

// TODO: abstract properly by putting common functions for read/write etc which do logging, stats etc, then delegate to actual circuit/line implementations.

void SetCircuitStateChangeCallback(void (*callback)(circuit_t *circuit))
{
	stateChangeCallback = callback;
}

void CircuitUp(circuit_t *circuit)
{
	Log(LogCircuit, LogInfo, "Circuit %s is coming up\n", circuit->name);
	circuit->state = CircuitStateUp;
	stateChangeCallback(circuit);
}

void CircuitUpComplete(circuit_t *circuit)
{
	circuit->Up(circuit);
    if (circuit->circuitType == EthernetCircuit)
    {
	    Log(LogCircuit, LogInfo, "Circuit %s up\n", circuit->name);
    }
    else
    {
	    Log(LogCircuit, LogInfo, "Circuit %s up, adjacent node = ", circuit->name);
        LogDecnetAddress(LogCircuit, LogInfo, &circuit->adjacentNode);
	    Log(LogCircuit, LogInfo, "\n");
    }
}

void CircuitDown(circuit_t *circuit)
{
	Log(LogCircuit, LogWarning, "Circuit %s going down\n", circuit->name);
	circuit->state = CircuitStateOff;
	stateChangeCallback(circuit);
}

void CircuitDownComplete(circuit_t *circuit)
{
	circuit->Down(circuit);
	Log(LogCircuit, LogInfo, "Circuit %s down\n", circuit->name);
}

void CircuitReject(circuit_t *circuit)
{
	if (circuit->Reject != NULL)
	{
	    Log(LogCircuit, LogInfo, "Circuit %s rejected\n", circuit->name);
		circuit->Reject(circuit);
	}
	else
	{
		CircuitDown(circuit);
	}
}

void CircuitCreateEthernetPcap(circuit_ptr circuit, char *name, int cost, void (*waitEventHandler)(void *context))
{
    circuit->name = (char *)malloc(strlen(name)+1);
	strcpy(circuit->name, name);
	circuit->context = (void *)EthCircuitCreatePcap(circuit);
	circuit->circuitType = EthernetCircuit;
	circuit->state = CircuitStateOff;
	circuit->cost = cost;
	circuit->nextLevel1Node = FirstLevel1Node();

	circuit->Start = EthCircuitStart;
	circuit->Up = EthCircuitUp;
	circuit->Down = EthCircuitDown;
	circuit->ReadPacket = EthCircuitReadPacket;
	circuit->WritePacket = EthCircuitWritePacket;
	circuit->Stop = EthCircuitStop;
	circuit->Reject = NULL;
	circuit->WaitEventHandler = waitEventHandler;

    numEthPcapCircuits++;
}

void CircuitCreateEthernetSocket(circuit_ptr circuit, char *name, uint16 receivePort, uint16 destinationPort, int cost, void (*waitEventHandler)(void *context))
{
	circuit->name = (char *)malloc(strlen(name)+1);
	strcpy(circuit->name, name);
	circuit->context = (void *)EthCircuitCreateSocket(circuit, receivePort, name, destinationPort);
	circuit->circuitType = EthernetCircuit;
	circuit->state = CircuitStateOff;
	circuit->cost = cost;
	circuit->nextLevel1Node = FirstLevel1Node();

    circuit->Start = EthCircuitStart;
	circuit->Up = EthCircuitUp;
	circuit->Down = EthCircuitDown;
	circuit->ReadPacket = EthCircuitReadPacket;
	circuit->WritePacket = EthCircuitWritePacket;
	circuit->Stop = EthCircuitStop;
	circuit->Reject = NULL;
	circuit->WaitEventHandler = waitEventHandler;

    numEthSockCircuits++;
}

void CircuitCreateDdcmpSocket(circuit_ptr circuit, char *name, uint16 port, int cost, int connectPoll, void (*waitEventHandler)(void *context))
{
	circuit->name = (char *)malloc(strlen(name)+1);
	strcpy(circuit->name, name);
	circuit->context = (void *)DdcmpCircuitCreateSocket(circuit, name, port, connectPoll);
	circuit->circuitType = DDCMPCircuit;
	circuit->state = CircuitStateOff;
	circuit->cost = cost;
	circuit->nextLevel1Node = FirstLevel1Node();

    circuit->Start = DdcmpCircuitStart;
	circuit->Up = DdcmpCircuitUp;
	circuit->Down = DdcmpCircuitDown;
	circuit->ReadPacket = DdcmpCircuitReadPacket;
	circuit->WritePacket = DdcmpCircuitWritePacket;
	circuit->Stop = DdcmpCircuitStop;
	circuit->Reject = DdcmpCircuitReject;
	circuit->WaitEventHandler = waitEventHandler;

    numDdcmpCircuits++;
}

line_t *GetLineFromCircuit(circuit_t *circuit)
{
    return circuit->line;
}

int  IsBroadcastCircuit(circuit_ptr circuit)
{
	return circuit->circuitType == EthernetCircuit;
}

circuit_t *GetCircuitFromLine(line_t *line)
{
    return (circuit_t*)line->notifyContext;
}

static int FirstLevel1Node(void)
{
	int ans = 0;
	/* make sure this node is the first level 1 node reported so other nodes see it as reachable quickly. If we start at 0 and
	   this node is at 1023 it will be in the last packet in the burst to be sent and may get lost by recipients until after a
	   few cycles of sending level 1 updates. */
	ans = (nodeInfo.address.node / LEVEL1_BATCH_SIZE) * LEVEL1_BATCH_SIZE;
	return ans;
}



