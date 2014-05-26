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
#include <pcap.h>
#include <pcap-bpf.h>
#include "constants.h"
#include "platform.h"
#include "node.h"
#include "circuit.h"
#include "eth_circuit.h"
#include "ddcmp_circuit.h"

#if defined(WIN32)
#include <Windows.h>
#include <WinSock2.h>
#endif

static void (*stateChangeCallback)(circuit_t *circuit);
static int FirstLevel1Node();

void SetCircuitStateChangeCallback(void (*callback)(circuit_t *circuit))
{
	stateChangeCallback = callback;
}

void CircuitUp(circuit_t *circuit)
{
	circuit->state = CircuitStateUp;
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
	stateChangeCallback(circuit);
}

void CircuitDown(circuit_t *circuit)
{
	Log(LogCircuit, LogInfo, "Circuit %s down\n", circuit->name);
	circuit->state = CircuitStateOff;
	stateChangeCallback(circuit);
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
	eth_circuit_t *context = EthCircuitCreatePcap(circuit);

	circuit->name = (char *)malloc(strlen(name)+1);
	strcpy(circuit->name, name);
	circuit->context = (void *)context;
	circuit->circuitType = EthernetCircuit;
	circuit->state = CircuitStateOff;
	circuit->cost = cost;
	circuit->nextLevel1Node = FirstLevel1Node();

	circuit->Open = EthCircuitOpen;
	circuit->Start = EthCircuitStart;
	circuit->ReadPacket = EthCircuitReadPacket;
	circuit->WritePacket = EthCircuitWritePacket;
	circuit->Close = EthCircuitClose;
	circuit->Reject = NULL;
	circuit->WaitEventHandler = waitEventHandler;
}

void CircuitCreateEthernetSocket(circuit_ptr circuit, char *name, uint16 receivePort, uint16 destinationPort, int cost, void (*waitEventHandler)(void *context))
{
	eth_circuit_t *context = EthCircuitCreateSocket(circuit, receivePort, name, destinationPort);

	circuit->name = (char *)malloc(strlen(name)+1);
	strcpy(circuit->name, name);
	circuit->context = (void *)context;
	circuit->circuitType = EthernetCircuit;
	circuit->state = CircuitStateOff;
	circuit->cost = cost;
	circuit->nextLevel1Node = FirstLevel1Node();

    circuit->Open = EthCircuitOpen;
	circuit->Start = EthCircuitStart;
	circuit->ReadPacket = EthCircuitReadPacket;
	circuit->WritePacket = EthCircuitWritePacket;
	circuit->Close = EthCircuitClose;
	circuit->Reject = NULL;
	circuit->WaitEventHandler = waitEventHandler;
}

void CircuitCreateDdcmpSocket(circuit_ptr circuit, char *name, int cost, void (*waitEventHandler)(void *context))
{
	ddcmp_circuit_t *context = DdcmpCircuitCreateSocket(circuit, name);

	circuit->name = (char *)malloc(strlen(name)+1);
	strcpy(circuit->name, name);
	circuit->context = (void *)context;
	circuit->circuitType = DDCMPCircuit;
	circuit->state = CircuitStateOff;
	circuit->cost = cost;
	circuit->nextLevel1Node = FirstLevel1Node();

    circuit->Open = DdcmpCircuitOpen;
	circuit->Start = DdcmpCircuitStart;
	circuit->ReadPacket = DdcmpCircuitReadPacket;
	circuit->WritePacket = DdcmpCircuitWritePacket;
	circuit->Close = DdcmpCircuitClose;
	circuit->Reject = DdcmpCircuitReject;
	circuit->WaitEventHandler = waitEventHandler;
}

int  IsBroadcastCircuit(circuit_ptr circuit)
{
	return circuit->circuitType == EthernetCircuit;
}

static int FirstLevel1Node()
{
	int ans = 0;
	/* make sure this node is the first level 1 node reported so other nodes see it as reachable quickly. If we start at 0 and
	   this node is at 1023 it will be in the last packet in the burst to be sent and may get lost by recipients until after a
	   few cycles of sending level 1 updates. */
	ans = (nodeInfo.address.node / LEVEL1_BATCH_SIZE) * LEVEL1_BATCH_SIZE;
	return ans;
}



