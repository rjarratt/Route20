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
#include "circuit.h"
#include "eth_circuit.h"

#if defined(WIN32)
#include <Windows.h>
#include <WinSock2.h>
#endif

static void (*stateChangeCallback)(circuit_t *circuit);

void SetCircuitStateChangeCallback(void (*callback)(circuit_t *circuit))
{
	stateChangeCallback = callback;
}

void CircuitStateChange(circuit_t *circuit)
{
	stateChangeCallback(circuit);
}

void CircuitCreateEthernetPcap(circuit_ptr circuit, char *name, int cost)
{
	eth_circuit_t *context = EthCircuitCreatePcap(circuit);

	circuit->name = (char *)malloc(strlen(name)+1);
	strcpy(circuit->name, name);
	circuit->context = (void *)context;
	circuit->circuitType = EthernetCircuit;
	circuit->state = CircuitOff;
	circuit->cost = cost;
	circuit->nextLevel1Node = 0;

	circuit->Open = EthCircuitOpen;
	circuit->Start = EthCircuitStart;
	circuit->ReadPacket = EthCircuitReadPacket;
	circuit->WritePacket = EthCircuitWritePacket;
	circuit->Close = EthCircuitClose;
}

void CircuitCreateEthernetSocket(circuit_ptr circuit, char *name, uint16 receivePort, uint16 destinationPort, int cost)
{
	eth_circuit_t *context = EthCircuitCreateSocket(circuit, receivePort, name, destinationPort);

	circuit->name = (char *)malloc(strlen(name)+1);
	strcpy(circuit->name, name);
	circuit->context = (void *)context;
	circuit->circuitType = EthernetCircuit;
	circuit->state = CircuitOff;
	circuit->cost = cost;
	circuit->nextLevel1Node = 0;

    circuit->Open = EthCircuitOpen;
	circuit->Start = EthCircuitStart;
	circuit->ReadPacket = EthCircuitReadPacket;
	circuit->WritePacket = EthCircuitWritePacket;
	circuit->Close = EthCircuitClose;
}

int  IsBroadcastCircuit(circuit_ptr circuit)
{
	return circuit->circuitType == EthernetCircuit;
}


