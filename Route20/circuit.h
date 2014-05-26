/* circuit.h: DECnet circuit
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

#include "packet.h"
#include "decnet.h"
#include "timer.h"

#if !defined(CIRCUIT_H)

typedef struct circuit *circuit_ptr;

typedef enum
{
	CircuitStateOff,
	CircuitStateUp
} CircuitState;

typedef enum
{
	EthernetCircuit,
	X25Circuit,
	DDCMPCircuit
} CircuitType;

typedef struct circuit_stats
{
	long          validRawPacketsReceived;
	long          decnetPacketsReceived;
	long          decnetToThisNodePacketsReceived;
	long          packetsSent;
	long          loopbackPacketsReceived;
	long          invalidPacketsReceived;
} circuit_stats_t;

typedef struct circuit
{
	int               slot;
	char             *name;
	void             *context;
	int               waitHandle;
	CircuitType       circuitType;
	CircuitState      state;
	decnet_address_t  adjacentNode; /* valid for non-broadcast circuits only */
	rtimer_t *        helloTimer;
	int               cost;
	int               nextLevel1Node;
	circuit_stats_t   stats;

	int (*Open)(circuit_ptr circuit);
	int (*Up)(circuit_ptr circuit);
	void (*Down)(circuit_ptr circuit);
	packet_t *(*ReadPacket)(circuit_ptr circuit);
	int (*WritePacket)(circuit_ptr circuit, decnet_address_t *from, decnet_address_t *to, packet_t *);
	void (*Close)(circuit_ptr circuit);
	void (*Reject)(circuit_ptr circuit);
	void (*WaitEventHandler)(void *context);
} circuit_t;

void SetCircuitStateChangeCallback(void (*callback)(circuit_t *circuit));
void CircuitUp(circuit_t *circuit);
void CircuitDown(circuit_t *circuit);
void CircuitReject(circuit_t *circuit);
void CircuitCreateEthernetPcap(circuit_ptr circuit, char *name, int cost, void (*waitEventHandler)(void *context));
void CircuitCreateEthernetSocket(circuit_ptr circuit, char *name, uint16 receivePort, uint16 destinationPort, int cost, void (*waitEventHandler)(void *context));
void CircuitCreateDdcmpSocket(circuit_ptr circuit, char *name, int cost, void (*waitEventHandler)(void *context));
int  IsBroadcastCircuit(circuit_ptr circuit);

#define CIRCUIT_H
#endif
