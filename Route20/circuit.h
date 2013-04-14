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

#if !defined(CIRCUIT_H)

typedef struct circuit *circuit_ptr;

typedef enum
{
	CircuitOff,
	CircuitUp
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
	int             slot;
	char           *name;
	void           *context;
	int             waitHandle;
	CircuitType     circuitType;
	CircuitState    state;
	int             cost;
	int             nextLevel1Node;
	circuit_stats_t stats;

	int (*Open)(circuit_ptr circuit);
	int (*Start)(circuit_ptr circuit);
	packet_t *(*ReadPacket)(circuit_ptr circuit);
	int (*WritePacket)(circuit_ptr circuit, decnet_address_t *from, decnet_address_t *to, packet_t *);
	void (*Close)(circuit_ptr circuit);
} circuit_t;

void SetCircuitStateChangeCallback(void (*callback)(circuit_t *circuit));
void CircuitStateChange(circuit_t *circuit);
void CircuitCreateEthernetPcap(circuit_ptr circuit, char *name, int cost);
void CircuitCreateEthernetSocket(circuit_ptr circuit, char *name, uint16 receivePort, uint16 destinationPort, int cost);
int  IsBroadcastCircuit(circuit_ptr circuit);

#define CIRCUIT_H
#endif
