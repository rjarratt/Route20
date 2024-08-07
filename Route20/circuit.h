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
#include "line.h"

extern int numCircuits;
extern int numEthPcapCircuits;
extern int numEthSockCircuits;
extern int numDdcmpCircuits;

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
	long          nonDecnetPacketsReceived;
} circuit_stats_t;

typedef struct circuit
{
	int                slot;
	char              *name;
	void              *context;
    line_t            *line;
	CircuitType        circuitType;
	CircuitState       state;
	struct init_layer *initLayer;
	decnet_address_t   adjacentNode; /* valid for non-broadcast circuits only */
	rtimer_t*          helloTimer;
	rtimer_t*          level2HelloTimer;
	int                cost;
	int                startLevel1Node; /* used to stagger the starting point for Level 1 updates to satisfy the requirements of section 4.8.1 to mitigate packet loss */
	circuit_stats_t    stats;

	int (*Start)(circuit_ptr circuit);
	void (*Up)(circuit_ptr circuit);
	void (*Down)(circuit_ptr circuit);
	packet_t *(*ReadPacket)(circuit_ptr circuit);
	int (*WritePacket)(circuit_ptr circuit, decnet_address_t *from, decnet_address_t *to, packet_t *, int isHello);
	void (*Stop)(circuit_ptr circuit);
	void (*Reject)(circuit_ptr circuit);
	void (*WaitEventHandler)(void *context);
} circuit_t;

void SetCircuitStateChangeCallback(void (*callback)(circuit_t *circuit));
void CircuitUp(circuit_t *circuit);
void CircuitUpComplete(circuit_t *circuit);
void CircuitDown(circuit_t *circuit);
void CircuitDownComplete(circuit_t *circuit);
void CircuitReject(circuit_t *circuit);
void CircuitCreateEthernetPcap(circuit_ptr circuit, char *name, int cost, void (*waitEventHandler)(void *context));
void CircuitCreateEthernetSocket(circuit_ptr circuit, char *name, uint16 receivePort, uint16 destinationPort, int cost, void (*waitEventHandler)(void *context));
void CircuitCreateDdcmpSocket(circuit_ptr circuit, char *name, uint16 port, int cost, int connectPoll, void (*waitEventHandler)(void *context));
line_t *GetLineFromCircuit(circuit_t *circuit);
int  IsBroadcastCircuit(circuit_ptr circuit);
circuit_t *GetCircuitFromLine(line_t *line);

#define CIRCUIT_H
#endif
