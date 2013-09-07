/* ddcmp_circuit.h: DDCMO circuit
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

#include "packet.h"
#include "timer.h"
#include "circuit.h"

#if !defined(DDCMP_CIRCUIT_H)

typedef enum
{
    DdcmpInitRUState,
    DdcmpInitCRState,
    DdcmpInitDSState,
    DdcmpInitRIState,
    DdcmpInitRVState,
    DdcmpInitRCState,
    DdcmpInitOFState,
    DdcmpInitHAState
} DdcmpInitState;

typedef struct ddcmp_circuit *ddcmp_circuit_ptr;

typedef struct ddcmp_circuit
{
	circuit_t      *circuit;
	void           *context;
	rtimer_t       *recallTimer;
    rtimer_t       *helloTimer; // TODO: consider if this should be moved to higher level timer so can use for ethernet ones too
    DdcmpInitState  state;

	int (*Open)(ddcmp_circuit_ptr circuit);
	int (*Start)(ddcmp_circuit_ptr circuit);
	packet_t *(*ReadPacket)(ddcmp_circuit_ptr circuit);
	int (*WritePacket)(ddcmp_circuit_ptr circuit, packet_t *);
	void (*Close)(ddcmp_circuit_ptr circuit);
} ddcmp_circuit_t;

ddcmp_circuit_ptr DdcmpCircuitCreateSocket(circuit_t *circuit, char *destinationHostName);

int DdcmpCircuitOpen(circuit_ptr circuit);
int DdcmpCircuitStart(circuit_ptr circuit);
packet_t *DdcmpCircuitReadPacket(circuit_ptr circuit);
int DdcmpCircuitWritePacket(circuit_ptr circuit, decnet_address_t *from, decnet_address_t *to, packet_t *);
void DdcmpCircuitClose(circuit_ptr circuit);

#define DDCMP_CIRCUIT_H
#endif
