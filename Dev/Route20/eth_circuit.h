/* eth_circuit.h: Ethernet circuit
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
#include "line.h"

#if !defined(ETH_CIRCUIT_H)

typedef struct eth_circuit *eth_circuit_ptr;

typedef struct eth_circuit
{
	circuit_t *circuit;
	int        isDesignatedRouter;

	int (*EthCircuitStart)(line_t *line);
	packet_t *(*EthCircuitReadPacket)(line_t *line);
	int (*EthCircuitWritePacket)(line_t *line, packet_t *);
	void (*EthCircuitStop)(line_t *line);
} eth_circuit_t;

eth_circuit_ptr EthCircuitCreatePcap(circuit_t *circuit);
eth_circuit_ptr EthCircuitCreateSocket(circuit_t *circuit, uint16 receivePort, char *destinationHostName, uint16 destinationPort);

int EthCircuitStart(circuit_ptr circuit);
void EthCircuitUp(circuit_ptr circuit);
void EthCircuitDown(circuit_ptr circuit);
packet_t *EthCircuitReadPacket(circuit_ptr circuit);
int EthCircuitWritePacket(circuit_ptr circuit, decnet_address_t *from, decnet_address_t *to, packet_t *, int isHello);
void EthCircuitStop(circuit_ptr circuit);

#define ETH_CIRCUIT_H
#endif
