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

#if !defined(ETH_CIRCUIT_H)

#define ETHERTYPE_DECnet 0x6003
#define ETHERTYPE_LAT 0x6004
#define ETHERTYPE_MOPDL 0x6001
#define ETHERTYPE_MOPRC 0x6002
#define ETHERTYPE_LOOPBACK 0x9000

typedef struct eth_circuit *eth_circuit_ptr;

typedef struct eth_circuit
{
	circuit_t *circuit;
	void      *context;
	int        isDesignatedRouter;

	int (*Open)(eth_circuit_ptr circuit);
	int (*Start)(eth_circuit_ptr circuit);
	packet_t *(*ReadPacket)(eth_circuit_ptr circuit);
	int (*WritePacket)(eth_circuit_ptr circuit, packet_t *);
	void (*Close)(eth_circuit_ptr circuit);
} eth_circuit_t;

eth_circuit_ptr EthCircuitCreatePcap(circuit_t *circuit);
eth_circuit_ptr EthCircuitCreateSocket(circuit_t *circuit, uint16 receivePort, char *destinationHostName, uint16 destinationPort);

int EthCircuitOpen(circuit_ptr circuit);
int EthCircuitStart(circuit_ptr circuit);
packet_t *EthCircuitReadPacket(circuit_ptr circuit);
int EthCircuitWritePacket(circuit_ptr circuit, decnet_address_t *from, decnet_address_t *to, packet_t *);
void EthCircuitClose(circuit_ptr circuit);

#define ETH_CIRCUIT_H
#endif
