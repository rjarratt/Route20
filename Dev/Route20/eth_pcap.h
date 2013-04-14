/* eth_pcap.h: Ethernet PCAP interface
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
#include "eth_decnet.h"
#include "eth_circuit.h"

#if !defined(ETH_PCAP_H)

typedef struct pcap pcap_t;

typedef struct
{
	pcap_t *pcap;
//	decnet_eth_address_t thisNode;
} eth_pcap_t;

int EthPcapOpen(eth_circuit_t *ethCircuit);
packet_t *EthPcapReadPacket(eth_circuit_t *ethCircuit);
int EthPcapWritePacket(eth_circuit_t *, packet_t *);
void EthPcapClose(eth_circuit_t *ethCircuit);

#define ETH_PCAP_H
#endif
