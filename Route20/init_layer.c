/* init_layer.h: Initialization layer
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

#include "init_layer.h"
#include "eth_init_layer.h"
#include "ddcmp_init_layer.h"

init_layer_t *CreateEthernetInitializationSublayer(void)
{
	static init_layer_t ethernetInitLayer;
	ethernetInitLayer.Start = EthInitLayerStart;
	ethernetInitLayer.Stop = EthInitLayerStop;
	ethernetInitLayer.CircuitUpComplete = EthInitLayerCircuitUpComplete;
	ethernetInitLayer.CircuitDownComplete = EthInitLayerCircuitDownComplete;
	ethernetInitLayer.AdjacencyUpComplete = EthInitLayerAdjacencyUpComplete;
	ethernetInitLayer.AdjacencyDownComplete = EthInitLayerAdjacencyDownComplete;
	return &ethernetInitLayer;
}

init_layer_t *CreateDdcmpInitializationSublayer(void)
{
	static init_layer_t ddcmpInitLayer;
	ddcmpInitLayer.Start = DdcmpInitLayerStart;
	ddcmpInitLayer.Stop = DdcmpInitLayerStop;
	ddcmpInitLayer.CircuitUpComplete = DdcmpInitLayerCircuitUpComplete;
	ddcmpInitLayer.CircuitDownComplete = DdcmpInitLayerCircuitDownComplete;
	ddcmpInitLayer.AdjacencyUpComplete = DdcmpInitLayerAdjacencyUpComplete;
	ddcmpInitLayer.AdjacencyDownComplete = DdcmpInitLayerAdjacencyDownComplete;
	return &ddcmpInitLayer;
}

void InitializationSublayerAssociateCircuits(circuit_t circuits[], int circuitCount, CircuitType circuitType, init_layer_t *initLayer)
{
	int i;

	for(i = 1; i <= circuitCount; i++)
	{
		if (circuits[i].circuitType == circuitType)
		{
		    circuits[i].initLayer = initLayer;
		}
	}
}

