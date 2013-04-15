/* update.c: DECnet Update Process (section 4.8)
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

#include <time.h>
#include "constants.h"
#include "update.h"
#include "routing_database.h"
#include "area_routing_database.h"
#include "adjacency.h"
#include "messages.h"
#include "packet.h"
#include "timer.h"
#include "platform.h"

static void ProcessUpdateTimer(rtimer_t *timer, char *name, void *context);
static void ProcessCircuitLevel1Update(circuit_t *circuit);
static void ProcessCircuitLevel2Update(circuit_t *circuit);
static int Level1UpdateRequired(int slot, int from, int count);
static int Level2UpdateRequired(int slot);

void InitialiseUpdateProcess(void)
{
	time_t now;

	time(&now);

	if (nodeInfo.level == 1 || nodeInfo.level == 2)
	{
		/* add T3 + 5 seconds to first delay to allow ethernet adjacencies to come up first so that any other nodes on the 
		   ethernet see the adjacency before receiving any routing messages */
	    CreateTimer("Update", now + T2 + T3 + 5, T2, NULL, ProcessUpdateTimer);
	}
}

static void ProcessUpdateTimer(rtimer_t *timer, char *name, void *context)
{
	int i;
	for (i = 1; i <= NC; i++)
	{
		circuit_t *circuit = &Circuits[i];
		if (circuit->state == CircuitUp)
		{
			if (nodeInfo.level == 1 || nodeInfo.level == 2)
			{
		        ProcessCircuitLevel1Update(circuit);
			}

			if (nodeInfo.level == 2)
			{
		        ProcessCircuitLevel2Update(circuit);
			}
		}
	}
}

static void ProcessCircuitLevel1Update(circuit_t *circuit)
{
	packet_t *packet;
	int startNode = circuit->nextLevel1Node;
		
	do
	{
	    if (Level1UpdateRequired(circuit->slot, circuit->nextLevel1Node, LEVEL1_BATCH_SIZE))
		{
		    Log(LogUpdate, LogVerbose, "Sending level 1 routing to %s for node range %d-%d\n", circuit->name, circuit->nextLevel1Node, circuit->nextLevel1Node + LEVEL1_BATCH_SIZE -1);
		    packet = CreateLevel1RoutingMessage(circuit->nextLevel1Node, LEVEL1_BATCH_SIZE);
			if (IsBroadcastCircuit(circuit))
			{
				circuit->WritePacket(circuit, &nodeInfo.address, &AllRoutersAddress, packet);
			}
			else
			{
				//TODO: circuit->WritePacket(circuit, &nodeInfo.address, &adjacency->id, packet);
			}
		}

		circuit->nextLevel1Node = (circuit->nextLevel1Node + LEVEL1_BATCH_SIZE) % (NN + 1);
	}
	while (circuit->nextLevel1Node != startNode);

	/* ensure next time round we start from a different point in the table, satisfies 4.8.1 requirement to mitigate packet loss */
	circuit->nextLevel1Node = (circuit->nextLevel1Node + LEVEL1_BATCH_SIZE) % (NN + 1);
}

static void ProcessCircuitLevel2Update(circuit_t *circuit)
{
	packet_t *packet;
		
	if (Level2UpdateRequired(circuit->slot))
	{
		Log(LogUpdate, LogVerbose, "Sending level 2 routing to %s\n", circuit->name);
		packet = CreateLevel2RoutingMessage();
		if (IsBroadcastCircuit(circuit))
		{
			circuit->WritePacket(circuit, &nodeInfo.address, &AllRoutersAddress, packet);
		}
		else
		{
			//TODO: circuit->WritePacket(circuit, &nodeInfo.address, &adjacency->id, packet);
		}
	}
}

static int Level1UpdateRequired(int slot, int from, int count)
{
	int i;
	int ans = 0;
	for (i = from; i < from + count; i++)
	{
		if (Srm[i][slot])
		{
			ans = 1;
			Srm[i][slot] = 0;
		}
	}

	return ans;
}

static int Level2UpdateRequired(int slot)
{
	int i;
	int ans = 0;
	for (i = 1; i <= NA; i++)
	{
		if (ASrm[i][slot])
		{
			ans = 1;
			ASrm[i][slot] = 0;
		}
	}

	return ans;
}
