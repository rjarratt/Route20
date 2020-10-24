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
#include <stdlib.h>
#include "constants.h"
#include "update.h"
#include "routing_database.h"
#include "area_routing_database.h"
#include "adjacency.h"
#include "messages.h"
#include "packet.h"
#include "timer.h"
#include "platform.h"

static void ProcessUpdateTimer(rtimer_t* timer, char* name, void* context);
static void ProcessCircuitLevel1Update(circuit_t* circuit);
static void ProcessCircuitLevel2Update(circuit_t* circuit);
static int Level1UpdateRequired(int slot, int from, int count);
static int Level2UpdateRequired(int slot);

typedef struct
{
    circuit_t* circuit;
    int nextLevel1Node;
} Level1UpdateBatch;

static Level1UpdateBatch Level1UpdateBatches[(NN + 1) / LEVEL1_BATCH_SIZE];

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

static void ProcessUpdateTimer(rtimer_t* timer, char* name, void* context)
{
    int i;
    for (i = 1; i <= NC; i++)
    {
        circuit_t* circuit = &Circuits[i];
        if (circuit->state == CircuitStateUp)
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

static void SendLevel1UpdateBatch(rtimer_t* timer, char* name, void* context)
{
    packet_t* packet;
    Level1UpdateBatch* batch = (Level1UpdateBatch*)context;
    if (Level1UpdateRequired(batch->circuit->slot, batch->nextLevel1Node, LEVEL1_BATCH_SIZE))
    {
        Log(LogUpdate, LogVerbose, "Sending level 1 routing to %s for node range %d-%d\n", batch->circuit->name, batch->nextLevel1Node, batch->nextLevel1Node + LEVEL1_BATCH_SIZE - 1);
        packet = CreateLevel1RoutingMessage(batch->nextLevel1Node, LEVEL1_BATCH_SIZE);
        if (IsBroadcastCircuit(batch->circuit))
        {
            batch->circuit->WritePacket(batch->circuit, &nodeInfo.address, &AllRoutersAddress, packet, 0);
        }
        else
        {
            batch->circuit->WritePacket(batch->circuit, NULL, NULL, packet, 0);
        }
    }
}

static void ProcessCircuitLevel1Update(circuit_t* circuit)
{
    int startNode = circuit->nextLevel1Node;
    time_t now;
    int i = 0;
    time(&now);

    do
    {
        Level1UpdateBatch* batch = &Level1UpdateBatches[i];
        batch->circuit = circuit;
        batch->nextLevel1Node = circuit->nextLevel1Node;
        CreateTimer("Level1Update", now + i, 0, batch, SendLevel1UpdateBatch); // Send each batch at 1-second intervals so there is less chance of a loss of packets if we send a whole load at once
        circuit->nextLevel1Node = (circuit->nextLevel1Node + LEVEL1_BATCH_SIZE) % (NN + 1);
        i++;
    } while (circuit->nextLevel1Node != startNode);

    /* ensure next time round we start from a different point in the table, satisfies 4.8.1 requirement to mitigate packet loss */
    circuit->nextLevel1Node = (circuit->nextLevel1Node + LEVEL1_BATCH_SIZE) % (NN + 1);
}

static void ProcessCircuitLevel2Update(circuit_t* circuit)
{
    packet_t* packet;

    if (Level2UpdateRequired(circuit->slot))
    {
        Log(LogUpdate, LogVerbose, "Sending level 2 routing to %s\n", circuit->name);
        packet = CreateLevel2RoutingMessage();
        if (IsBroadcastCircuit(circuit))
        {
            circuit->WritePacket(circuit, &nodeInfo.address, &AllRoutersAddress, packet, 0);
        }
        else
        {
            circuit->WritePacket(circuit, NULL, NULL, packet, 0);
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
