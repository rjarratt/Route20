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

static void ProcessLevel2UpdateTimer(rtimer_t *timer, char *name, void *context);
static void ProcessCircuitLevel2Update(circuit_t *circuit);
static int Level2UpdateRequired(int slot);

// TODO: Level 1 not done, it also needs to spread things out for Ethernet (applies to Level 1 routing where packets would be too big to send all in 1 message).
void InitialiseUpdateProcess(void)
{
	time_t now;

	time(&now);
	CreateTimer("level 2 update", now + T2, T2, NULL, ProcessLevel2UpdateTimer);
}

static void ProcessLevel2UpdateTimer(rtimer_t *timer, char *name, void *context)
{
	int i;
	for (i = 1; i <= NC; i++)
	{
		circuit_t *circuit = &Circuits[i];
		if (circuit->state == CircuitUp)
		{
		    ProcessCircuitLevel2Update(circuit);
		}
	}

}

static void ProcessCircuitLevel2Update(circuit_t *circuit)
{
	packet_t *packet;
		
	if (Level2UpdateRequired(circuit->slot))
	{
		//Log(LogInfo, "Sending level 2 routing to %s\n", circuit->name);
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
