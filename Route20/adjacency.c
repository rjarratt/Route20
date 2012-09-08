/* adjacency.c: Supports DECnet adjacencies
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

#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include <limits.h>
#include "platform.h"
#include "adjacency.h"
#include "decnet.h"
#include "eth_init_layer.h"

#define NBRA_BASE (NC)
#define NBEA_BASE (NC + NBRA + 1) // temp slot for router adjacencies is in slot at end of NBRA portion

typedef struct
{
	decnet_address_t *id;
	adjacency_t      *adjacency;

} findargs_t;

static adjacency_t adjacencies[NC + NBRA + NBEA + 1]; // Add one so there is room temporarily to store one router above the limit while choosing which one to drop
static int routerAdjacencyCount = 0;
static int endnodeAdjacencyCount = 0;
static void (*stateChangeCallback)(adjacency_t *adjacency);

static void AdjacencyUp(adjacency_t *adjacency);
static adjacency_t *FindFreeAdjacencySlot(int from, int n);
static adjacency_t *AddRouterAdjacency(decnet_address_t *id, circuit_t *circuit, AdjacencyType type, int helloTimer, int priority);
static adjacency_t *AddEndnodeAdjacency(decnet_address_t *id, circuit_t *circuit, int helloTimer);
static void DeleteAdjacency(adjacency_t *adjacency);
static AdjacencyState GetNewAdjacencyState(rslist_t *routers, int routersCount);
static void PurgeLowestPriorityAdjacency(void);
static int ThisIsDesignatedRouter(adjacency_t *adjacency);
static void ProcessAllAdjacencies(int (*process)(adjacency_t *adjacency, void *context), void *context);
static int FindAdjacencyCallback(adjacency_t *adjacency, void *context);
static int StopAdjacencyCallback(adjacency_t *adjacency, void *context);
static int PurgeAdjacencyCallback(adjacency_t *adjacency, void *context);

void InitialiseAdjacencies(void)
{
	int i;
	for (i = 0; i <= NC + NBRA + NBEA; i++)
	{
		adjacencies[i].slot = i + 1;
	}
}

void CheckRouterAdjacency(decnet_address_t *from, circuit_t *circuit, AdjacencyType type, int helloTimer, int priority, rslist_t *routers, int routersCount)
{
	adjacency_t *adjacency = NULL;
	AdjacencyState newState;

	/*Log(LogInfo, "Checking adjacency for "); LogDecnetAddress(LogInfo, &from); Log(LogInfo, ", hello=%d, priority=%d\n", helloTimer, priority);*/

	adjacency = FindAdjacency(from);

	if (adjacency == NULL)
	{
        /*Log(LogInfo, "Adding adjacency\n");*/
        adjacency = AddRouterAdjacency(from, circuit, type, helloTimer, priority);
	}

	if (adjacency != NULL)
	{
		time(&adjacency->lastHeardFrom);
		adjacency->helloTimer = helloTimer;
		adjacency->priority = (byte)priority;

		newState = GetNewAdjacencyState(routers, routersCount);

		if (adjacency->state == Initialising && newState == Up)
		{
			AdjacencyUp(adjacency);
		}
		else if (adjacency->state == Up && newState == Initialising)
		{
			AdjacencyDown(adjacency);
		}
	}

    EthInitCheckDesignatedRouter();
}

void CheckEndnodeAdjacency(decnet_address_t *from, circuit_t *circuit, int helloTimer)
{
	adjacency_t *adjacency = NULL;

	/*Log(LogInfo, "Checking adjacency for "); LogDecnetAddress(LogInfo, &from); Log(LogInfo, ", hello=%d\n", helloTimer);*/

	adjacency = FindAdjacency(from);

	if (adjacency == NULL)
	{
        adjacency = AddEndnodeAdjacency(from, circuit, helloTimer);
	}

	if (adjacency != NULL)
	{
		time(&adjacency->lastHeardFrom);
		adjacency->helloTimer = helloTimer;

		if (adjacency->state == Initialising)
		{
			AdjacencyUp(adjacency);
		}
	}
}

 void ProcessRouterAdjacencies(int (*process)(adjacency_t *adjacency, void *context), void *context)
{
	int i;
	for( i = NC; i < NC + NBRA + 1; i++)
	{
		adjacency_t *adjacency = &adjacencies[i];
		if (adjacency->type != UnusedAdjacency)
		{
			if (!process(adjacency, context))
			{
				break;
			}
		}
	}
}

void PurgeAdjacencies(void)
{
	time_t now;
	time(&now);
	ProcessAllAdjacencies(PurgeAdjacencyCallback, &now);
}

void StopAllAdjacencies(void)
{
	ProcessAllAdjacencies(StopAdjacencyCallback, NULL);
}

adjacency_t *GetAdjacency(int i)
{
	return &adjacencies[i-1]; /* using 1-based indexing in the algorithms from the DEC spec */
}

adjacency_t *FindAdjacency(decnet_address_t *id)
{
	findargs_t args;
	args.adjacency = NULL;
	args.id = id;
	ProcessAllAdjacencies(FindAdjacencyCallback, &args);

	return args.adjacency;
}

void SetAdjacencyStateChangeCallback(void (*callback)(adjacency_t *adjacency))
{
	stateChangeCallback = callback;
}

int IsBroadcastRouterAdjacency(adjacency_t *adjacency)
{
	return adjacency->type == Level1RouterAdjacency || adjacency->type == Level2RouterAdjacency;
}

int IsBroadcastEndnodeAdjacency(adjacency_t *adjacency)
{
	return adjacency->type == EndnodeAdjacency;
}

static void AdjacencyUp(adjacency_t *adjacency)
{
	adjacency->state = Up;
	stateChangeCallback(adjacency);
	Log(LogInfo, "Adjacency up "); LogDecnetAddress(LogInfo, &adjacency->id); Log(LogInfo, " (Slot %d)\n", adjacency->slot);
}

void AdjacencyDown(adjacency_t *adjacency)
{
	adjacency->state = Initialising;
	stateChangeCallback(adjacency);
	Log(LogInfo, "Adjacency down "); LogDecnetAddress(LogInfo, &adjacency->id); Log(LogInfo, " (Slot %d)\n", adjacency->slot);
}

static void DeleteAdjacency(adjacency_t *adjacency)
{
	int slot;
	if (IsBroadcastRouterAdjacency(adjacency))
	{
		routerAdjacencyCount--;
	}
	else if (adjacency->type == EndnodeAdjacency)
	{
		endnodeAdjacencyCount--;
	}

	slot = adjacency->slot;
	memset(adjacency, 0, sizeof(adjacency_t));
	adjacency->slot = slot;
	adjacency->type = UnusedAdjacency;
}

static adjacency_t *FindFreeAdjacencySlot(int from, int n)
{
	int i;
	adjacency_t *adjacency = NULL;

	for (i = from; i < from + n; i++)
	{
		if (adjacencies[i].type == UnusedAdjacency)
		{
			adjacency = &adjacencies[i];
			break;
		}
	}

	/*if (adjacency == NULL)
	{
	    Log(LogInfo, "Adjacency Slot in range %d-%d: FULL\n", from, from + n);
	}
	else
	{
	    Log(LogInfo, "Adjacency Slot in range %d-%d: %d\n", from, from + n, i);
	}*/

	return adjacency;
}

static adjacency_t *AddRouterAdjacency(decnet_address_t *id, circuit_t *circuit, AdjacencyType type, int helloTimer, int priority)
{
	adjacency_t *adjacency = NULL;

	/*Log(LogInfo, "Adding router adjacency "); LogDecnetAddress(LogInfo, id); Log(LogInfo, ", priority %d\n", priority);*/
	adjacency = FindFreeAdjacencySlot(NBRA_BASE, NBRA + 1);
	routerAdjacencyCount++;
		
	adjacency->type = type;
	memcpy(&adjacency->id, id, sizeof(decnet_address_t));
	adjacency->circuit = circuit;
	adjacency->state = Initialising;
	adjacency->helloTimer = helloTimer;
	adjacency->priority = (byte)priority;

	if (routerAdjacencyCount > NBRA)
	{
		PurgeLowestPriorityAdjacency();
		adjacency = FindAdjacency(id);
	}

	return adjacency;
}

static adjacency_t *AddEndnodeAdjacency(decnet_address_t *id, circuit_t *circuit, int helloTimer)
{
	adjacency_t *adjacency = NULL;

	/*Log(LogInfo, "Adding endnode adjacency "); LogDecnetAddress(LogInfo, id); Log(LogInfo, "\n");*/
	adjacency = FindFreeAdjacencySlot(NBEA_BASE, NBEA);
	if (adjacency != NULL)
	{
		endnodeAdjacencyCount++;
		adjacency->type = EndnodeAdjacency;
	    memcpy(&adjacency->id, id, sizeof(decnet_address_t));
	    adjacency->circuit = circuit;
		adjacency->state = Initialising;
		adjacency->helloTimer = helloTimer;
	}

	return adjacency;
}

static AdjacencyState GetNewAdjacencyState(rslist_t *routers, int routersCount)
{
	AdjacencyState newState = Initialising;
	int i;
	for (i = 0; i < routersCount; i++)
	{
		decnet_address_t remoteAddress;

		GetDecnetAddress(&routers[i].router, &remoteAddress);
		if (CompareDecnetAddress(&remoteAddress, &nodeInfo.address))
		{
			newState = Up;
			break;
		}
	}

	return newState;
}

static void PurgeLowestPriorityAdjacency(void)
{
	int i;
	adjacency_t *selectedAdjacency;
	int lowestPriority = INT_MAX;
	int lowestId = INT_MAX;
	int slotToDelete;

	for( i = 0; i < routerAdjacencyCount; i++)
	{
		int thisId;
		adjacency_t *adjacency = &adjacencies[NBRA_BASE + i];
		thisId = GetDecnetId(adjacency->id);
		if (adjacency->priority < lowestPriority || (adjacency->priority == lowestPriority && thisId < lowestId))
		{
			selectedAdjacency = adjacency;
			lowestPriority = adjacency->priority;
			lowestId = thisId;
		}
	}

	if (selectedAdjacency->state == Up)
	{
		AdjacencyDown(selectedAdjacency);
	}

	slotToDelete = selectedAdjacency->slot;
	DeleteAdjacency(selectedAdjacency);

	/* Move adjacency in the highest slot to the deleted slot so that it does not have an illegal slot number for the decision algorithms */
	if (slotToDelete != NC + NBRA + 1)
	{
	    memcpy(&adjacencies[slotToDelete - 1], &adjacencies[NC + NBRA], sizeof(adjacency_t));
		adjacencies[slotToDelete - 1].slot = slotToDelete;
		routerAdjacencyCount++; /* delete brings it back down again, but in effect we do have an extra one for the moment */
		DeleteAdjacency(&adjacencies[NC + NBRA]);
	}
}

static int ThisIsDesignatedRouter(adjacency_t *adjacency)
{
	int ans = nodeInfo.priority > adjacency->priority;
	if (nodeInfo.priority == adjacency->priority)
	{
		ans = GetDecnetId(nodeInfo.address) > GetDecnetId(adjacency->id);
	}

	return ans;
}

static void ProcessAllAdjacencies(int (*process)(adjacency_t *adjacency, void *context), void *context)
{
	int i;
	for( i = 0; i < NC + NBRA + NBEA; i++)
	{
		adjacency_t *adjacency = &adjacencies[i];
		if (adjacency->type != UnusedAdjacency)
		{
			if (!process(adjacency, context))
			{
				break;
			}
		}
	}
}

static int FindAdjacencyCallback(adjacency_t *adjacency, void *context)
{
	findargs_t *findArgs = (findargs_t *)context;
	if (memcmp(findArgs->id, &adjacency->id, sizeof(decnet_address_t))==0)
	{
		findArgs->adjacency = adjacency;
	}

	return findArgs->adjacency == NULL;
}

static int StopAdjacencyCallback(adjacency_t *adjacency, void *context)
{
	AdjacencyDown(adjacency);
	DeleteAdjacency(adjacency);
	return 1;
}

static int PurgeAdjacencyCallback(adjacency_t *adjacency, void *context)
{
	time_t now = *((time_t *)context);

	if ((now - adjacency->lastHeardFrom) > (BCT3MULT * adjacency->helloTimer))
	{
		if (adjacency->state == Up)
		{
			AdjacencyDown(adjacency);
		}

		DeleteAdjacency(adjacency);
	}

	return 1;
}
