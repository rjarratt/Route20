/* decision.c: DECnet Decision Algorithms (section 4.7.2)
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

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "constants.h"
#include "decnet.h"
#include "timer.h"
#include "adjacency.h"
#include "messages.h"
#include "routing_database.h"
#include "area_routing_database.h"
#include "forwarding_database.h"
#include "area_forwarding_database.h"
#include "platform.h"

static void Dump(int from, int to);
static void DumpHeading(FILE *dumpFile, char * prefix, int from, int to);
static void ProcessBroadcastAdjacencyDown(adjacency_t *adjacency);
static void ProcessBroadcastAdjacencyUp(adjacency_t *adjacency);
static void ProcessCircuitDown(circuit_t *circuit);
static void ProcessCircuitUp(circuit_t *circuit);
static int DownAdjacencyAssociatedWithCircuit(adjacency_t *adjacency, void *context);
static void CheckCircuitCostGreaterThanZero(circuit_t *circuit);
static void T1TimerProcess(rtimer_t *timer, char *name, void *context);
static void BCT1TimerProcess(rtimer_t *timer, char *name, void *context);
static void DumpTimer(rtimer_t *timer, char *name, void *context);
static void Rowmin(int M[][NC+NBRA+1], int I, int *minimum, int *VECT);
static void Minimize(int I, int M[][NC+NBRA+1], int *V, int P1, int P2, int *VECT);
static void Routes(int FirstDest, int LastDest);
static void ARoutes(int FirstArea, int LastArea);
static void Check(char *detail);

void InitialiseDecisionProcess(void)
{
	time_t now;
	InitRoutingDatabase();
	InitAreaForwardingDatabase();
	if (nodeInfo.level == 2)
	{
		InitAreaRoutingDatabase();
	}

	Routes(0, NN);

	if (nodeInfo.level == 2)
	{
		ARoutes(1, NA);
	}

	time(&now);
	CreateTimer("T1 Timer", now + T1, T1, NULL, T1TimerProcess);
	CreateTimer("BCT1 Timer", now + BCT1, BCT1, NULL, BCT1TimerProcess);
	//CreateTimer("Dump Timer", now + 60, 600, NULL, DumpTimer);
}

void ProcessAdjacencyStateChange(adjacency_t *adjacency)
{
	if (adjacency->state == Up)
	{
		ProcessBroadcastAdjacencyUp(adjacency);
	}
	else
	{
		ProcessBroadcastAdjacencyDown(adjacency);
	}
}

void ProcessCircuitStateChange(circuit_t *circuit)
{
	if (circuit->state == CircuitUp)
	{
    	ProcessCircuitUp(circuit);
	}
	else
	{
    	ProcessCircuitDown(circuit);
	}
}

void ProcessLevel1RoutingMessage(routing_msg_t *msg)
{
	adjacency_t *adjacency;
	int seg;
	int i;

	adjacency = FindAdjacency(&msg->srcnode);
	if (adjacency != NULL)
	{
		CheckCircuitCostGreaterThanZero(adjacency->circuit);
		Check(NULL);
		for (seg = 0; seg < msg->segmentCount; seg++)
		{
			routing_segment_t *segment = msg->segments[seg];
//Log(LogInfo, "Segment start %d, segment count %d\n", segment->start, segment->count);
			for (i = segment->start; i < segment->start + segment->count; i++)
			{
				int hops;
				int cost;
				ExtractRoutingInfo(segment->rtginfo[i - segment->start], &hops, &cost);
				Log(LogDecision, LogVerbose, "L1 Adjacency slot %d, segment index is %d, hops=%d, cost=%d\n", adjacency->slot, i, hops, cost);
				Hop[i][adjacency->slot] = hops;
				Hop[i][adjacency->slot]++;
				Cost[i][adjacency->slot] = cost;
				Cost[i][adjacency->slot] += adjacency->circuit->cost;
				Routes(i,i);
			}
		}
	}
}

void ProcessLevel2RoutingMessage(routing_msg_t *msg)
{
	adjacency_t *adjacency;
	int seg;
	int i;

	adjacency = FindAdjacency(&msg->srcnode);
	if (adjacency != NULL)
	{
		CheckCircuitCostGreaterThanZero(adjacency->circuit);
		Check(NULL);
		for (seg = 0; seg < msg->segmentCount; seg++)
		{
			routing_segment_t *segment = msg->segments[seg];
			for (i = segment->start; i < segment->start + segment->count; i++)
			{
				int hops;
				int cost;
				ExtractRoutingInfo(segment->rtginfo[i - segment->start], &hops, &cost);
				Log(LogDecision, LogVerbose, "L2 Adjacency slot %d, segment index is %d, hops=%d, cost=%d\n", adjacency->slot, i, hops, cost);
				AHop[i][adjacency->slot] = hops;
				AHop[i][adjacency->slot]++;
				ACost[i][adjacency->slot] = cost;
				ACost[i][adjacency->slot] += adjacency->circuit->cost;
				ARoutes(i,i);
			}
		}
	}
}

static void Dump(int from, int to)
{
	int i;
	int j;
	FILE *dumpFile = fopen("DecisionDb.txt", "w");
	fprintf(dumpFile, "Attached=%d\n", AttachedFlg);
	DumpHeading(dumpFile, "                     ", 0, NC+NBRA);
	fprintf(dumpFile, "Area Rch Adj         Cost\n");
	for (i = from; i <= to; i++)
	{
		adjacency_t *adjacency;
		fprintf(dumpFile, "%4d %3d", i, AReach[i]);
		adjacency = GetAdjacency(AOA[i]);
		if (adjacency->type != UnusedAdjacency)
		{
			fprintf(dumpFile, " %2d.%-4d(%2d) ", adjacency->id.area, adjacency->id.node, adjacency->slot);
		}
		else
		{
			fprintf(dumpFile, " N/A         ");
		}

		for (j = 0; j <= NC+NBRA; j++)
		{
			int c = ACost[i][j];
			if (c == Infc)
			{
				fprintf(dumpFile, "I");
			}
			else if (c > 9)
			{
				fprintf(dumpFile, "H", c);
			}
			else
			{
				fprintf(dumpFile, "%d", c);
            }
		}

		fprintf(dumpFile, "\n");
	}
	fclose(dumpFile);
}

static void DumpHeading(FILE *dumpFile, char * prefix, int from, int to)
{
	int j;
	fprintf(dumpFile, "%s", prefix);
	for (j = from; j <= to; j++)
	{
		fprintf(dumpFile, "%d", j / 10);
	}

	fprintf(dumpFile, "\n");

	fprintf(dumpFile, "%s", prefix);
	for (j = from; j <= to; j++)
	{
		fprintf(dumpFile, "%d", j % 10);
	}

	fprintf(dumpFile, "\n");

	fprintf(dumpFile, "%s", prefix);
	for (j = from; j <= to; j++)
	{
		fprintf(dumpFile, "-");
	}

	fprintf(dumpFile, "\n");
}

static void ProcessBroadcastAdjacencyDown(adjacency_t *adjacency)
{
	int i;
	if (IsBroadcastRouterAdjacency(adjacency))
	{
		for (i = 1; i <= NN; i++)
		{
			Hop[i][adjacency->slot] = Infh;
			Cost[i][adjacency->slot] = Infc;
		}

		if (nodeInfo.level == 2)
		{
			for (i = 1; i <= NA; i++)
			{
				AHop[i][adjacency->slot] = Infh;
				ACost[i][adjacency->slot] = Infc;
			}
		}

		if (nodeInfo.level == 2 && adjacency->type == Level2RouterAdjacency)
		{
			ARoutes(1, NA);
		}

		Routes(0,NN);
	}
	else if (IsBroadcastEndnodeAdjacency(adjacency))
	{
		int nodeid = adjacency->id.node;
		int k = adjacency->circuit->slot;
		Hop[nodeid][k] = Infh;
		Cost[nodeid][k] = Infc;
		Routes(nodeid, adjacency->id.node);
	}
}

static void ProcessBroadcastAdjacencyUp(adjacency_t *adjacency)
{
	int i;
	if (IsBroadcastRouterAdjacency(adjacency))
	{
		int circ = adjacency->circuit->slot;
		for ( i = 0; i <= NN; i++)
		{
			Srm[i][circ] = 1;
		}

		if (nodeInfo.level == 2 && adjacency->type == Level2RouterAdjacency)
		{
			for ( i = 0; i <= NA; i++)
			{
				ASrm[i][circ] = 1;
			}
		}
	}
	else if (IsBroadcastEndnodeAdjacency(adjacency))
	{
		int nodeid = adjacency->id.node;
		int k = adjacency->circuit->slot;
		Hop[nodeid][k] = 1;
		Cost[nodeid][k] = adjacency->circuit->cost;
		Routes(nodeid, nodeid);
	}
}

static void ProcessCircuitDown(circuit_t *circuit)
{
	int i;
	int j = circuit->slot;

	Check(NULL);

	for (i = 0; i <= NN; i++)
	{
		Hop[i][j] = Infh;
	}

	if (nodeInfo.level == 2)
	{
		for (i = 1; i <= NA; i++)
		{
			AHop[i][j] = Infh;
		}
	}
	
	ProcessRouterAdjacencies(DownAdjacencyAssociatedWithCircuit, circuit);

	if (nodeInfo.level == 2)
	{
		ARoutes(1, NA);
	}

	Routes(0, NN);
}

static void ProcessCircuitUp(circuit_t *circuit)
{
	int i;
	int j = circuit->slot;

	Check(NULL);

	if (!IsBroadcastCircuit(circuit))
	{
		adjacency_t *adjacency = GetAdjacency(j);
		int k = adjacency->id.node;
		if (adjacency->type == EndnodeAdjacency)
		{
			Hop[k][j] = 1;

			CheckCircuitCostGreaterThanZero(circuit);

			Cost[k][j] = circuit->cost;

			Routes(k, k);
		}

		for (i = 0; i <= NN; i++)
		{
			Srm[i][j] = 1;
		}

		if (nodeInfo.level == 2 && adjacency->type == Level2RouterAdjacency)
		{
			for (i = 1; i <= NA; i++)
			{
				ASrm[i][j] = 1;
			}
		}
	}
	else
	{
		CheckCircuitCostGreaterThanZero(circuit);

		for (i = 0; i <= NN; i++)
		{
			Srm[i][j] = 1;
		}

		if (nodeInfo.level == 2)
		{
			for (i = 1; i <= NA; i++)
			{
				ASrm[i][j] = 1;
			}
		}
	}
}

static int DownAdjacencyAssociatedWithCircuit(adjacency_t *adjacency, void *context)
{
	circuit_t *circuit = (circuit_t *)context;
	if (adjacency->circuit == circuit)
	{
		AdjacencyDown(adjacency);
	}

	return 1;
}

static void CheckCircuitCostGreaterThanZero(circuit_t *circuit)
{
	if (circuit->cost <= 0)
	{
		Log(LogDecision, LogFatal, "Circuit cost must be greater than 0 when circuit goes up, terminating\n");
		exit(0);
	}
}

static void T1TimerProcess(rtimer_t *timer, char *name, void *context)
{
	int i;
	int j;

	//Log(LogInfo, "Process T1 timer\n");

	Check(NULL);

	for( j = 1; j <= NC; j++)
	{
		adjacency_t *adjacency = GetAdjacency(j);
		if (!IsBroadcastCircuit(&Circuits[j]) && adjacency->type != EndnodeAdjacency)
		{
			for (i = 0; i <= NN; i++)
			{
				Srm[i][j] = 1;
			}
		}

		if (nodeInfo.level == 2 && adjacency->type == Level2RouterAdjacency && !IsBroadcastCircuit(adjacency->circuit))
		{
			for (i = 0; i <= NA; i++)
			{
				ASrm[i][j] = 1;
			}
		}
	}

	Routes(0, NN);

	if (nodeInfo.level == 2)
	{
		ARoutes(1, NA);
	}
}

static void BCT1TimerProcess(rtimer_t *timer, char *name, void *context)
{
	int i;
	int j;

	//Log(LogInfo, "Process BCT1 timer\n");

	Check(NULL);

	for( j = 1; j <= NC; j++)
	{
		if (IsBroadcastCircuit(&Circuits[j]))
		{
			for (i = 0; i <= NN; i++)
			{
				Srm[i][j] = 1;
			}

			if (nodeInfo.level == 2)
			{
				for (i = 0; i <= NA; i++)
				{
					ASrm[i][j] = 1;
				}
			}
		}
	}
}

static void DumpTimer(rtimer_t *timer, char *name, void *context)
{
	Dump(0, NA);
}

/*This routine determines the minimum for row I of
  Matrix M and stores the column number in VECT(I).
*/
static void Rowmin(int M[][NC+NBRA+1], int I, int *minimum, int *VECT)
{
	int j;
	*minimum = INT_MAX;
	for (j = 0; j <= NC + NBRA; j++)
	{
		if ((M[I][j] < *minimum) || ((M[I][j] == *minimum) &&  GetDecnetId(GetAdjacency(j)->id) > GetDecnetId(GetAdjacency(VECT[I])->id)))
		{
			*minimum = M[I][j];
			VECT[I] = j;
		}
	}
}

/* This routine determines entries for vector V,
   containing the minimum of each row of matrix M,
   and passes to Rowmin the vector VECT in which to store the
   resulting output adjacency number.
*/
static void Minimize(int I, int M[][NC+NBRA+1], int *V, int P1, int P2, int *VECT)
{
	int minimum;
    Rowmin(M, I, &minimum, VECT);
	if (minimum > P1)
	{
		minimum = P2;
	}

    V[I] = minimum; /* error in spec, which shows this inside the above IF */
}

/* This routine determines the reachability and output adjacency
   for each destination in the range FirstDest to LastDest
   within the area, with destination #0 the nearest level 2 router.
*/
static void Routes(int FirstDest, int LastDest)
{
	int i;
	for (i = FirstDest; i <= LastDest; i++)
	{
		int Col;
		int OldHop = Minhop[i];
		int OldCost = Mincost[i];
		Minimize(i, Cost, Mincost, Maxc, Infc, OA);
		Col = OA[i];
		Minhop[i] = Hop[i][Col];
		if (Minhop[i] > Maxh)
		{
			Minhop[i] = Infh;
		}

		if (Col <= NC && Circuits[Col].circuitType == EthernetCircuit)
		{
			int j;
			for(j = NC + NBRA + 1; j <= NC + NBRA + 1 + NBEA; j++)
			{
				adjacency_t *adj = GetAdjacency(j);
				if (adj->type == EndnodeAdjacency && adj->id.node == i)
				{
					OA[i] = j;
				}
			}
		}

		if (Minhop[i] == Infh || Mincost[i] == Infc)
		{
			Reach[i] = 0;
			Minhop[i] = Infh;
			Mincost[i] = Infc;
		}
		else
		{
			Reach[i] = 1;
		}

		if (Minhop[i] != OldHop || Mincost[i] != OldCost)
		{
			int k;
			for (k = 1; k <= NC; k++)
			{
				Srm[i][k] = 1;
			}
		}
	}
}

/* This routine determines the reachability and output adjacency
   for each area in the range FirstArea to LastArea.
*/
static void ARoutes(int FirstArea, int LastArea)
{
	int i;
	for (i = FirstArea; i <= LastArea; i++)
	{
		int Col;
		int OldHop = AMinhop[i];
		int OldCost = AMincost[i];
		Minimize(i, ACost, AMincost, AMaxc, Infc, AOA);
		Col = AOA[i];
		AMinhop[i] = AHop[i][Col];
		if (AMinhop[i] > AMaxh)
		{
			AMinhop[i] = Infh;
		}

		if (AMinhop[i] == Infh || AMincost[i] == Infc)
		{
			//if (AReach[i])
			//{
			//	Log(LogInfo, "Area %d is no longer reachable\n", i);
			//}

			AReach[i] = 0;
			AMinhop[i] = Infh;
			AMincost[i] = Infc;
		}
		else
		{
			//if (!AReach[i])
			//{
			//	Log(LogInfo, "Area %d is now reachable\n", i);
			//}

			AReach[i] = 1;
		}

		if (AMinhop[i] != OldHop || AMincost[i] != OldCost)
		{
			int j;
			for (j = 1; j <= NC; j++)
			{
				if ((GetAdjacency(j)->type==Level2RouterAdjacency) || Circuits[j].circuitType == EthernetCircuit)
				{
					ASrm[i][j] = 1;
				}
			}
		}
	}
	
	AttachedFlg = 0;
    Hop[0][0] = Infh;
    Cost[0][0] = Infc;
	for (i = 1; i <= NA; i++)
	{
		if (AReach[i] && i != nodeInfo.address.area)
		{
            Hop[0][0] = 0;
            Cost[0][0] = 0;
			AttachedFlg = 1;
		}
	}

	Routes(0, 0);
}

/* This routine detects any corruption of column 0 in the
   Hop, Cost, AHop and ACost matrices.
*/
static void Check(char *detail)
{
	int i;
	int ok = 1;

	if (Hop[nodeInfo.address.node][0] != 0 || Cost[nodeInfo.address.node][0] != 0)
	{
		Log(LogDecision, LogError, "Check 1 failed. Hop is %d, cost is %d\n", Hop[nodeInfo.address.node][0], Cost[nodeInfo.address.node][0]);
		ok = 0;
	}

	if (nodeInfo.level == 2 && AttachedFlg)
	{
		if (Hop[0][0] != 0 || Cost[0][0] != 0)
		{
		    Log(LogDecision, LogError, "Check 2 failed. Hop[0][0]=%d Cost[0][0]=%d\n", Hop[0][0], Cost[0][0]);
			ok = 0;
		}
	}

	if (nodeInfo.level == 2 && !AttachedFlg)
	{
		if (Hop[0][0] != Infh || Cost[0][0] != Infc)
		{
		    Log(LogDecision, LogError, "Check 3 failed. Hop[0][0]=%d Cost[0][0]=%d\n", Hop[0][0], Cost[0][0]);
			ok = 0;
		}
	}

	if (nodeInfo.level == 2)
	{
		for (i = 1; i <= NA; i++)
		{
			if (nodeInfo.address.area == i)
			{
				if (AHop[i][0] != 0 || ACost[i][0] != 0)
				{
		            Log(LogDecision, LogError, "Check 4 failed. AHop[%d][0]=%d, ACost[%d][0]=%d\n", i, AHop[i][0], i, ACost[i][0]);
					ok = 0;
				}
			}
			else
			{
				if (AHop[i][0] != Infh || ACost[i][0] != Infc)
				{
		            Log(LogDecision, LogError, "Check 5 failed. AHop[%d][0]=%d, ACost[%d][0]=%d\n", i, AHop[i][0], i, ACost[i][0]);
					ok = 0;
				}
			}
		}
	}

	if (!ok)
	{
		if (detail == NULL)
		{
		    Log(LogDecision, LogFatal, "Check failed, exiting\n");
		}
		else
		{
		    Log(LogDecision, LogFatal, "Check failed, exiting: %s\n", detail);
		}
		exit(0);
	}

}
