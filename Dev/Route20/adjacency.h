/* adjacency.h: Supports DECnet adjacencies
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
#include "basictypes.h"
#include "eth_decnet.h"
#include "circuit.h"

#if !defined(ADJACENCY_H)

typedef enum
{
	Initialising,
	Up
} AdjacencyState;

typedef enum
{
	UnusedAdjacency,
	EndnodeAdjacency,
	Level1RouterAdjacency,
	Level2RouterAdjacency,
	PhaseIIIAdjacency
} AdjacencyType;

typedef struct
{
	decnet_eth_address_t router;
	byte                 priority_state;
} rslist_t;

typedef struct
{
	int              slot;
	circuit_t       *circuit;
	AdjacencyType    type;
	decnet_address_t id;
	time_t           lastHeardFrom;
	int              helloTimer;
	AdjacencyState   state;
	byte             priority;
} adjacency_t;

void InitialiseAdjacencies(void);
void CheckRouterAdjacency(decnet_address_t *from, circuit_t *circuit, AdjacencyType type, int helloTimer, int priority, rslist_t *routers, int routersCount);
void CheckEndnodeAdjacency(decnet_address_t *from, circuit_t *circuit, int helloTimer);
void InitialiseCircuitAdjacency(decnet_address_t *from, circuit_t *circuit, AdjacencyType type, int helloTimer);
void CheckCircuitAdjacency(decnet_address_t *from, circuit_t *circuit);
void AdjacencyDown(adjacency_t *adjacency);
void ProcessRouterAdjacencies(int (*process)(adjacency_t *adjacency, void *context), void *context);
void PurgeAdjacencies(void);
void StopAllAdjacencies(CircuitType circuitType);
adjacency_t *FindAdjacency(decnet_address_t *id);
adjacency_t *GetAdjacency(int i);
void SetAdjacencyStateChangeCallback(void (*callback)(adjacency_t *adjacency));
int IsBroadcastRouterAdjacency(adjacency_t *adjacency);
int IsBroadcastEndnodeAdjacency(adjacency_t *adjacency);

#define ADJACENCY_H
#endif
