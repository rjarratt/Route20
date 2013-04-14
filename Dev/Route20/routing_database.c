/* routing_database.c: Routing Database in Level 1 and Level 2 Routers (section 4.2)
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
#include "constants.h"
#include "node.h"
#include "routing_database.h"

void InitRoutingDatabase(void)
{
	// TODO: consider moving adjacencies database here as well and initialise it here too. Make it a 1-based array too.
	int i;
	int j;
	for (i = 0; i <= NC; i++)
	{
		Circuits[i].slot = i;
	}

	for (i = 0; i <= NN; i++)
	{
		Minhop[i] = Infh;
		Mincost[i] = Infc;
		for (j = 0; j <= NC+NBRA; j++)
		{
			Hop[i][j] = Infh;
			Cost[i][j] = Infc;
		}

		for (j = 1; j <= NC; j++)
		{
			Srm[i][j] = 0;
		}
	}

	Hop[nodeInfo.address.node][0] = 0;
	Cost[nodeInfo.address.node][0] = 0;
}
