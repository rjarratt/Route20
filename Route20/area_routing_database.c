/* area_routing_database.c: Area Routing Data Base In Level 2 Routers (section 4.3)
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
#include "area_routing_database.h"

int AMinhop[NA + 1];
int AMincost[NA + 1];
int ACost[NA + 1][NC + NBRA + 1];
int AHop[NA + 1][NC + NBRA + 1];
int ASrm[NA + 1][NC + 1];
int AttachedFlg;

void InitAreaRoutingDatabase(void)
{
	int i;
	int j;

	for (i = 1; i <= NA; i++)
	{
		AMinhop[i] = Infh;
		AMincost[i] = Infc;
		for (j = 0; j <= NC+NBRA; j++)
		{
			AHop[i][j] = Infh;
			ACost[i][j] = Infc;
		}

		for (j = 1; j <= NC; j++)
		{
			ASrm[i][j] = 0;
		}
	}

	AHop[nodeInfo.address.area][0] = 0;
	ACost[nodeInfo.address.area][0] = 0;
	AttachedFlg = 0;
}
