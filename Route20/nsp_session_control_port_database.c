/* nsp_session_control_port_database.c: NSP Session Control Port Database
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
#include "platform.h"
#include "nsp_session_control_port_database.h"

static uint16 lastPort = 0;
static session_control_port_t scpDatabase[NSP_MAX_SESSIONS];

static int IsEntryClosed(session_control_port_t *entry, void *context);
static int IsEntryOpen(session_control_port_t *entry, void *context);
static int IsEntryLocalAddress(session_control_port_t *entry, void *context);

void NspInitialiseScpDatabase(void)
{
	int i;
	for (i = 0; i < NSP_MAX_SESSIONS; i++)
	{
		memset(&scpDatabase[i], 0, sizeof(session_control_port_t));
		scpDatabase[i].state = NspPortStateClosed;
	}
}

session_control_port_t *NspFindScpDatabaseEntry(int (*compare)(session_control_port_t *, void *context), void *context)
{
	session_control_port_t *ans = NULL;
	int i;

	for (i = 0; i < NSP_MAX_SESSIONS; i++)
	{
		int found;
		session_control_port_t *entry = &scpDatabase[i];
		found = compare(entry, context);

		//Log(LogNsp, LogVerbose, "Comparing to node=");
		//LogDecnetAddress(LogNsp, LogVerbose, &entry->node);
		//Log(LogNsp, LogVerbose, " src=%hu ", entry->addrLoc);
		//Log(LogNsp, LogVerbose, " dst=%hu ", entry->addrRem);
		//Log(LogNsp, LogVerbose, " state=%d ", entry->state);
		//Log(LogNsp, LogVerbose, " %s\n", found ? "FOUND" : "NOT FOUND");
		
		if (found)
		{
			ans = entry;
			break;
		}
	}

	return ans;
}

session_control_port_t *NspFindFreeScpDatabaseEntry(void)
{
	return NspFindScpDatabaseEntry(IsEntryClosed, NULL);
}

session_control_port_t *NspFindOpenScpDatabaseEntry(void)
{
	return NspFindScpDatabaseEntry(IsEntryOpen, NULL);
}

session_control_port_t *NspFindScpDatabaseEntryByLocalAddress(uint16 addrLoc)
{
	return NspFindScpDatabaseEntry(IsEntryLocalAddress, &addrLoc);
}

static int IsEntryClosed(session_control_port_t *entry, void *context)
{
	return entry->state == NspPortStateClosed;
}

static int IsEntryOpen(session_control_port_t *entry, void *context)
{
	return entry->state == NspPortStateOpen;
}

static int IsEntryLocalAddress(session_control_port_t *entry, void *context)
{
	uint16 *addrLoc = (uint16 *)context;
	return entry->addrLoc = *addrLoc;
}

