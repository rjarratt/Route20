/* nsp_session_control_port_database.h: NSP Session Control Port Database
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

#include "basictypes.h"
#include "decnet.h"
#include "nsp_transmit_queue.h"

#if !defined(NSP_SCP_DATABASE_H)

#define NSP_MAX_SESSIONS 3

typedef enum
{
	NspPortStateOpen,
	NspPortStateConnectReceived,
	NspPortStateDisconnectReject,
	NspPortStateDisconnectRejectComplete,
	NspPortStateConnectConfirm,
	NspPortStateConnectInitiate,
	NspPortStateNoResources,
	NspPortStateNoCommunication,
	NspPortStateConnectDelivered,
	NspPortStateRejected,
	NspPortStateRunning,
	NspPortStateDisconnectInitiate,
	NspPortStateDisconnectComplete,
	NspPortStateDisconnectNotification,
	NspPortStateClosed,
	NspPortStateClosedNotification
} NspPortState;

typedef struct
{
	NspPortState      state;
	decnet_address_t  node;
	uint16            addrLoc;
	uint16            addrRem;
	uint16            numOth;
	uint16            numHigh;
	uint16            numSent;
	uint16            ackXmtDat;
	uint16            ackXmtOth;
	uint16            ackRcvDat;
	byte              flowLocDat;
	//char *???            flowLocDat;
	uint16            flowRemDat;
	uint16            flowRemInt;
	transmit_queue_t  transmit_queue;

	void (*closeCallback)(uint16 locAddr);
	void (*connectCallback)(decnet_address_t* remNode, uint16 locAddr, uint16 remAddr, byte *data, int dataLength);
	void (*dataCallback)(uint16 locAddr, byte *data, int dataLength);
} session_control_port_t;

void NspInitialiseScpDatabase(void);
session_control_port_t *NspFindScpDatabaseEntry(int (*compare)(session_control_port_t *, void *context), void *context);
session_control_port_t *NspFindFreeScpDatabaseEntry(void);
session_control_port_t *NspFindOpenScpDatabaseEntry(void);
session_control_port_t *NspFindScpDatabaseEntryByLocalAddress(uint16 addrLoc);

#define NSP_SCP_DATABASE_H
#endif