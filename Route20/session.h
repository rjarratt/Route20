/* session.h: Session support
  ------------------------------------------------------------------------------

   Copyright (c) 2020, Robert M. A. Jarratt

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

#if !defined(SESSION_H)

#include "basictypes.h"
#include "decnet.h"

typedef struct
{
	int  sessionInactivityTimeout; /* inactivity timer in seconds */
} session_config_t;

session_config_t SessionConfig;

void SessionInitialise(void);
void SessionInitialiseConfig(void);
int SessionRegisterObjectType(byte objectType, int (*connectCallback)(void *session, decnet_address_t *remNode, byte *data, byte dataLength, uint16 *reason, byte **acceptData, byte *acceptDataLength), void (*closeCallback)(void *session), void (*dataCallback)(void *session, byte *data, uint16 dataLength));
void SessionClose(void *session);
void SessionDataTransmit(void *session, byte *data, uint16 dataLength);

#define SESSION_H
#endif

