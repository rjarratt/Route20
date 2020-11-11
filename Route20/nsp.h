/* nsp.h: NSP support
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

#include "packet.h"

#if !defined(NSP_H)

#define SERVICES_NONE 1
#define SERVICES_SEGMENT 5


#define REASON_NO_RESOURCES 1
#define REASON_DISCONNECT_COMPLETE 42
#define REASON_NO_LINK_TERMINATE 41

typedef struct
{
	int  NSPInactTim; /* inactivity timer in seconds */
} nsp_config_t;

nsp_config_t NspConfig;

void NspInitialise(void);
void NspInitialiseConfig(void);
// TODO: Add context parameter to support multiple sessions
int NspOpen(void (*closeCallback)(uint16 locAddr), void (*connectCallback)(decnet_address_t* remNode, uint16 locAddr, uint16 remAddr, byte* data, byte dataLength), void (*dataCallback)(uint16 locAddr, byte* data, uint16 dataLength));
void NspClose(uint16 locAddr);
int NspAccept(uint16 srcAddr, byte services, byte dataLen, byte* data);
int NspReject(decnet_address_t* dstNode, uint16 srcAddr, uint16 dstAddr, uint16 reason, byte dataLen, byte* data); //TODO: check if reject really needs the dstNode parameter or if it can come from the port
void NspTransmit(uint16 srcAddr, byte *data, int dataLength); // TODO: will need to identify link src, dst (and node?)
void NspProcessPacket(decnet_address_t *from, byte *data, int dataLength);
#define NSP_H
#endif

