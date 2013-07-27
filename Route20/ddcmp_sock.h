/* ddcmp_sock.h: Ddcmp sockets interface
  ------------------------------------------------------------------------------

   Copyright (c) 2013, Robert M. A. Jarratt

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

#if defined(WIN32)
//#include <Windows.h>
#include <WinSock2.h>
#endif

#include "packet.h"
#include "socket.h"
#include "ddcmp.h"
#include "ddcmp_circuit.h"

#if !defined(DDCMP_SOCK_H)

typedef struct
{
	socket_t socket;
	char *destinationHostName;
	sockaddr_t destinationAddress;
	ddcmp_line_t line;
	byte *buffer;
	int bufferLength;
} ddcmp_sock_t;

int DdcmpSockOpen(ddcmp_circuit_t *ddcmpCircuit);
packet_t *DdcmpSockReadPacket(ddcmp_circuit_t *ddcmpCircuit);
int DdcmpSockWritePacket(ddcmp_circuit_t *ddcmp, packet_t *packet);
void DdcmpSockClose(ddcmp_circuit_t *ddcmpCircuit);
int DdcmpSockWaitHandle(ddcmp_circuit_t *ddcmpCircuit);

#define DDCMP_SOCK_H
#endif
