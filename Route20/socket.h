/* socket.h: Socket support
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

#if defined(WIN32)
//#include <Windows.h>
#include <WinSock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#define INVALID_SOCKET (-1)
#endif

#include "packet.h"

#if !defined(SOCKET_H)

typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_in sockaddr_in_t;
typedef struct in_addr rinaddr_t;
typedef struct hostent hostent_t;

typedef struct
{
	int socketConfigured;
	uint16 tcpListenPort;
} socket_config_t;

typedef struct
{
	unsigned int socket;
	unsigned int waitHandle;
	unsigned int receivePort;
} socket_t;

socket_config_t SocketConfig;
socket_t ListenSocket;

void InitialiseSockets();
int OpenUdpSocket(socket_t *sock, char *eventName, uint16 receivePort);
int OpenTcpSocket(socket_t *sock, char *eventName, uint16 receivePort);
void SetTcpAcceptCallback(socket_t *(*callback)(sockaddr_t *receivedFrom));
void SetTcpConnectCallback(void (*callback)(socket_t *sock));
int ReadFromDatagramSocket(socket_t *sock, packet_t *packet, sockaddr_t *receivedFrom);
int ReadFromStreamSocket(socket_t *sock, byte *buffer, int bufferLength);
int WriteToStreamSocket(socket_t *sock, byte *buffer, int bufferLength);
int SendToSocket(socket_t *sock, sockaddr_t *destination, packet_t *packet);
void CloseSocket(socket_t *sock);
sockaddr_t *GetSocketAddressFromName(char *hostName, uint16 port);
sockaddr_t *GetSocketAddressFromIpAddress(byte *address, uint16 port);

#define SOCKET_H
#endif
