/* socket.c: Socket support
  ------------------------------------------------------------------------------

   Copyright (c) 2012, Robert M. A. Jarratt
   Portions: Robert M Supnik

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
#include <errno.h>
#include "platform.h"
#include "socket.h"

static int started;
static int SockStartup(void);
static void SockError(char *msg);
static void SockErrorAndClear(char *msg);
static void SockErrorClear();
static void SetNonBlocking(socket_t *socket);

static int lastSocketError = 0;

int OpenUdpSocket(socket_t *sock, char *eventName, uint16 receivePort)
{
	sockaddr_in_t sa;

	sock->socket = INVALID_SOCKET;
	sock->waitHandle = (unsigned int)-1;

	if (!started)
	{
		SockStartup();
	}

	if (started)
	{
		sock->socket = socket(PF_INET, SOCK_DGRAM, 0);
		if (sock->socket == INVALID_SOCKET)
		{
			SockErrorAndClear("socket");
		}
		else
		{
			SetNonBlocking(sock);
			sa.sin_family = AF_INET;
			sa.sin_port = htons(receivePort);
			sa.sin_addr.s_addr = INADDR_ANY; /* TODO: use specific interface? */
			if (bind(sock->socket, (sockaddr_t*)&sa, sizeof(sa)) == -1)
			{
				CloseSocket(sock);
				SockErrorAndClear("bind");
			}
			else
			{
#if defined(WIN32)
				sock->waitHandle = (int)CreateEvent(NULL, 0, 0, eventName);
				if (WSAEventSelect(sock->socket, (HANDLE)sock->waitHandle, FD_READ) == SOCKET_ERROR)
				{
					SockErrorAndClear("WSAEventSelect");
				}
#else
				sock->waitHandle = sock->socket;
#endif
				if (sock->waitHandle == -1)
				{
					CloseSocket(sock);
				}
			}
		}
	}

	return sock->socket != INVALID_SOCKET;
}

int ReadFromSocket(socket_t *sock, packet_t *packet, sockaddr_t *receivedFrom)
{
	static byte buf[8192];
	int ans;
	int ilen;

	ans = 1;
	ilen = sizeof(*receivedFrom);
	packet->rawLen = recvfrom(sock->socket, (char *)buf, 1518, 0, receivedFrom, &ilen);
	if (packet->rawLen > 0)
	{
		packet->rawData = buf;
	}
	else
	{
		ans = 0;
	}

	return  ans;
}

int SendToSocket(socket_t *sock, sockaddr_t *destination, packet_t *packet)
{
	int ans = 0;
	int retry = 0;

	do
	{
		if (sendto(sock->socket, (char *)packet->rawData, packet->rawLen, 0, destination, sizeof(*destination)) == -1)
		{
#if defined(WIN32)
			if (WSAGetLastError() == WSAEWOULDBLOCK)
			{
				retry = 1;
				Sleep(1);
			}
			else
			{
				retry = 0;
				SockError("sendto");
			}
#else
			SockError("sendto");
#endif
		}
		else
		{
			ans = 1;
			retry = 0;
		}
	}
	while (retry);

	SockErrorClear();

	return ans;
}

void CloseSocket(socket_t *sock)
{
#if defined(WIN32)
	closesocket(sock->socket);
#else
	close(sock->socket);
#endif
	sock->socket = INVALID_SOCKET;
}

sockaddr_t *GetSocketAddressFromName(char *hostName, uint16 port)
{
	static sockaddr_in_t sa;
	sockaddr_t *ans;
	hostent_t *he;

	if (!started)
	{
		SockStartup();
	}

	he = gethostbyname(hostName);
	if (he != NULL)
	{
		rinaddr_t *addr;
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		addr = (rinaddr_t *)(he->h_addr);
		sa.sin_addr.s_addr = addr->s_addr;
		ans = (sockaddr_t *)&sa;
	}
	else
	{
		SockErrorAndClear("gethostbyname");
		ans = NULL;
	}

	return ans;
}

sockaddr_t *GetSocketAddressFromIpAddress(byte *address, uint16 port)
{
	static struct sockaddr_in sa;
	rinaddr_t *addr;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	addr = (rinaddr_t *)(address);
	sa.sin_addr.s_addr = addr->s_addr;

	return (sockaddr_t *)&sa;
}

static int SockStartup(void)
{
#if defined(WIN32)
	WSADATA wsaData;
	WORD wVersionRequested; 
	int err;
	wVersionRequested = MAKEWORD (1, 1); 

	SockErrorClear();

	err = WSAStartup (wVersionRequested, &wsaData);
	if (err != 0)
	{
		SockErrorAndClear("startup");
	}
	else
	{
		started = 1;
	}
#else
	started = 1;
#endif

	return started;
}

static void SockError(char *msg)
{
#if defined(WIN32)
	int err = WSAGetLastError ();
#else
	int err = errno;
#endif

	if (lastSocketError != err)
	{
	    Log(LogError, "Sockets: %s error %d\n", msg, err);
		lastSocketError = err;
	}
}

static void SockErrorAndClear(char *msg)
{
	SockError(msg);
	SockErrorClear();
}

static void SockErrorClear()
{
	lastSocketError = 0;
}

static void SetNonBlocking(socket_t *socket)
{
	/* this code from SIMH by Robert M Supnik */
#if defined(WIN32)
    unsigned long value = 1;
	ioctlsocket(socket->socket, FIONBIO, &value);
#else
    int flags;
	int status;

    flags = fcntl(socket->socket, F_GETFL, 0);
    if (flags == -1)
	{
		SockErrorAndClear("fcntl");
	}
	else
	{
		status = fcntl(socket->socket, F_SETFL, flags | O_NONBLOCK);
		if (status == -1)
		{
		    SockErrorAndClear("fcntl");
		}
	}
#endif
}
