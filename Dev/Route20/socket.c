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
#include "route20.h"
#include "socket.h"

#define MAX_BUF_LEN 8192

static int started;
static int SockStartup(void);
static int GetSockError(void);
static void SockError(char *msg);
static void SockErrorAndClear(char *msg);
static void SockErrorClear();
static void SetNonBlocking(socket_t *socket);
static int OpenSocket(socket_t *sock, char *eventName, uint16 receivePort, int type, int protocol);
static int ListenTcpSocket(socket_t *sock);
static void SetupSocketEvents(socket_t *sock, char *eventName, long events);
static void ProcessListenSocketEvent(void *context);

static socket_t *(*tcpAcceptCallback)(sockaddr_t *receivedFrom);
static void (*tcpConnectCallback)(socket_t *sock);
static void (*tcpDisconnectCallback)(socket_t *sock);
static int lastSocketError = 0;

void InitialiseSockets()
{
	if (!started)
	{
		SockStartup();
	}

	ListenSocket.socket = INVALID_SOCKET;
	ListenSocket.waitHandle = (unsigned int)-1;
	if (SocketConfig.socketConfigured)
	{
		if (OpenTcpSocket(&ListenSocket, "TCPLISTEN", SocketConfig.tcpListenPort))
        {
		    RegisterEventHandler(ListenSocket.waitHandle, "TCP socket", NULL, ProcessListenSocketEvent);
        }
        else
        {
            Log(LogSock, LogError, "Unable to open TCP socket on port %d\n", SocketConfig.tcpListenPort);
        }
	}
}

int OpenUdpSocket(socket_t *sock, char *eventName, uint16 receivePort)
{
	int ans = OpenSocket(sock, eventName, receivePort, SOCK_DGRAM, 0);

	return ans;
}

int OpenTcpSocket(socket_t *sock, char *eventName, uint16 receivePort)
{
	int ans = OpenSocket(sock, eventName, receivePort, SOCK_STREAM, IPPROTO_TCP);
	if (ans)
	{
		ans = ListenTcpSocket(sock);
	}

	return ans;
}

void SetTcpAcceptCallback(socket_t * (*callback)(sockaddr_t *receivedFrom))
{
	tcpAcceptCallback = callback;
}

void SetTcpConnectCallback(void (*callback)(socket_t *sock))
{
	tcpConnectCallback = callback;
}

void SetTcpDisconnectCallback(void (*callback)(socket_t *sock))
{
	tcpDisconnectCallback = callback;
}

int ReadFromDatagramSocket(socket_t *sock, packet_t *packet, sockaddr_t *receivedFrom)
{
	static byte buf[8192];
	int ans;
	int ilen;

	ans = 1;
	ilen = sizeof(*receivedFrom);
	packet->rawLen = recvfrom(sock->socket, (char *)buf, 1518, 0, receivedFrom, &ilen);
	if (packet->rawLen > 0)
	{
	    Log(LogSock, LogVerbose, "Read %d bytes on port %d\n", packet->rawLen, sock->receivePort);
		LogBytes(LogSock, LogVerbose, buf, packet->rawLen);
		packet->rawData = buf;
	}
	else
	{
		ans = 0;
	}

	return  ans;
}

int ReadFromStreamSocket(socket_t *sock, byte *buffer, int bufferLength)
{
	int ans;
	int bytesRead;

	ans = 0;
	bytesRead = recv(sock->socket, (char *)buffer, bufferLength, 0);
	if (bytesRead > 0)
	{
	    Log(LogSock, LogVerbose, "Read %d bytes on port %d\n", bytesRead, sock->receivePort);
		LogBytes(LogSock, LogVerbose, buffer, bytesRead);
	    ans = bytesRead;
	}
	else
    {
        int closed = 0;
        int sockErr = 0;
        if (bytesRead == 0)
        {
            closed = 1;
        }
        else
        {
            sockErr = GetSockError();
            if (sockErr == WSAECONNRESET || sockErr == WSAECONNABORTED)
            {
                closed = 1;
            }
        }

        if (closed)
        {
            Log(LogSock, LogWarning, "TCP connection on port %d closed\n", sock->receivePort);
            CloseSocket(sock);
            if (tcpDisconnectCallback != NULL)
            {
                tcpDisconnectCallback(sock);
            }
        }
        else if (sockErr != WSAEWOULDBLOCK) // TODO: will need to make this work right on Linux, where it is EWOULDBLOCK
        {
            SockErrorAndClear("recv");
        }
    }

	return ans;
}

int WriteToStreamSocket(socket_t *sock, byte *buffer, int bufferLength)
{
    int ans = 1;
    int totalBytesSent = 0;
    
    do
    {
        int sentBytes = send(sock->socket, (char *)buffer + totalBytesSent, bufferLength - totalBytesSent, 0);
        if (sentBytes == SOCKET_ERROR)
        {
            int retry = 0;
#if defined(WIN32)
			if (WSAGetLastError() == WSAEWOULDBLOCK) // TODO: abstracted wouldblock check elsewhere now.
			{
				retry = 1;
				Sleep(1);
			}
			else
			{
				retry = 0;
				SockError("send");
			}
#else
			SockError("send");
#endif
			if (!retry)
            {
                Log(LogSock, LogWarning, "TCP connection on port %d closed\n", sock->receivePort);
                CloseSocket(sock);
                if (tcpDisconnectCallback != NULL)
                {
                    tcpDisconnectCallback(sock);
                }

                ans = 0;
                break;
            }
        }
        else
        {
    	    Log(LogSock, LogVerbose, "Wrote %d bytes on port %d\n", sentBytes, sock->receivePort);
		    LogBytes(LogSock, LogVerbose, buffer + totalBytesSent, sentBytes);
            totalBytesSent += sentBytes;
        }

    }
    while (totalBytesSent < bufferLength);

	return ans;
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
			if (WSAGetLastError() == WSAEWOULDBLOCK) // TODO: abstracted wouldblock check elsewhere now.
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
    	    Log(LogSock, LogVerbose, "Wrote %d bytes on port %d\n", packet->rawLen, sock->receivePort);
		    LogBytes(LogSock, LogVerbose, packet->rawData, packet->rawLen);
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
    if (sock->waitHandle != (unsigned int)-1)
    {
        CloseHandle((HANDLE)sock->waitHandle);
    }
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

static int GetSockError(void)
{
#if defined(WIN32)
	int err = WSAGetLastError ();
#else
	int err = errno;
#endif

	return err;
}

static void SockError(char *msg)
{
	int err = GetSockError();

	if (lastSocketError != err)
	{
	    Log(LogSock, LogError, "Sockets: %s error %d\n", msg, err);
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

static int OpenSocket(socket_t *sock, char *eventName, uint16 receivePort, int type, int protocol)
{
	sockaddr_in_t sa;

	sock->socket = INVALID_SOCKET;
	sock->waitHandle = (unsigned int)-1;
	sock->receivePort = receivePort;

	if (!started)
	{
		SockStartup();
	}

	if (started)
	{
		sock->socket = socket(PF_INET, type, protocol);
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
				SockErrorAndClear("bind");
				CloseSocket(sock);
			}
			else
			{
				SetupSocketEvents(sock, eventName, FD_READ | FD_ACCEPT);
				if (sock->waitHandle == -1)
				{
					CloseSocket(sock);
				}
			}
		}
	}

	return sock->socket != INVALID_SOCKET;
}

static int ListenTcpSocket(socket_t *sock)
{
	int ans = 1;
	if (listen(sock->socket, 5) != SOCKET_ERROR)
	{
	    Log(LogSock, LogVerbose, "Listening for TCP connections on %d\n", sock->receivePort);
	}
	else
	{
		SockErrorAndClear("listen");
		CloseSocket(sock);
	}

	return ans;
}

static void SetupSocketEvents(socket_t *sock, char *eventName, long events)
{
#if defined(WIN32)
	sock->waitHandle = (int)CreateEvent(NULL, 0, 0, eventName);
	//Log(LogSock, LogVerbose, "Wait handle for port %d is %d\n", sock->receivePort, sock->waitHandle);
	if (WSAEventSelect(sock->socket, (HANDLE)sock->waitHandle, events) == SOCKET_ERROR)
	{
		SockErrorAndClear("WSAEventSelect");
	}
#else
	sock->waitHandle = sock->socket;
#endif
}

static void ProcessListenSocketEvent(void *context)
{
	int ilen;
    sockaddr_t receivedFrom;
	struct sockaddr_in  *inaddr;
	unsigned int newSocket;

	Log(LogSock, LogVerbose, "Processing TCP connection attempt on %d\n", ListenSocket.receivePort);
	ilen = sizeof(receivedFrom);
	newSocket = accept(ListenSocket.socket, &receivedFrom, &ilen);
	if (newSocket != INVALID_SOCKET)
	{
		socket_t *sock = NULL;
		if (tcpAcceptCallback != NULL)
		{
			sock = tcpAcceptCallback(&receivedFrom);
		}

		inaddr = (struct sockaddr_in *)&receivedFrom;

		if (sock != NULL)
		{
	        Log(LogSock, LogWarning, "TCP connection from %d.%d.%d.%d accepted\n", inaddr->sin_addr.S_un.S_un_b.s_b1, inaddr->sin_addr.S_un.S_un_b.s_b2, inaddr->sin_addr.S_un.S_un_b.s_b3, inaddr->sin_addr.S_un.S_un_b.s_b4);
			sock->socket = newSocket;
			sock->receivePort = inaddr->sin_port;
			SetNonBlocking(sock);
			SetupSocketEvents(sock, NULL, FD_READ | FD_CLOSE); // TODO: DDCMP event name, ought to come from ddcmp circuit, but not available here and name is not essential, could move eventName to socket structure but not valid for eth_pcap
			if (tcpConnectCallback != NULL)
			{
				tcpConnectCallback(sock);
			}

		}
		else
		{
	        Log(LogSock, LogWarning, "TCP connection from %d.%d.%d.%d rejected\n", inaddr->sin_addr.S_un.S_un_b.s_b1, inaddr->sin_addr.S_un.S_un_b.s_b2, inaddr->sin_addr.S_un.S_un_b.s_b3, inaddr->sin_addr.S_un.S_un_b.s_b4);
			closesocket(newSocket);
		}
	}
}
