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

// TODO: Don't try outbound connect again, if there is still an outbound connect in progress

#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include "route20.h"
#include "socket.h"
#if defined(WIN32)
#elif defined(__VAX)
#include inetdef
#else
#include <unistd.h>
#include <sys/time.h>
#endif

#define MAX_BUF_LEN 8192

static int started;
static int SockStartup(void);
static int GetSockError(void);
static void SockError(char *msg);
static int IsSockClosed(socket_t *sock);
static int IsSockConnected(socket_t *sock);
static int IsSockErrorConnReset(int err);
static int IsSockErrorConnAborted(int err);
static int IsSockErrorWouldBlock(int err);
static void SockErrorAndClear(char *msg);
static void SockErrorClear(void);
static void SetNonBlocking(socket_t *socket);
static int OpenSocket(socket_t *sock, char *eventName, uint16 receivePort, int type, int protocol);
static int ListenTcpSocket(socket_t *sock);
static int ConnectTcpSocket(socket_t *sock);
static void SetupSocketEvents(socket_t *sock, char *eventName, long events);
static void CompleteSocketDisconnection(socket_t *sock);
static void ProcessListenSocketEvent(void *context);
static void ProcessConnectSocketEvent(void *context);
#if defined(WIN32)
static void LogNetworkEvent(WSANETWORKEVENTS *networkEvents, char *name, int mask, int bitNo);
#endif
static void LogNetworkEvents(socket_t *sock);
static char *FormatAddr(sockaddr_t *addr);

static socket_t *(*tcpAcceptCallback)(sockaddr_t *receivedFrom);
static void (*tcpConnectCallback)(socket_t *sock);
static void (*tcpDisconnectCallback)(socket_t *sock);
static int lastSocketError = 0;

void InitialiseSockets(void)
{
	if (!started)
	{
		SockStartup();
	}

    InitialiseSocket(&ListenSocket, "TCPLISTEN");
	if (SocketConfig.socketConfigured)
	{
		if (OpenTcpSocketInbound(&ListenSocket, SocketConfig.tcpListenPort))
        {
		    RegisterEventHandler(ListenSocket.waitHandle, "TCP listen socket", NULL, ProcessListenSocketEvent);
        }
        else
        {
            Log(LogSock, LogError, "Unable to open TCP listen socket on port %d\n", SocketConfig.tcpListenPort);
        }
	}
}

void InitialiseSocket(socket_t *sock, char *eventName)
{
    sock->socket = INVALID_SOCKET;
    sock->waitHandle = (unsigned int)-1;
    sock->eventName = eventName;
}

int OpenUdpSocket(socket_t *sock, uint16 receivePort)
{
	int ans = OpenSocket(sock, sock->eventName, receivePort, SOCK_DGRAM, IPPROTO_UDP);

	return ans;
}

int OpenTcpSocketInbound(socket_t *sock, uint16 receivePort)
{
	int ans = OpenSocket(sock, sock->eventName, receivePort, SOCK_STREAM, IPPROTO_TCP);
	if (ans)
	{
		ans = ListenTcpSocket(sock);
	}

	return ans;
}

int OpenTcpSocketOutbound(socket_t *sock, sockaddr_t *address)
{
	int ans = OpenSocket(sock, sock->eventName, 0, SOCK_STREAM, IPPROTO_TCP);
	if (ans)
	{
        memcpy(&sock->remoteAddress, address, sizeof(sockaddr_t));
		ans = ConnectTcpSocket(sock);
        if (ans)
        {
		    RegisterEventHandler(sock->waitHandle, sock->eventName, sock, ProcessConnectSocketEvent);
        }
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
	socklen_t ilen;

	ans = 1;
	ilen = sizeof(*receivedFrom);
	packet->rawLen = recvfrom(sock->socket, (char *)buf, 1518, 0, receivedFrom, &ilen);
	if (packet->rawLen > 0)
	{
        if (IsLoggable(LogSock, LogVerbose)
        {
	        Log(LogSock, LogVerbose, "Read %d bytes on port %d\n", packet->rawLen, sock->receivePort);
		    LogBytes(LogSock, LogVerbose, buf, packet->rawLen);
        }
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
    if (!IsSockClosed(sock))
    {
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
                if (IsSockErrorConnReset(sockErr) || IsSockErrorConnAborted(sockErr))
                {
                    closed = 1;
                }
            }

            if (closed)
            {
                Log(LogSock, LogDetail, "Socket read failure due to unexpected closure of socket %s\n", sock->eventName);
                QueueImmediate(sock, (void (*)(void *))CompleteSocketDisconnection);
            }
            else if (!IsSockErrorWouldBlock(sockErr))
            {
                SockErrorAndClear("recv");
            }
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
			if (IsSockErrorWouldBlock(GetSockError()))
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
               Log(LogSock, LogDetail, "Socket write failure due to unexpected closure of socket %s\n", sock->eventName);
               QueueImmediate(sock, (void (*)(void *))CompleteSocketDisconnection);
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
			if (IsSockErrorWouldBlock(GetSockError()))
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

static void ClosePrimitiveSocket(uint_ptr sock)
{
#if defined(WIN32)
	closesocket(sock);
#else
	close(sock);
#endif
}

void CloseSocket(socket_t *sock)
{
#if defined(WIN32)
    if (sock->waitHandle != (unsigned int)-1)
    {
        CloseHandle((HANDLE)sock->waitHandle);
        sock->waitHandle = (unsigned int)-1;
    }
#endif
    ClosePrimitiveSocket(sock->socket);
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

static int IsSockClosed(socket_t *sock)
{
    return sock->socket == INVALID_SOCKET;
}

static int IsSockConnected(socket_t *sock)
{
    int ans = 0;
#if !defined(__VAX)
    fd_set readSet;
    fd_set writeSet;
    fd_set errorSet;
    struct timeval tz;

    timerclear (&tz);
    FD_ZERO (&readSet);
    FD_ZERO (&writeSet);
    FD_ZERO (&errorSet);
    FD_SET (sock->socket, &readSet);
    FD_SET (sock->socket, &writeSet);
    FD_SET (sock->socket, &errorSet);

    if (select ((int) sock->socket + 1, &readSet, &writeSet, &errorSet, &tz) == SOCKET_ERROR)
    {
        SockError("select");
    }
    else
    {
        ans = FD_ISSET(sock->socket, &writeSet);
    }

    /* Other possible techniques are to send zero bytes and to get the SO_ERROR socket option:

    ans = send(sock->socket, "", 0, 0) != SOCKET_ERROR;
    Log(LogSock, LogInfo, "Sendable %d\n", ans);
    if (getsockopt(sock->socket, SOL_SOCKET, SO_ERROR, (char *)&err, &errLen) == SOCKET_ERROR)
    {
        SockError("getsockopt");
    }
    Log(LogSock, LogInfo, "SO_ERROR %d\n", err);
    ans = err == 0;
    */
#endif

    return ans;
}

static int IsSockErrorConnReset(int err)
{
    int ans;
#if defined(WIN32)
    ans = err == WSAECONNRESET;
#else
	ans = err == ECONNRESET;
#endif

	return ans;
}

static int IsSockErrorConnAborted(int err)
{
    int ans;
#if defined(WIN32)
    ans = err == WSAECONNABORTED;
#else
	ans = 0;
#endif

	return ans;
}

static int IsSockErrorWouldBlock(int err)
{
    int ans;
#if defined(WIN32)
    ans = err == WSAEWOULDBLOCK;
#else
	ans = err == EWOULDBLOCK;
#endif

	return ans;
}

static void SockErrorAndClear(char *msg)
{
	SockError(msg);
	SockErrorClear();
}

static void SockErrorClear(void)
{
	lastSocketError = 0;
}

static void SetNonBlocking(socket_t *socket)
{
	/* this code from SIMH by Robert M Supnik */
#if defined(WIN32)
    unsigned long value = 1;
	ioctlsocket(socket->socket, FIONBIO, &value);
#elif defined(__VAX)
    int value = 1;
    int socketDeviceDescriptor = vaxc$get_sdc((int)socket->socket);
    if (socketDeviceDescriptor)
    {
        if (vaxc$socket_control(socketDeviceDescriptor, FIONBIO, &value) != 0)
        {
            Log(LogSock, LogError, "Failed to set non-blocking on socket, error=%d\n", errno);
        }
    }
    else
    {
        Log(LogSock, LogError, "Failed to get socket device descriptor\n");
    }
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

    Log(LogSock, LogVerbose, "Opening %s socket for %s, receive port is %d, protocol is %d\n", (type==SOCK_DGRAM) ? "UDP": "TCP", eventName, receivePort, protocol);
    InitialiseSocket(sock, eventName);
	sock->receivePort = receivePort;

	if (!started)
	{
		SockStartup();
	}

	if (started)
	{
		sock->socket = socket(AF_INET, type, protocol);
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
#if defined(WIN32)
				SetupSocketEvents(sock, eventName, FD_READ | FD_ACCEPT | FD_CONNECT);
#else
				SetupSocketEvents(sock, eventName, 0);
#endif
				if (sock->waitHandle == -1)
				{
                    Log(LogSock, LogError, "Closing opened socket because there is no wait handle, event name is %s\n", eventName);
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
	    Log(LogSock, LogDetail, "Listening for TCP connections on %d\n", sock->receivePort);
	}
	else
	{
        ans = 0;
		SockErrorAndClear("listen");
		CloseSocket(sock);
	}

	return ans;
}

static int ConnectTcpSocket(socket_t *sock)
{
	int ans = 1;

    if (connect(sock->socket, &sock->remoteAddress, sizeof(sockaddr_in_t)) == SOCKET_ERROR)
    {
        if (!IsSockErrorWouldBlock(GetSockError()))
        {
            ans = 0;
            SockErrorAndClear("connect");
            CloseSocket(sock);
        }
	}

    if (ans)
    {
	    Log(LogSock, LogDetail, "Connecting to TCP address %s\n", FormatAddr(&sock->remoteAddress));
    }

    return ans;
}

static void SetupSocketEvents(socket_t *sock, char *eventName, long events)
{
#if defined(WIN32)
    /* For outbound sockets we can change the events we are interested in and the event may already exist, so don't create it again */
    if (sock->waitHandle == (unsigned int)-1)
    {
	    sock->waitHandle = (int)CreateEvent(NULL, 0, 0, eventName);
	    Log(LogSock, LogDetail, "New wait handle for %s is %d\n", eventName, sock->waitHandle);
    }
    else
    {
	    Log(LogSock, LogDetail, "Reusing wait handle %d for %s\n", sock->waitHandle, eventName);
    }

	if (WSAEventSelect(sock->socket, (HANDLE)sock->waitHandle, events) == SOCKET_ERROR)
	{
		SockErrorAndClear("WSAEventSelect");
	}
#elif defined(__VAX)
    sock->waitHandle = sock->socket;
#else
	sock->waitHandle = sock->socket;
#endif
}

static void CompleteSocketDisconnection(socket_t *sock)
{
    if (!IsSockClosed(sock))
    {
        if (tcpDisconnectCallback != NULL)
        {
            tcpDisconnectCallback(sock);
        }

        CloseSocket(sock);
        Log(LogSock, LogDetail, "TCP connection on port %d closed\n", sock->receivePort);
    }
}

static void ProcessListenSocketEvent(void *context)
{
	socklen_t ilen;
    sockaddr_t receivedFrom;
	struct sockaddr_in  *inaddr;
	uint_ptr newSocket;

	Log(LogSock, LogDetail, "Processing TCP connection attempt on %d\n", ListenSocket.receivePort);
	ilen = sizeof(receivedFrom);
	newSocket = accept(ListenSocket.socket, &receivedFrom, &ilen);
	if (newSocket != INVALID_SOCKET)
	{
        int reject = 1;
		socket_t *sock = NULL;
		if (tcpAcceptCallback != NULL)
		{
			sock = tcpAcceptCallback(&receivedFrom);
            if (sock == NULL)
            {
    	        Log(LogSock, LogDetail, "TCP connection from %s rejected\n", FormatAddr(&receivedFrom));
            }
		}

		inaddr = (struct sockaddr_in *)&receivedFrom;

		if (sock != NULL)
		{
            reject = 0;
            if (sock->socket != INVALID_SOCKET)
            {
                if (IsSockConnected(sock))
                {
                    /* we have both an inbound request connected, and an outbound request connected, so we randomly reject one of them */
                    if (rand() < (RAND_MAX / 2))
                    {
                        /* reject inbound request */
    	                Log(LogSock, LogDetail, "Successful inbound and outbound connection, randomly rejecting inbound request from %s\n", FormatAddr(&receivedFrom));
                        reject = 1;
                    }
                    else
                    {
                        /* reject outbound connection */
    	                Log(LogSock, LogDetail, "Successful inbound and outbound connection, randomly rejecting outbound request from %s\n", FormatAddr(&receivedFrom));
                        ClosePrimitiveSocket(sock->socket);
                    }
                }
            }

            if (!reject)
            {
                Log(LogSock, LogDetail, "TCP connection from %s accepted\n", FormatAddr(&receivedFrom));
                sock->socket = newSocket;
                sock->receivePort = inaddr->sin_port;
                SetNonBlocking(sock);
#if defined(WIN32)
                SetupSocketEvents(sock, sock->eventName, FD_READ | FD_CLOSE);
#else
                SetupSocketEvents(sock, sock->eventName, 0);
#endif
                if (tcpConnectCallback != NULL)
                {
                    tcpConnectCallback(sock);
                }
            }
		}
		
        if (reject)
		{
			ClosePrimitiveSocket(newSocket);
		}
	}
}

static void ProcessConnectSocketEvent(void *context)
{
    socket_t *sock = (socket_t *)context;

    LogNetworkEvents(sock);

    Log(LogSock, LogDetail, "TCP connection to %s ", FormatAddr(&sock->remoteAddress));
    
    if (IsSockConnected(sock))
    {
        Log(LogSock, LogDetail, "connected\n");

        SetNonBlocking(sock);
#if defined(WIN32)
        SetupSocketEvents(sock, sock->eventName, FD_READ | FD_CLOSE);
#else
        SetupSocketEvents(sock, sock->eventName, 0);
#endif
        if (tcpConnectCallback != NULL)
        {
            tcpConnectCallback(sock);
        }
    }
    else
    {
        Log(LogSock, LogDetail, "failed or rejected\n");
        DeregisterEventHandler(sock->waitHandle);
        CloseSocket(sock);
    }
}

#if defined(WIN32)
static void LogNetworkEvent(WSANETWORKEVENTS *networkEvents, char *name, int mask, int bitNo)
{
    if ((networkEvents->lNetworkEvents & mask) != 0)
    {
        Log(LogSock, LogVerbose, "Socket event %s occurred, error code %d\n", name, networkEvents->iErrorCode[bitNo]);
    }
}
#endif

static void LogNetworkEvents(socket_t *sock)
{
#if defined(WIN32)
    WSANETWORKEVENTS NetworkEvents;

    WSAEnumNetworkEvents(sock->socket, NULL, &NetworkEvents);

    LogNetworkEvent(&NetworkEvents, "Connect", FD_CONNECT, FD_CONNECT_BIT);
    LogNetworkEvent(&NetworkEvents, "Close", FD_CLOSE, FD_CLOSE_BIT);
    LogNetworkEvent(&NetworkEvents, "Accept", FD_ACCEPT, FD_ACCEPT_BIT);
    LogNetworkEvent(&NetworkEvents, "Address list change", FD_ADDRESS_LIST_CHANGE, FD_ADDRESS_LIST_CHANGE_BIT);
    LogNetworkEvent(&NetworkEvents, "Group QOS", FD_GROUP_QOS, FD_GROUP_QOS_BIT);
    LogNetworkEvent(&NetworkEvents, "QOS", FD_QOS, FD_QOS_BIT);
    LogNetworkEvent(&NetworkEvents, "OOB", FD_OOB, FD_OOB_BIT);
    LogNetworkEvent(&NetworkEvents, "Read", FD_READ, FD_READ_BIT);
    LogNetworkEvent(&NetworkEvents, "Write", FD_WRITE, FD_WRITE_BIT);
    LogNetworkEvent(&NetworkEvents, "Routing interface change", FD_ROUTING_INTERFACE_CHANGE, FD_ROUTING_INTERFACE_CHANGE_BIT);
#endif
}

static char *FormatAddr(sockaddr_t *addr)
{
    sockaddr_in_t *inaddr = (sockaddr_in_t *)addr;
    static char buf[30];

    if (inaddr->sin_port != 0)
    {
        sprintf(buf, "%d.%d.%d.%d:%d", (inaddr->sin_addr.s_addr) & 0xFF, (inaddr->sin_addr.s_addr >> 8) & 0xFF, (inaddr->sin_addr.s_addr >> 16) & 0xFF, (inaddr->sin_addr.s_addr >> 24) & 0xFF, ntohs(inaddr->sin_port));
    }
    else
    {
        sprintf(buf, "%d.%d.%d.%d", (inaddr->sin_addr.s_addr) & 0xFF, (inaddr->sin_addr.s_addr >> 8) & 0xFF, (inaddr->sin_addr.s_addr >> 16) & 0xFF, (inaddr->sin_addr.s_addr >> 24) & 0xFF);
    }

    return buf;
}
