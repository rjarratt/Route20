/* session.c: Session support
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

#include <stdlib.h>
#include <memory.h>
#include "session.h"
#include "nsp.h"
#include "timer.h"

session_config_t SessionConfig;

#define MAX_SESSIONS 5
#define MAX_OBJECTS 3

#define REASON_DISCONNECT_BY_OBJECT 0
#define REASON_NETWORK_RESOURCES 1
#define REASON_UNRECOGNIZED_OBJECT 4

typedef struct
{
    int inUse;
    int objectType;
    int (*connectCallback)(void *session, decnet_address_t *remNode, byte *data, byte dataLength, uint16 *reason, byte **acceptData, byte *acceptDataLength);
    void (*closeCallback)(void *session);
    void (*dataCallback)(void *session, byte *data, uint16 dataLength);
} object_registration_t;

typedef struct
{
    int inUse;
    uint16                 locAddr;
    uint16                 remaddr;
    decnet_address_t       remNode;
    rtimer_t              *inactivityTimer; // TODO: Inactivity should be based on Confidence status from NSP rather than just this timer, this timer should be after confidence is low
    object_registration_t *objectRegistration;
} session_t;

static session_t SessionTable[MAX_SESSIONS];
static object_registration_t ObjectRegistrationTable[MAX_OBJECTS];

static void OpenPort(void);
static session_t *FindSession(uint16 locAddr);
static void HandleSessionInactivityTimer(rtimer_t *timer, char *name, void *context);

static void CloseCallback(uint16 locAddr);
static void ConnectCallback(decnet_address_t *remNode, uint16 locAddr, uint16 remAddr, byte *data, byte dataLength);
static void DataCallback(uint16 locAddr, byte *data, uint16 dataLength);

void SessionInitialise(void)
{
    unsigned int i;
    for (i = 0; i < MAX_SESSIONS; i++)
    {
        memset(&ObjectRegistrationTable[i], 0, sizeof(session_t));
    }

    for (i = 0; i < MAX_OBJECTS; i++)
    {
        memset(&SessionTable[i], 0, sizeof(object_registration_t));
    }

    OpenPort();
}

void SessionInitialiseConfig(void)
{
    SessionConfig.sessionInactivityTimeout = 60;
}

int SessionRegisterObjectType(byte objectType, int (*connectCallback)(void *session, decnet_address_t *remNode, byte *data, byte dataLength, uint16 *reason, byte **acceptData, byte *acceptDataLength), void (*closeCallback)(void *session), void (*dataCallback)(void *session, byte *data, uint16 dataLength))
{
    int result = 0;
    unsigned int i;
    object_registration_t *registration = NULL;
    for (i = 0; i < MAX_OBJECTS; i++)
    {
        if (!ObjectRegistrationTable[i].inUse)
        {
            registration = &ObjectRegistrationTable[i];
            break;
        }
    }

    if (registration != NULL)
    {
        Log(LogSession, LogVerbose, "Registered object type %hu\n", objectType);
        result = 1;
        registration->inUse = 1;
        registration->objectType = objectType;
        registration->connectCallback = connectCallback;
        registration->dataCallback = dataCallback;
        registration->closeCallback = closeCallback;
    }

    return result;
}

void SessionClose(void *session)
{
    session_t *s = (session_t * )session;
    NspClose(s->locAddr);
    OpenPort();
}

void SessionDataTransmit(void *session, byte *data, uint16 dataLength)
{
    session_t *s = (session_t *)session;
    ResetTimer(s->inactivityTimer);
    NspTransmit(s->locAddr, data, dataLength);
}

static session_t *FindSession(uint16 locAddr)
{
    unsigned int i;
    session_t *result = NULL;

    for (i = 0; i < MAX_SESSIONS; i++)
    {
        if (SessionTable[i].inUse && SessionTable[i].locAddr == locAddr)
        {
            result = &SessionTable[i];
            break;
        }
    }

    return result;
}

static void HandleSessionInactivityTimer(rtimer_t *timer, char *name, void *context)
{
    session_t *session = (session_t *)context;
    StopTimer(timer);
    if (session->inUse)
    {
        Log(LogSession, LogInfo, "Disconnecting session with ");
        LogDecnetAddress(LogSession, LogInfo, &session->remNode);
        Log(LogSession, LogInfo, " due to inactivity\n");
        NspDisconnect(session->locAddr, REASON_DISCONNECT_BY_OBJECT);
        // TODO: TimerCon in NSP to ensure we disconnect?
    }
}

static void ConnectCallback(decnet_address_t *remNode, uint16 locAddr, uint16 remAddr, byte *data, byte dataLength)
{
    unsigned int i;
    object_registration_t *registration = NULL;
    session_t *session = NULL;
    uint16 objectType = 0;
    
    if (dataLength >= 2)
    {
        objectType = BigEndianBytesToUint16(data);
        for (i = 0; i < MAX_OBJECTS; i++)
        {
            if (ObjectRegistrationTable[i].inUse && ObjectRegistrationTable[i].objectType == objectType)
            {
                registration = &ObjectRegistrationTable[i];
                break;
            }
        }
    }

    if (registration == NULL)
    {
        Log(LogSession, LogWarning, "Unable to start session because object type %hu is unknown\n", objectType);
        NspReject(remNode, locAddr, remAddr, REASON_UNRECOGNIZED_OBJECT, 0, NULL);
    }
    else
    {
        for (i = 0; i < MAX_SESSIONS; i++)
        {
            if (!SessionTable[i].inUse)
            {
                session = &SessionTable[i];
                break;
            }
        }

        if (session == NULL)
        {
            Log(LogSession, LogWarning, "Unable to start session for object type %hu because there are no more session slots available\n", objectType);
            NspReject(remNode, locAddr, remAddr, REASON_NETWORK_RESOURCES, 0, NULL);
        }
        else
        {
            uint16 reason;
            byte *acceptData;
            byte acceptDataLength;
            time_t now;
            if (registration->connectCallback((void *)session, remNode, NULL, 0, &reason, &acceptData, &acceptDataLength)) // TODO: probably should remove the object type and pass remaining data?
            {
                time(&now);
                session->inUse = 1;
                session->locAddr = locAddr;
                session->remaddr = remAddr;
                memcpy(&session->remNode, remNode, sizeof(decnet_address_t));
                session->objectRegistration = registration;
                session->inactivityTimer = CreateTimer("Session Inactivity Timer", now + SessionConfig.sessionInactivityTimeout, SessionConfig.sessionInactivityTimeout, session, HandleSessionInactivityTimer);
                NspAccept(locAddr, SERVICES_NONE, acceptDataLength, acceptData);
                Log(LogSession, LogInfo, "Starting session with ");
                LogDecnetAddress(LogSession, LogInfo, remNode);
                Log(LogSession, LogInfo, " for object type %d\n", registration->objectType);
            }
            else
            {
                Log(LogSession, LogWarning, "Unable to start session for object type %hu because the object rejected the session with reason=%hu\n", objectType, reason);
                NspReject(remNode, locAddr, remAddr, reason, 0, NULL);
            }
        }
    }
}

static void CloseCallback(uint16 locAddr)
{
    session_t *session = FindSession(locAddr);
    if (session != NULL)
    {
        StopTimer(session->inactivityTimer);
        session->objectRegistration->closeCallback(session);
        memset(session, 0, sizeof(session_t));
    }
}

static void DataCallback(uint16 locAddr, byte *data, uint16 dataLength)
{
    session_t *session = FindSession(locAddr);
    if (session != NULL)
    {
        ResetTimer(session->inactivityTimer);
        session->objectRegistration->dataCallback(session, data, dataLength);
    }
}

static void OpenPort(void)
{

    uint16 nspPort;
    int port = NspOpen(CloseCallback, ConnectCallback, DataCallback);
    if (port <= 0)
    {
        Log(LogSession, LogError, "Session could not open NSP port.\n");
    }
    else
    {
        nspPort = (uint16)port;
        Log(LogSession, LogVerbose, "Opened NSP port %hu\n", nspPort);
    }
}
