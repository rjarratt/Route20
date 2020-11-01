/* netman.c: Network Management support
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

#include <memory.h>
#include <string.h>
#include "constants.h"
#include "adjacency.h"
#include "forwarding.h"
#include "routing_database.h"
#include "platform.h"
#include "netman_messages.h"
#include "netman.h"
#include "nsp.h"

  // TODO: Check object type and reject objects not supported in connect callback

int numCircuits;

typedef struct
{
	uint16     srcPort;
	circuit_t *circuit;
	int        adjacentRoutersCount;
} AdjacentNodeCallbackData;

void OpenPort(void);
void CloseCallback(uint16 locAddr);
void ConnectCallback(decnet_address_t* remNode, uint16 locAddr, uint16 remAddr, byte* data, int dataLength);
void DataCallback(uint16 locAddr, byte *data, int dataLength);

static void ProcessReadInformationMessage(uint16 locAddr, netman_read_information_t *readInformation);
static void ProcessShowKnownCircuits(uint16 locAddr);
static void ProcessShowAdjacentNodes(uint16 locAddr);

static void SendAcceptWithMultipleResponses(uint16 locAddr);
static void SendDoneWithMultipleResponses(uint16 locAddr);
static void SendError(uint16 locAddr);

static int AdjacentNodeCircuitCallback(adjacency_t *adjacency, void *context);
static int AdjacentNodeCallback(adjacency_t *adjacency, void *context);
static void SendCircuitInfo(uint16 srcPort, circuit_t *circuit, decnet_address_t *address);
static void SendAdjacentNodeInfo(uint16 srcPort, circuit_t *circuit, decnet_address_t *address);
static void AddDecnetIdToResponse(byte *data, int *pos, decnet_address_t *address);
static void AddStringToResponse(byte *data, int *pos, char *s);

void NetManInitialise(void)
{
	OpenPort();
}

void OpenPort(void)
{
    uint16 nspPort;
	int port = NspOpen(CloseCallback, ConnectCallback, DataCallback);
	if (port <= 0)
	{
		Log(LogNetMan, LogError, "Network Management could not open NSP port.\n");
	}
	else
	{
		nspPort = (uint16)port;
		Log(LogNetMan, LogVerbose, "Opened NSP port %hu\n", nspPort);
	}
}

void CloseCallback(uint16 locAddr)
{
	Log(LogNetMan, LogVerbose, "NSP port %hu closed\n", locAddr);
	NspClose(locAddr);
	OpenPort();
}

void ConnectCallback(decnet_address_t *remNode, uint16 locAddr, uint16 remAddr, byte* data, int dataLength)
{
	byte acceptData[] = { NETMAN_VERSION, NETMAN_DEC_ECO, NETMAN_USER_ECO };

	Log(LogNetMan, LogVerbose, "Accepting on NSP port %hu\n", locAddr);
	NspAccept(locAddr, SERVICES_NONE, sizeof(acceptData), acceptData);
	//NspReject(remNode, locAddr, remAddr, 0, 0, NULL);
}

void DataCallback(uint16 locAddr, byte *data, int dataLength)
{
	int i;
	Log(LogNetMan, LogVerbose, "Data callback, data=", dataLength);
	for (i = 0; i < dataLength; i++)
	{
	    Log(LogNetMan, LogVerbose, "%02X", data[i]);
	}
	Log(LogNetMan, LogVerbose, "\n", data[i]);

	if (IsNetmanReadInformationMessage(data))
	{
		ProcessReadInformationMessage(locAddr, ParseNetmanReadInformation(data, dataLength));
	}

}

static void ProcessReadInformationMessage(uint16 locAddr, netman_read_information_t *readInformation)
{
	int isVolatile;
	NetmanInfoTypeCode infoType;
	NetmanEntityTypeCode entityType;
	int isKnown;
	int isAdjacent;

	isVolatile = (readInformation->option >> 7) == 0;
	infoType = (NetmanInfoTypeCode)((readInformation->option & 0x70) >> 4);
	entityType = (NetmanEntityTypeCode)(readInformation->option & 0x07);
	isKnown = readInformation->entity == 0xFF;
	isAdjacent = readInformation->entity == 0xFC;

	Log(LogNetMan, LogVerbose, "Read Information. Volatile = %d, Info Type = %d, EntityType = %d, Is Known = %d(0x%02X)\n", isVolatile, infoType, entityType, isKnown, readInformation->entity);

	if (isVolatile && infoType == NetmanSummaryInfoTypeCode && entityType == NetmanCircuitEntityTypeCode && isKnown)
	{
		ProcessShowKnownCircuits(locAddr);
	}
	else if (isVolatile && infoType == NetmanSummaryInfoTypeCode && entityType == NetmanNodeEntityTypeCode && isAdjacent)
	{
		ProcessShowAdjacentNodes(locAddr);
	}
	else
	{
		SendError(locAddr);
	}
}

static void SendAcceptWithMultipleResponses(uint16 locAddr)
{
	byte responseData[256];

	memset(responseData, 0, 13);
	responseData[0] = 2; /* Accept with multiple responses */
	responseData[1] = 0xFF;
	responseData[2] = 0xFF;
	NspTransmit(locAddr, responseData, 4);
}

static void SendDoneWithMultipleResponses(uint16 locAddr)
{
	byte responseData[256];

	memset(responseData, 0, 13);
	responseData[0] = 0x80; /* Done with multiple responses */
	NspTransmit(locAddr, responseData, 4);
}

static void SendError(uint16 locAddr)
{
	byte responseData[256];

	memset(responseData, 0, 13);
	responseData[0] = 0xFF; /* Unrecognized function or option */
	responseData[1] = 0xFF;
	responseData[2] = 0xFF;
	NspTransmit(locAddr, responseData, 4);
}

static void ProcessShowKnownCircuits(uint16 locAddr)
{
    // TODO: Reports eth0 multiple times if more than one adjacency is up on eth0
	int i;

	Log(LogNetMan, LogInfo, "Processing SHOW KNOWN CIRCUITS for port %hu\n", locAddr);

	SendAcceptWithMultipleResponses(locAddr);

	for(i = 1; i <= numCircuits; i++)
	{
		circuit_t *circuit = &Circuits[i];
		if (circuit->state == CircuitStateUp)
		{
			AdjacentNodeCallbackData context;
			context.srcPort = locAddr;
			context.circuit = circuit;
			context.adjacentRoutersCount = 0;
			ProcessRouterAdjacencies(AdjacentNodeCircuitCallback, &context);
			if (context.adjacentRoutersCount <= 0)
			{
				SendCircuitInfo(locAddr, circuit, NULL);
			}
		}
		else
		{
			SendCircuitInfo(locAddr, circuit, NULL);
		}
	}

	SendDoneWithMultipleResponses(locAddr);
}

static void ProcessShowAdjacentNodes(uint16 locAddr)
{
	int i;

	Log(LogNetMan, LogInfo, "Processing SHOW ADJACENT NODES for port %hu\n", locAddr);

	SendAcceptWithMultipleResponses(locAddr);

	for(i = 1; i <= numCircuits; i++)
	{
		circuit_t *circuit = &Circuits[i];
		if (circuit->state == CircuitStateUp)
		{
			AdjacentNodeCallbackData context;
			context.srcPort = locAddr;
			context.circuit = circuit;
			ProcessRouterAdjacencies(AdjacentNodeCallback, &context);
		}
		else
		{
			SendCircuitInfo(locAddr, circuit, NULL);
		}
	}

	SendDoneWithMultipleResponses(locAddr);
}

static int AdjacentNodeCircuitCallback(adjacency_t *adjacency, void *context)
{
	AdjacentNodeCallbackData *callbackData = (AdjacentNodeCallbackData *)context;
	if (callbackData->circuit == adjacency->circuit)
	{
		callbackData->adjacentRoutersCount++;
		SendCircuitInfo(callbackData->srcPort, callbackData->circuit, &adjacency->id);
	}

	return 1;
}

static int AdjacentNodeCallback(adjacency_t *adjacency, void *context)
{
	AdjacentNodeCallbackData *callbackData = (AdjacentNodeCallbackData *)context;
	if (callbackData->circuit == adjacency->circuit)
	{
		SendAdjacentNodeInfo(callbackData->srcPort, callbackData->circuit, &adjacency->id);
	}

	return 1;
}

static void SendCircuitInfo(uint16 srcPort, circuit_t *circuit, decnet_address_t *address)
{
	byte responseData[512];
	int len = 0;
	memset(responseData, 0, sizeof(responseData));
	responseData[len++] = 1; /* Success */
	responseData[len++] = 0xFF;
	responseData[len++] = 0xFF;
	responseData[len++] = 0;
	AddStringToResponse(responseData, &len, circuit->name);

	/* Circuit State */
	responseData[len++] = 0;
	responseData[len++] = 0;
	responseData[len++] = 0x81;
	responseData[len++] = circuit->state == CircuitStateUp ? 0 : 1;

	if (address != NULL)
	{
		responseData[len++] = 0x20;  /* DataId = Adjacent node */
		responseData[len++] = 0x03;  /* DataId = Adjacent node */
		responseData[len++] = 0xC1;  /* Data Type Coded Multiple Fields (1 fields) */
		responseData[len++] = 0x02;  /* length of DECnet ID */
		AddDecnetIdToResponse(responseData, &len, address);
	}

	NspTransmit(srcPort, responseData, len);
}

static void SendAdjacentNodeInfo(uint16 srcPort, circuit_t *circuit, decnet_address_t *address)
{
	byte responseData[512];
	int len = 0;
	memset(responseData, 0, sizeof(responseData));
	responseData[len++] = 1; /* Success */
	responseData[len++] = 0xFF;
	responseData[len++] = 0xFF;
	responseData[len++] = 0;
	AddDecnetIdToResponse(responseData, &len, address);
	responseData[len++] = 0; /* length of name - not supplying it */

	/* Node state */
	responseData[len++] = 0;
	responseData[len++] = 0;
	responseData[len++] = 0x81;
	responseData[len++] = IsReachable(address) ? 4 : 5;

	/* Circuit */
	responseData[len++] = 0x36; /* DataId = Circuit */
	responseData[len++] = 0x03; /* DataId = Circuit */
	responseData[len++] = 0x40;
	AddStringToResponse(responseData, &len, circuit->name);

	NspTransmit(srcPort, responseData, len);
}

static void AddDecnetIdToResponse(byte *data, int *pos, decnet_address_t *address)
{
		uint16 id = Uint16ToLittleEndian(GetDecnetId(*address));
		memcpy(&data[*pos], &id, sizeof(uint16));
		*pos = *pos + sizeof(uint16);
}

static void AddStringToResponse(byte *data, int *pos, char *s)
{
	int len = (int)strlen(s);
	data[(*pos)++] = (byte)len;
	strcpy((char *)(&data[*pos]), s);
	*pos = *pos +len;
}