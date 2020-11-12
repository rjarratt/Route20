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
#include "session.h"

#define OBJECT_NML 19

#define ENTITY_TYPE_NODE_C_IDENTIFICATION 100
#define ENTITY_TYPE_NODE_C_MANAGEMENT_VERSION 101
#define ENTITY_TYPE_NODE_C_TYPE 901
#define ENTITY_TYPE_NODE_S_CIRCUIT 822

#define ENTITY_TYPE_CIRCUIT_S_ADJACENT_NODE 800
#define ENTITY_TYPE_CIRCUIT_S_BLOCK_SIZE 810

#define DATA_TYPE_C(n) (0x80 | n)
#define DATA_TYPE_AI 0x40
#define DATA_TYPE_DU(n) (0x00 | n)
#define DATA_TYPE_CM(n) (0xC0 | n)

int numCircuits;

typedef enum
{
	SignificantNodes = 0xFB,
	AdjacentNodes = 0xFC,
	LoopNodes = 0xFD,
	ActiveNodes = 0xFE,
	KnownNodes = 0xFF,
	NodeAddress = 0
} NodeFormat;

typedef struct
{
	decnet_address_t  remNode;
	void             *session;
} nice_session_t;

typedef struct
{
	nice_session_t *niceSession;
	circuit_t      *circuit;
	int             adjacentRoutersCount;
} AdjacentNodeCallbackData;

static nice_session_t NiceSessions; // TODO: allow more than one concurrent NICE session

void OpenPort(void);
int ConnectCallback(void *session, decnet_address_t *remNode, byte *data, byte dataLength, uint16 *reason, byte **acceptData, byte *acceptDataLength);
void DataCallback(void *session, byte *data, uint16 dataLength);
void CloseCallback(void *session);

static void ProcessReadInformationMessage(nice_session_t *niceSession, netman_read_information_t *readInformation);
static void ProcessShowKnownCircuits(nice_session_t *niceSession);
static void ProcessShowAdjacentNodes(nice_session_t *niceSession);
static void ProcessShowExecutorCharacteristics(nice_session_t *niceSession);

static void SendAcceptWithMultipleResponses(nice_session_t *niceSession);
static void SendDoneWithMultipleResponses(nice_session_t *niceSession);
static void SendError(nice_session_t *niceSession);

static int AdjacentNodeCircuitCallback(adjacency_t *adjacency, void *context);
static int AdjacentNodeCallback(adjacency_t *adjacency, void *context);
static void SendCircuitInfo(nice_session_t *niceSession, circuit_t *circuit, decnet_address_t *address);
static void SendAdjacentNodeInfo(nice_session_t *niceSession, circuit_t *circuit, decnet_address_t *address);
static void StartDataBlockResponse(byte* data, uint16* pos);
static void AddDecnetIdToResponse(byte* data, uint16 * pos, decnet_address_t* address);
static void AddEntityTypeAndDataTypeToResponse(byte* data, uint16 * pos, uint16 entityType, byte dataType);
static void AddStringToResponse(byte *data, uint16 *pos, char *s);

void NetManInitialise(void)
{
	SessionRegisterObjectType(OBJECT_NML, ConnectCallback, CloseCallback, DataCallback);
}

int ConnectCallback(void *session, decnet_address_t *remNode, byte *data, byte dataLength, uint16 *reason, byte **acceptData, byte *acceptDataLength)
{
	static byte niceAcceptData[] = { NETMAN_VERSION, NETMAN_DEC_ECO, NETMAN_USER_ECO };
	nice_session_t *niceSession = &NiceSessions;
	int result = 1;

	Log(LogNetMan, LogVerbose, "Accepting session from ");
	LogDecnetAddress(LogNetMan, LogVerbose, remNode);
	Log(LogNetMan, LogVerbose, "\n");

	memcpy(&niceSession->remNode, remNode, sizeof(decnet_address_t));
	niceSession->session = session;

	*acceptData = niceAcceptData;
	*acceptDataLength = sizeof(niceAcceptData);

	return result;
}

void DataCallback(void *handle, byte *data, uint16 dataLength)
{
	nice_session_t *niceSession = &NiceSessions;

	Log(LogNetMan, LogVerbose, "Received data from ");
	LogDecnetAddress(LogNetMan, LogVerbose, &niceSession->remNode);
	Log(LogNetMan, LogVerbose, ", data = ");
	LogBytes(LogNetMan, LogVerbose, data, dataLength);

	if (IsNetmanReadInformationMessage(data))
	{
		ProcessReadInformationMessage(niceSession, ParseNetmanReadInformation(data, dataLength));
	}
}

void CloseCallback(void *session)
{
	nice_session_t *niceSession = &NiceSessions;

	Log(LogNetMan, LogVerbose, "Session with ");
	LogDecnetAddress(LogNetMan, LogVerbose, &niceSession->remNode);
	Log(LogNetMan, LogVerbose, " closed\n");
	SessionClose(session);
}

static void ProcessReadInformationMessage(nice_session_t *niceSession, netman_read_information_t *readInformation)
{
	int isVolatile;
	NetmanInfoTypeCode infoType;
	NetmanEntityTypeCode entityType;
	NodeFormat nodeFormat;
	char* nodeFormatStr;

	isVolatile = (readInformation->option >> 7) == 0;
	infoType = (NetmanInfoTypeCode)((readInformation->option & 0x70) >> 4);
	entityType = (NetmanEntityTypeCode)(readInformation->option & 0x07);
	nodeFormat = readInformation->entity;

	switch (nodeFormat)
	{
		case SignificantNodes: { nodeFormatStr = "Significant Nodes"; break; }
		case AdjacentNodes: { nodeFormatStr = "Adjacent Nodes"; break; }
		case LoopNodes: { nodeFormatStr = "Loop Nodes"; break; }
		case ActiveNodes: { nodeFormatStr = "Active Nodes"; break; }
		case KnownNodes: { nodeFormatStr = "Known Nodes"; break; }
		case NodeAddress: { nodeFormatStr = "Node Address"; break; }
		default: { nodeFormatStr = "Length of node name"; break; }
	}
	Log(LogNetMan, LogVerbose, "Read Information. Volatile = %d, Info Type = %d, EntityType = %d, Node Format = %s(0x%02X)\n", isVolatile, infoType, entityType, nodeFormatStr, readInformation->entity);

	if (isVolatile && (infoType == NetmanSummaryInfoTypeCode || infoType == NetmanStatusInfoTypeCode) && entityType == NetmanCircuitEntityTypeCode && nodeFormat == KnownNodes)
	{
		ProcessShowKnownCircuits(niceSession);
	}
	else if (isVolatile && (infoType == NetmanSummaryInfoTypeCode || infoType == NetmanStatusInfoTypeCode) && entityType == NetmanNodeEntityTypeCode && (nodeFormat == AdjacentNodes || nodeFormat == ActiveNodes))
	{
		ProcessShowAdjacentNodes(niceSession);
	}
	else if (isVolatile && infoType == NetmanCharacteristicsInfoTypeCode && entityType == NetmanNodeEntityTypeCode)
	{
		ProcessShowExecutorCharacteristics(niceSession);
	}
	else
	{
		SendError(niceSession);
	}
}

static void SendAcceptWithMultipleResponses(nice_session_t *niceSession)
{
	byte responseData[256];

	memset(responseData, 0, 13);
	responseData[0] = 2; /* Accept with multiple responses */
	responseData[1] = 0xFF;
	responseData[2] = 0xFF;
	SessionDataTransmit(niceSession->session, responseData, 4);
}

static void SendDoneWithMultipleResponses(nice_session_t *niceSession)
{
	byte responseData[256];

	memset(responseData, 0, 13);
	responseData[0] = 0x80; /* Done with multiple responses */
	SessionDataTransmit(niceSession->session, responseData, 4);
}

static void SendError(nice_session_t *niceSession)
{
	byte responseData[256];

	memset(responseData, 0, 13);
	responseData[0] = 0xFF; /* Unrecognized function or option */
	responseData[1] = 0xFF;
	responseData[2] = 0xFF;
	SessionDataTransmit(niceSession->session, responseData, 4);
}

static void ProcessShowKnownCircuits(nice_session_t *niceSession)
{
    // TODO: Reports eth0 multiple times if more than one adjacency is up on eth0
	int i;

	Log(LogNetMan, LogInfo, "Processing SHOW KNOWN CIRCUITS from ");
	LogDecnetAddress(LogNetMan, LogInfo, &niceSession->remNode);
	Log(LogNetMan, LogInfo, "\n");

	SendAcceptWithMultipleResponses(niceSession);

	for(i = 1; i <= numCircuits; i++)
	{
		circuit_t *circuit = &Circuits[i];
		if (circuit->state == CircuitStateUp)
		{
			AdjacentNodeCallbackData context;
			context.niceSession = niceSession;
			context.circuit = circuit;
			context.adjacentRoutersCount = 0;
			ProcessRouterAdjacencies(AdjacentNodeCircuitCallback, &context);
			if (context.adjacentRoutersCount <= 0)
			{
				SendCircuitInfo(niceSession, circuit, NULL);
			}
		}
		else
		{
			SendCircuitInfo(niceSession, circuit, NULL);
		}
	}

	SendDoneWithMultipleResponses(niceSession);
}

static void ProcessShowAdjacentNodes(nice_session_t *niceSession)
{
	int i;

	Log(LogNetMan, LogInfo, "Processing SHOW ADJACENT NODES from ");
	LogDecnetAddress(LogNetMan, LogInfo, &niceSession->remNode);
	Log(LogNetMan, LogInfo, "\n");

	SendAcceptWithMultipleResponses(niceSession);

	for(i = 1; i <= numCircuits; i++)
	{
		circuit_t *circuit = &Circuits[i];
		if (circuit->state == CircuitStateUp)
		{
			AdjacentNodeCallbackData context;
			context.niceSession = niceSession;
			context.circuit = circuit;
			ProcessRouterAdjacencies(AdjacentNodeCallback, &context);
		}
		else
		{
			SendCircuitInfo(niceSession, circuit, NULL);
		}
	}

	SendDoneWithMultipleResponses(niceSession);
}

static void ProcessShowExecutorCharacteristics(nice_session_t *niceSession)
{
	byte responseData[512];
	uint16 len;

	Log(LogNetMan, LogInfo, "Processing SHOW EXECUTOR CHARACTERISTICS from ");
	LogDecnetAddress(LogNetMan, LogInfo, &niceSession->remNode);
	Log(LogNetMan, LogInfo, "\n");

	SendAcceptWithMultipleResponses(niceSession);

	memset(responseData, 0, sizeof(responseData));
	StartDataBlockResponse(responseData, &len);
	AddDecnetIdToResponse(responseData, &len, &nodeInfo.address);
	AddStringToResponse(responseData, &len, nodeInfo.name);

	AddEntityTypeAndDataTypeToResponse(responseData, &len, ENTITY_TYPE_NODE_C_IDENTIFICATION, DATA_TYPE_AI);
	AddStringToResponse(responseData, &len, "Route20 User Mode Router");

	AddEntityTypeAndDataTypeToResponse(responseData, &len, ENTITY_TYPE_NODE_C_MANAGEMENT_VERSION, DATA_TYPE_CM(3));
	responseData[len++] = DATA_TYPE_DU(1);
	responseData[len++] = NETMAN_VERSION;
	responseData[len++] = DATA_TYPE_DU(1);
	responseData[len++] = NETMAN_DEC_ECO;
	responseData[len++] = DATA_TYPE_DU(1);
	responseData[len++] = NETMAN_USER_ECO;

	AddEntityTypeAndDataTypeToResponse(responseData, &len, ENTITY_TYPE_NODE_C_TYPE, DATA_TYPE_C(1));
	responseData[len++] = nodeInfo.level == 1 ? 4 : 3;

	SessionDataTransmit(niceSession->session, responseData, len);

	SendDoneWithMultipleResponses(niceSession);
}

static int AdjacentNodeCircuitCallback(adjacency_t *adjacency, void *context)
{
	AdjacentNodeCallbackData *callbackData = (AdjacentNodeCallbackData *)context;
	if (callbackData->circuit == adjacency->circuit)
	{
		callbackData->adjacentRoutersCount++;
		SendCircuitInfo(callbackData->niceSession, callbackData->circuit, &adjacency->id);
	}

	return 1;
}

static int AdjacentNodeCallback(adjacency_t *adjacency, void *context)
{
	AdjacentNodeCallbackData *callbackData = (AdjacentNodeCallbackData *)context;
	if (callbackData->circuit == adjacency->circuit)
	{
		SendAdjacentNodeInfo(callbackData->niceSession, callbackData->circuit, &adjacency->id);
	}

	return 1;
}

static void SendCircuitInfo(nice_session_t *niceSession, circuit_t *circuit, decnet_address_t *address)
{
	byte responseData[512];
	uint16 len;

	memset(responseData, 0, sizeof(responseData));
	StartDataBlockResponse(responseData, &len);
	AddStringToResponse(responseData, &len, circuit->name);

	/* Circuit State */
	responseData[len++] = 0;
	responseData[len++] = 0;
	responseData[len++] = 0x81;
	responseData[len++] = circuit->state == CircuitStateUp ? 0 : 1;

	if (address != NULL)
	{
		AddEntityTypeAndDataTypeToResponse(responseData, &len, ENTITY_TYPE_CIRCUIT_S_ADJACENT_NODE, DATA_TYPE_CM(1));
		responseData[len++] = 0x02;  /* length of DECnet ID */
		AddDecnetIdToResponse(responseData, &len, address);
	}

	SessionDataTransmit(niceSession->session, responseData, len);
}

static void SendAdjacentNodeInfo(nice_session_t *niceSession, circuit_t *circuit, decnet_address_t *address)
{
	byte responseData[512];
	uint16 len;

	memset(responseData, 0, sizeof(responseData));
	StartDataBlockResponse(responseData, &len);
	AddDecnetIdToResponse(responseData, &len, address);
	responseData[len++] = 0; /* length of name - not supplying it */

	/* Node state */
	responseData[len++] = 0;
	responseData[len++] = 0;
	responseData[len++] = 0x81;
	responseData[len++] = IsReachable(address) ? 4 : 5;

	/* Circuit */
	AddEntityTypeAndDataTypeToResponse(responseData, &len, ENTITY_TYPE_NODE_S_CIRCUIT, DATA_TYPE_AI);
	AddStringToResponse(responseData, &len, circuit->name);

	SessionDataTransmit(niceSession->session, responseData, len);
}

static void StartDataBlockResponse(byte* data, uint16 * pos)
{
	*pos = 0;
	data[(*pos)++] = 1; /* Success */
	data[(*pos)++] = 0xFF;
	data[(*pos)++] = 0xFF;
	data[(*pos)++] = 0;
}

static void AddDecnetIdToResponse(byte *data, uint16 *pos, decnet_address_t *address)
{
		uint16 id = Uint16ToLittleEndian(GetDecnetId(*address));
		memcpy(&data[*pos], &id, sizeof(uint16));
		*pos = *pos + sizeof(uint16);
}

static void AddEntityTypeAndDataTypeToResponse(byte* data, uint16 * pos, uint16 entityType, byte dataType)
{
	data[(*pos)++] = entityType & 0xFF;
	data[(*pos)++] = (entityType >> 8) & 0xFF;
	data[(*pos)++] = dataType;
}

static void AddStringToResponse(byte *data, uint16 *pos, char *s)
{
	uint16 len = (uint16)strlen(s);
	data[(*pos)++] = (byte)len;
	strcpy((char *)(&data[*pos]), s);
	*pos = *pos +len;
}