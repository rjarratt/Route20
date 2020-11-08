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
static void ProcessShowExecutorCharacteristics(uint16 locAddr);

static void SendAcceptWithMultipleResponses(uint16 locAddr);
static void SendDoneWithMultipleResponses(uint16 locAddr);
static void SendError(uint16 locAddr);

static int AdjacentNodeCircuitCallback(adjacency_t *adjacency, void *context);
static int AdjacentNodeCallback(adjacency_t *adjacency, void *context);
static void SendCircuitInfo(uint16 srcPort, circuit_t *circuit, decnet_address_t *address);
static void SendAdjacentNodeInfo(uint16 srcPort, circuit_t *circuit, decnet_address_t *address);
static void StartDataBlockResponse(byte* data, int* pos);
static void AddDecnetIdToResponse(byte* data, int* pos, decnet_address_t* address);
static void AddEntityTypeAndDataTypeToResponse(byte* data, int* pos, uint16 entityType, byte dataType);
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
	int reject = 0;

	byte acceptData[] = { NETMAN_VERSION, NETMAN_DEC_ECO, NETMAN_USER_ECO };

	Log(LogNetMan, LogVerbose, "Accepting on NSP port %hu\n", locAddr);
	if (dataLength < 2)
	{
		reject = 1;
	}
	else
	{
		uint16 objectType = BigEndianBytesToUint16(data);
		if (objectType != OBJECT_NML)
		{
			reject = 1;
		}
	}

	if (!reject)
	{
		NspAccept(locAddr, SERVICES_NONE, sizeof(acceptData), acceptData);
	}
	else
	{
		NspReject(remNode, locAddr, remAddr, 4, 0, NULL);
	}
}

void DataCallback(uint16 locAddr, byte *data, int dataLength)
{
	Log(LogNetMan, LogVerbose, "Data callback, data=");
	LogBytes(LogNetMan, LogVerbose, data, dataLength);

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
		ProcessShowKnownCircuits(locAddr);
	}
	else if (isVolatile && (infoType == NetmanSummaryInfoTypeCode || infoType == NetmanStatusInfoTypeCode) && entityType == NetmanNodeEntityTypeCode && (nodeFormat == AdjacentNodes || nodeFormat == ActiveNodes))
	{
		ProcessShowAdjacentNodes(locAddr);
	}
	else if (isVolatile && infoType == NetmanCharacteristicsInfoTypeCode && entityType == NetmanNodeEntityTypeCode)
	{
		ProcessShowExecutorCharacteristics(locAddr);
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

static void ProcessShowExecutorCharacteristics(uint16 locAddr)
{
	byte responseData[512];
	int len;

	Log(LogNetMan, LogInfo, "Processing SHOW EXECUTOR CHARACTERISTICS for port %hu\n", locAddr);

	SendAcceptWithMultipleResponses(locAddr);

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

	NspTransmit(locAddr, responseData, len);

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
	int len;

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

	NspTransmit(srcPort, responseData, len);
}

static void SendAdjacentNodeInfo(uint16 srcPort, circuit_t *circuit, decnet_address_t *address)
{
	byte responseData[512];
	int len;

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

	NspTransmit(srcPort, responseData, len);
}

static void StartDataBlockResponse(byte* data, int* pos)
{
	*pos = 0;
	data[(*pos)++] = 1; /* Success */
	data[(*pos)++] = 0xFF;
	data[(*pos)++] = 0xFF;
	data[(*pos)++] = 0;
}

static void AddDecnetIdToResponse(byte *data, int *pos, decnet_address_t *address)
{
		uint16 id = Uint16ToLittleEndian(GetDecnetId(*address));
		memcpy(&data[*pos], &id, sizeof(uint16));
		*pos = *pos + sizeof(uint16);
}
static void AddEntityTypeAndDataTypeToResponse(byte* data, int* pos, uint16 entityType, byte dataType)
{
	data[(*pos)++] = entityType & 0xFF;
	data[(*pos)++] = (entityType >> 8) & 0xFF;
	data[(*pos)++] = dataType;
}

static void AddStringToResponse(byte *data, int *pos, char *s)
{
	int len = (int)strlen(s);
	data[(*pos)++] = (byte)len;
	strcpy((char *)(&data[*pos]), s);
	*pos = *pos +len;
}