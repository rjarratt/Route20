/* route20.c: DECnet Routing 2.0
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

#include "platform.h"
#pragma warning( push, 3 )
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#pragma warning( pop )

#include "route20.h"
#include "circuit.h"
#include "line.h"
#include "messages.h"
#include "decnet.h"
#include "adjacency.h"
#include "timer.h"
#include "init_layer.h"
#include "ddcmp_init_layer.h"
#include "routing_database.h"
#include "decision.h"
#include "forwarding.h"
#include "update.h"
#include "nsp.h"
#include "session.h"
#include "dns.h"
#include "node.h"
#include "socket.h"

static int dnsNeeded = 0;
int numCircuits = 0;
static init_layer_t *ethernetInitLayer;
static init_layer_t *ddcmpInitLayer;
static void (*processHigherLevelProtocolPacket)(decnet_address_t *from, byte *data, uint16 dataLength) = NULL;
static rtimer_t *statsTimer = NULL;

// TODO: Add Phase III support
static char *ReadConfigLine(FILE *f);
static char *ReadConfigToNextSection(FILE *f);
static char *ReadLoggingConfig(FILE *f, ConfigReadMode mode, int *ans);
static char *ReadNodeConfig(FILE *f, ConfigReadMode mode, int *ans);
static char *ReadSocketConfig(FILE *f, ConfigReadMode mode, int *ans);
static char *ReadEthernetConfig(FILE *f, ConfigReadMode mode, int *ans);
static char *ReadBridgeConfig(FILE *f, ConfigReadMode mode, int *ans);
static char *ReadDdcmpConfig(FILE *f, ConfigReadMode mode, int *ans);
static char *ReadNspConfig(FILE *f, ConfigReadMode mode, int *ans);
static char *ReadSessionConfig(FILE *f, ConfigReadMode mode, int *ans);
static char *ReadDnsConfig(FILE *f, ConfigReadMode mode, int *ans);
static char *ReadStatsConfig(FILE *f, ConfigReadMode mode, int *ans);
static int SplitString(char *string, char splitBy, char **left, char **right);
static void ParseLogLevel(char *string, int *source);
static void PurgeAdjacenciesCallback(rtimer_t *, char *, void *);
static void LogAllStats(rtimer_t *, char *, void *);
static void LogCircuitStats(circuit_t *);
static void LogLineStats(line_t *);
static int ProcessSingleCircuitPacket(circuit_t *circuit);
static void ProcessPhaseIIMessage(circuit_t *circuit, packet_t *packet);
static void ProcessPhaseIVMessage(circuit_t *circuit, packet_t *packet);
static int RouterHelloIsForThisNode(decnet_address_t *from, int iinfo);
static int EndnodeHelloIsForThisNode(decnet_address_t *from, int iinfo);
static void LogMessage(circuit_t* circuit, packet_t* packet, char* messageName);
static void LogMessageEnd(void);
static void LogLoopbackMessage(circuit_t *circuit, packet_t *packet, char *messageName);

#pragma warning(disable : 4996)

void InitialiseLogging(void)
{
	int i;

    for (i = 0; i < LogEndMarker; i++)
	{
		LoggingLevels[i] = LogInfo;
	}

    LogSourceName[LogGeneral] = "GEN";
    LogSourceName[LogCircuit] = "CRC";
    LogSourceName[LogLine] = "LIN";
    LogSourceName[LogAdjacency] = "ADJ";
    LogSourceName[LogUpdate] = "UPD";
    LogSourceName[LogDecision] = "DEC";
    LogSourceName[LogForwarding] = "FWD";
    LogSourceName[LogMessages] = "MSG";
    LogSourceName[LogDns] = "DNS";
    LogSourceName[LogEthInit] = "ETI";
    LogSourceName[LogEthCircuit] = "ECR";
    LogSourceName[LogEthPcapLine] = "EPL";
    LogSourceName[LogEthSockLine] = "ESL";
    LogSourceName[LogDdcmpSock] = "DSK";
    LogSourceName[LogDdcmp] = "DDC";
    LogSourceName[LogDdcmpInit] = "DDI";
    LogSourceName[LogSock] = "SOK";
    LogSourceName[LogNsp] = "NSP";
    LogSourceName[LogNspMessages] = "NSM";
	LogSourceName[LogNetMan] = "NMN";
	LogSourceName[LogSession] = "SES";

	SysLogLocalFacilityNumber = 0;
}

int InitialiseConfig(int (*ConfigReader)(char *fileName, ConfigReadMode mode), char *configFileName)
{
	int ans;
	NspInitialiseConfig();
	SessionInitialiseConfig();
	DnsConfig.dnsConfigured = 0;

	ans = ConfigReader(configFileName, ConfigReadModeFull);

    if (ans)
    {
        Log(LogGeneral, LogInfo, "Initialisation completed successfully\n");
    }
    else
    {
        Log(LogGeneral, LogFatal, "Initialisation failed, router will now exit\n");
    }

    return ans;
}

int DecnetInitialise(void)
{
    int ans = 1;
    time_t now;

    InitialiseSockets();
    InitialiseAdjacencies();
    InitialiseDecisionProcess();
    InitialiseUpdateProcess();
    SetAdjacencyStateChangeCallback(ProcessAdjacencyStateChange);
    SetCircuitStateChangeCallback(ProcessCircuitStateChange);
    nodeInfo.state = Running;
    time(&now);
    CreateTimer("PurgeAdjacencies", now + 1, 1, NULL, PurgeAdjacenciesCallback);

    ethernetInitLayer = CreateEthernetInitializationSublayer();
    InitializationSublayerAssociateCircuits(Circuits, numCircuits, EthernetCircuit, ethernetInitLayer);
    ans &= ethernetInitLayer->Start(Circuits, numCircuits);

    ddcmpInitLayer = CreateDdcmpInitializationSublayer();
    InitializationSublayerAssociateCircuits(Circuits, numCircuits, DDCMPCircuit, ddcmpInitLayer);
    ans &= ddcmpInitLayer->Start(Circuits, numCircuits);

    if (DnsConfig.dnsConfigured && dnsNeeded)
    {
        DnsOpen(DnsConfig.serverName);
    }

    return ans;
}

void RoutingSetCallback(void (*callback)(decnet_address_t *from, byte *data, uint16 dataLength))
{
	processHigherLevelProtocolPacket = callback;
}

void RegisterEventHandler(unsigned int waitHandle, char *name, void *context, void (*eventHandler)(void *context))
{
    int i;
    int entry = numEventHandlers;

    /* we may already have this wait handle registered, if so just update the information. This can happen for outbound sockets where the handler changes after the socket is connected */

    for (i = 0; i < numEventHandlers; i++)
    {
        if (eventHandlers[i].waitHandle == waitHandle)
        {
            entry = i;
            break;
        }
    }

	if (entry >= MAX_EVENT_HANDLERS)
	{
		Log(LogGeneral, LogFatal, "Cannot allocate a new event handler\n");
		exit(EXIT_FAILURE);
	}

	Log(LogGeneral, LogDetail, "Registering event handler for %s in slot %d, handle is %d\n", name, entry, waitHandle);
	eventHandlers[entry].waitHandle = waitHandle;
	eventHandlers[entry].name = name;
	eventHandlers[entry].context = context;
	eventHandlers[entry].eventHandler = eventHandler;
    if (entry >= numEventHandlers)
    {
        numEventHandlers++;
        eventHandlersChanged = 1;
    }
}

void DeregisterEventHandler(unsigned int waitHandle)
{
	int i;
	int found = 0;
	for (i = 0; i < numEventHandlers; i++)
	{
		if (found)
		{
			memcpy(&eventHandlers[i-1], &eventHandlers[i], sizeof(event_handler_t));
		}
		else if (eventHandlers[i].waitHandle == waitHandle)
		{
        	Log(LogGeneral, LogDetail, "Deregistering event handler for %s in slot %d, handle is %d\n", eventHandlers[i].name, i, waitHandle);
			found = 1;
		}
	}

	if (found)
	{
		numEventHandlers--;
	    eventHandlersChanged = 1;
	}
    else
    {
        Log(LogGeneral, LogWarning, "Unable to deregister event handler as the registration entry for the handle %d could not be found\n", waitHandle);
    }
}

void MainLoop(void)
{
	Log(LogGeneral, LogInfo, "Main loop start\n");

	ProcessEvents(Circuits, numCircuits, ProcessPacket);

	Log(LogGeneral, LogInfo, "Main loop terminated\n");
	nodeInfo.state = Stopping;

	Log(LogGeneral, LogInfo, "Stopping Ethernet Initialisation Layer\n");
	ethernetInitLayer->Stop();

	Log(LogGeneral, LogInfo, "Stopping DDCMP Initialisation Layer\n");
	ddcmpInitLayer->Stop();

	/* handle any final events queued for immediate processing as part of shutdown */
	while (SecondsUntilNextDue() == 0)
	{
	    ProcessTimers();
	}

	StopAllTimers();
	Log(LogGeneral, LogInfo, "Shutdown complete\n");
}

int ReadConfig(char *fileName, ConfigReadMode mode)
{
	FILE *f;
	int ans = 1;
	int nodePresent = 0;
	int ddcmpPresent = 0;
	char *errString;

	if (mode == ConfigReadModeUpdate)
	{
		Log(LogGeneral, LogInfo, "Updating configuration\n");
	}

	if ((f = fopen(fileName, "r")) == NULL)
	{
		errString = strerror(errno);
		if (errString == NULL)
		{
			errString = "n/a";
		}

		Log(LogGeneral, LogError, "Could not open the configuration file: %s, error %s (%d)\n", fileName, errString, errno);
		ans = 0;
	}

	if (ans)
	{
		char *line = "";
		while(line != NULL)
		{
			if (stricmp(line, "[logging]") == 0)
			{
				line = ReadLoggingConfig(f, mode, &ans);
			}
			else if (stricmp(line, "[node]") == 0)
			{
				nodePresent = 1;
				line = ReadNodeConfig(f, mode, &ans);
			}
			else if (stricmp(line, "[socket]") == 0)
			{
				line = ReadSocketConfig(f, mode, &ans);
			}
			else if (stricmp(line, "[ethernet]") == 0)
			{
				line = ReadEthernetConfig(f, mode, &ans);
			}
			else if (stricmp(line, "[bridge]") == 0)
			{
				line = ReadBridgeConfig(f, mode, &ans);
			}
			else if (stricmp(line, "[ddcmp]") == 0)
			{
				line = ReadDdcmpConfig(f, mode, &ans);
				ddcmpPresent = 1;
			}
			else if (stricmp(line, "[nsp]") == 0)
			{
				line = ReadNspConfig(f, mode, &ans);
			}
			else if (stricmp(line, "[session]") == 0)
			{
				line = ReadSessionConfig(f, mode, &ans);
			}
			else if (stricmp(line, "[dns]") == 0)
			{
				line = ReadDnsConfig(f, mode, &ans);
			}
			else if (stricmp(line, "[stats]") == 0)
			{
				line = ReadStatsConfig(f, mode, &ans);
			}
			else
			{
				line = ReadConfigLine(f);
			}
		}

		fclose(f);
	}

	if (mode == ConfigReadModeFull)
	{
		if (!nodePresent)
		{
			Log(LogGeneral, LogError, "Node section missing from configuration file\n");
			ans = 0;
		}
		else if (numCircuits <= 0)
		{
			Log(LogGeneral, LogError, "No circuits defined\n");
			ans = 0;
		}
		else if (ddcmpPresent && !SocketConfig.socketConfigured)
		{
			Log(LogGeneral, LogError, "Socket section required in configuration file for DDCMP circuits\n");
			ans = 0;
		}
	}

    if (!ans)
    {
		Log(LogGeneral, LogError, "Invalid configuration file\n");
    }

	return ans;
}

static char *ReadLoggingConfig(FILE *f, ConfigReadMode mode, int *ans)
{
	char *line;
	char *name;
	char *value;

	/* if this is an update where a setting has been commented out it should return to the default setting */
	InitialiseLogging();

	while (((line = ReadConfigLine(f))))
	{
		if (*line == '[')
		{
			break;
		}

		if (SplitString(line, '=', &name, &value))
		{
			if (stricmp(name, "general") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogGeneral]);
			}
			else if (stricmp(name, "circuit") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogCircuit]);
			}
			else if (stricmp(name, "line") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogLine]);
			}
			else if (stricmp(name, "adjacency") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogAdjacency]);
			}
			else if (stricmp(name, "update") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogUpdate]);
			}
			else if (stricmp(name, "decision") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogDecision]);
			}
			else if (stricmp(name, "forwarding") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogForwarding]);
			}
			else if (stricmp(name, "messages") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogMessages]);
			}
			else if (stricmp(name, "dns") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogDns]);
			}
			else if (stricmp(name, "ethinit") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogEthInit]);
			}
			else if (stricmp(name, "ethcircuit") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogEthCircuit]);
			}
			else if (stricmp(name, "ethpcapline") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogEthPcapLine]);
			}
			else if (stricmp(name, "ethsockline") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogEthSockLine]);
			}
			else if (stricmp(name, "ddcmpsock") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogDdcmpSock]);
			}
			else if (stricmp(name, "ddcmp") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogDdcmp]);
			}
			else if (stricmp(name, "ddcmpinit") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogDdcmpInit]);
			}
			else if (stricmp(name, "sock") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogSock]);
			}
			else if (stricmp(name, "nsp") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogNsp]);
			}
			else if (stricmp(name, "nspmessages") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogNspMessages]);
			}
			else if (stricmp(name, "netman") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogNetMan]);
			}
			else if (stricmp(name, "session") == 0)
			{
				ParseLogLevel(value, &LoggingLevels[LogSession]);
			}
			else if (stricmp(name, "SysLogLocalFacilityNumber") == 0)
			{
				SysLogLocalFacilityNumber = atoi(value);
			}
		}
	}

	return line;
}

static char *ReadNodeConfig(FILE *f, ConfigReadMode mode, int *ans)
{
	char *line;
	char *name;
	char *value;
	int addressPresent = 0;
	int namePresent = 0;

	if (mode == ConfigReadModeFull)
	{
		nodeInfo.priority = 64;
		nodeInfo.level = 2;

		while (((line = ReadConfigLine(f))))
		{
			if (*line == '[')
			{
				break;
			}

			if (SplitString(line, '=', &name, &value))
			{
				if (stricmp(name, "level") == 0)
				{
					nodeInfo.level = atoi(value);
				}
				else if (stricmp(name, "address") == 0)
				{
					char *area;
					char *node;
					if (SplitString(value, '.', &area, &node))
					{
						nodeInfo.address.area = atoi(area);
						nodeInfo.address.node = atoi(node);
						addressPresent = 1;
					}
					else
					{
						Log(LogGeneral, LogError, "Node address must be in the form <area>.<node>\n");
					}
				}
				else if (stricmp(name, "name") == 0)
				{
					strncpy(nodeInfo.name, value, sizeof(nodeInfo.name) - 1);
					nodeInfo.name[sizeof(nodeInfo.name) - 1] = '\0';
					namePresent = 1;
				}
				else if (stricmp(name, "priority") == 0)
				{
					nodeInfo.priority = (byte)atoi(value);
				}
			}
		}

		if (!addressPresent)
		{
			*ans = 0;
			Log(LogGeneral, LogError, "Node address must be defined in the configuration file\n");
		}
		else if (!namePresent)
		{
			*ans = 0;
			Log(LogGeneral, LogError, "Node name must be defined in the configuration file\n");
		}
	}
	else
	{
		line = ReadConfigToNextSection(f);
	}

	return line;
}

static char *ReadSocketConfig(FILE *f, ConfigReadMode mode, int *ans)
{
	char  *line;
	char  *name;
	char  *value;
	int    TcpListenPortPresent = 0;

	if (mode == ConfigReadModeFull)
	{
		while ((line = ReadConfigLine(f)))
		{
			if (*line == '[')
			{
				break;
			}

			if (SplitString(line, '=', &name, &value))
			{
				if (stricmp(name, "TcpListenPort") == 0)
				{
					SocketConfig.tcpListenPort = (uint16)atoi(value);
					TcpListenPortPresent = 1;
				}
			}
		}

		if (!TcpListenPortPresent)
		{
			*ans = 0;
			Log(LogGeneral, LogError, "TCP listen port not specified\n");
		}
		else
		{
			Log(LogGeneral, LogInfo, "TCP listening on port %d\n", SocketConfig.tcpListenPort);
			SocketConfig.socketConfigured = 1;
		}
	}
	else
	{
		line = ReadConfigToNextSection(f);
	}

	return line;
}

static char *ReadEthernetConfig(FILE *f, ConfigReadMode mode, int *ans)
{
	char *line;
	char *name;
	char *value;
	int cost = 3;
	char pcapInterface[80] = "";

	if (mode == ConfigReadModeFull)
	{
		while ((line = ReadConfigLine(f)))
		{
			if (*line == '[')
			{
				break;
			}

			if (SplitString(line, '=', &name, &value))
			{
				if (stricmp(name, "interface") == 0)
				{
					strncpy(pcapInterface, value, sizeof(pcapInterface) -1);
				}
				if (stricmp(name, "cost") == 0)
				{
					cost = atoi(value);
				}
			}
		}

		if (*pcapInterface == '\0')
		{
			*ans = 0;
			Log(LogGeneral, LogError, "Interface not defined for ethernet circuit\n");
		}
		else
		{
			if (numCircuits >= NC)
			{
				Log(LogGeneral, LogError, "Too many circuit definitions, ignoring ethernet interface %s\n", pcapInterface);
			}
			else
			{
				Log(LogGeneral, LogInfo, "Ethernet interface is: %s\n", pcapInterface);
				CircuitCreateEthernetPcap(&Circuits[1 + numCircuits++], pcapInterface, cost, ProcessCircuitEvent);
			}
		}
	}
	else
	{
		line = ReadConfigToNextSection(f);
	}

	return line;
}

static char *ReadBridgeConfig(FILE *f, ConfigReadMode mode, int *ans)
{
	char  *line;
	char  *name;
	char  *value;
	char   addressPresent = 0;
	int    receivePortPresent = 0;
	char   hostName[80];
	uint16 destPort = 0;
	uint16 receivePort = 0;
	int    cost = 5;

	if (mode == ConfigReadModeFull)
	{
		while ((line = ReadConfigLine(f)))
		{
			if (*line == '[')
			{
				break;
			}

			if (SplitString(line, '=', &name, &value))
			{
				if (stricmp(name, "address") == 0)
				{
					char *hostStr;
					char *portStr;
					if (SplitString(value, ':', &hostStr, &portStr))
					{
						strncpy(hostName, hostStr, sizeof(hostName) - 1);
						destPort = (uint16)atoi(portStr);
						addressPresent = 1;
					}
					else
					{
						Log(LogGeneral, LogError, "Bridge address must be of the form <host>:<port>\n");
					}
				}
				else if (stricmp(name, "port") == 0)
				{
					receivePort = (uint16)atoi(value);
					receivePortPresent = 1;
				}
				if (stricmp(name, "cost") == 0)
				{
					cost = atoi(value);
				}
			}
		}

		if (!addressPresent)
		{
			*ans = 0;
			Log(LogGeneral, LogError, "Address not defined for bridge circuit\n");
		}
		else if (!receivePortPresent)
		{
			*ans = 0;
			Log(LogGeneral, LogError, "Port not defined for bridge circuit\n");
		}
		else
		{
			if (numCircuits >= NC)
			{
				Log(LogGeneral, LogError, "Too many circuit definitions, ignoring bridge interface %s\n", hostName);
			}
			else
			{
				Log(LogGeneral, LogInfo, "Bridge interface sends to %s:%d and listens on %d\n", hostName, destPort, receivePort);
				CircuitCreateEthernetSocket(&Circuits[1 + numCircuits++], hostName, receivePort, destPort, cost, ProcessCircuitEvent);
				dnsNeeded = 1;
			}
		}
	}
	else
	{
		line = ReadConfigToNextSection(f);
	}

	return line;
}

static char *ReadDdcmpConfig(FILE *f, ConfigReadMode mode, int *ans)
{
	char  *line;
	char  *name;
	char  *value;
	char   addressPresent = 0;
	char   hostName[80];
	uint16 port;
	int    cost = 5;
    int    connectPoll = 30;

	if (mode == ConfigReadModeFull)
	{
		while ((line = ReadConfigLine(f)))
		{
			if (*line == '[')
			{
				break;
			}

			if (SplitString(line, '=', &name, &value))
			{
				if (stricmp(name, "address") == 0)
				{
					char *hostStr;
					char *portStr;

					if (SplitString(value, ':', &hostStr, &portStr))
					{
						strncpy(hostName, hostStr, sizeof(hostName) - 1);
						port = (uint16)atoi(portStr);
					}
					else
					{
						strncpy(hostName, value, sizeof(hostName) - 1);
						port = 0;
					}

					addressPresent = 1;
				}

				if (stricmp(name, "cost") == 0)
				{
					cost = atoi(value);
				}

				if (stricmp(name, "connectpoll") == 0)
				{
					connectPoll = atoi(value);
				}
			}
		}

		if (!addressPresent)
		{
			*ans = 0;
			Log(LogGeneral, LogError, "Address not defined for DDCMP circuit\n");
		}
		else
		{
			if (numCircuits >= NC)
			{
				Log(LogGeneral, LogError, "Too many circuit definitions, ignoring DDCMP interface %s\n", hostName);
			}
			else
			{
				if (port == 0)
				{
				    Log(LogGeneral, LogInfo, "DDCMP interface expecting connections from %s\n", hostName);
				}
				else
				{
				    Log(LogGeneral, LogInfo, "DDCMP interface connecting to %s:%d\n", hostName, port);
				}

				CircuitCreateDdcmpSocket(&Circuits[1 + numCircuits++], hostName, port, cost, connectPoll, ProcessCircuitEvent);
				dnsNeeded = 1;
			}
		}
	}
	else
	{
		line = ReadConfigToNextSection(f);
	}

	return line;
}

static char *ReadNspConfig(FILE *f, ConfigReadMode mode, int *ans)
{
	char *line;
	char *name;
	char *value;

	if (mode == ConfigReadModeFull)
	{
		while ((line = ReadConfigLine(f)))
		{
			if (*line == '[')
			{
				break;
			}

			if (SplitString(line, '=', &name, &value))
			{
				if (stricmp(name, "InactivityTimer") == 0)
				{
					NspConfig.NSPInactTim = atoi(value);
				}
			}
		}
	}
	else
	{
		line = ReadConfigToNextSection(f);
	}

	return line;
}

static char *ReadSessionConfig(FILE *f, ConfigReadMode mode, int *ans)
{
	char *line;
	char *name;
	char *value;

	if (mode == ConfigReadModeFull)
	{
		while ((line = ReadConfigLine(f)))
		{
			if (*line == '[')
			{
				break;
			}

			if (SplitString(line, '=', &name, &value))
			{
				if (stricmp(name, "InactivityTimer") == 0)
				{
					SessionConfig.sessionInactivityTimeout = atoi(value);
				}
			}
		}
	}
	else
	{
		line = ReadConfigToNextSection(f);
	}

	return line;
}

static char *ReadDnsConfig(FILE *f, ConfigReadMode mode, int *ans)
{
	char *line;
	char *name;
	char *value;
	char  addressPresent = 0;
	int   pollPresent = 0;

	if (mode == ConfigReadModeFull)
	{
		while ((line = ReadConfigLine(f)))
		{
			if (*line == '[')
			{
				break;
			}

			if (SplitString(line, '=', &name, &value))
			{
				if (stricmp(name, "address") == 0)
				{
					strncpy(DnsConfig.serverName, value, sizeof(DnsConfig.serverName) - 1);
					addressPresent = 1;
				}
				else if (stricmp(name, "poll") == 0)
				{
					DnsConfig.pollPeriod = atoi(value);
					pollPresent = 1;
				}
			}
		}

		if (!addressPresent)
		{
			*ans = 0;
			Log(LogGeneral, LogError, "Address not defined for DNS\n");
		}
		else if (!pollPresent)
		{
			*ans = 0;
			Log(LogGeneral, LogError, "Poll period not defined for DNS\n");
		}
		else
		{
			DnsConfig.dnsConfigured = 1;
		}
	}
	else
	{
		line = ReadConfigToNextSection(f);
	}

	return line;
}

static char *ReadStatsConfig(FILE *f, ConfigReadMode mode, int *ans)
{
	char *line;
	char *name;
	char *value;
	int period = -1;

	if (mode == ConfigReadModeFull || mode == ConfigReadModeUpdate)
	{
		while ((line = ReadConfigLine(f)))
		{
			if (*line == '[')
			{
				break;
			}

			if (SplitString(line, '=', &name, &value))
			{
				if (stricmp(name, "logginginterval") == 0)
				{
					period = atoi(value);
				}
			}
		}

		if (statsTimer != NULL)
		{
			StopTimer(statsTimer);
			statsTimer = NULL;
		}

		if (period > 0)
		{
			time_t now;

			time(&now);
			statsTimer = CreateTimer("CircuitStats", now + period, period, NULL, LogAllStats);
		}
	}
	else
	{
		line = ReadConfigToNextSection(f);
	}

	return line;
}

static char *ReadConfigLine(FILE *f)
{
	char * ans = NULL;
	static char buf[80];
	ans = fgets(buf,sizeof(buf), f);
	if (buf[strlen(buf) - 1] == '\n')
	{
		buf[strlen(buf) - 1] = '\0';
	}

	if (buf[strlen(buf) - 1] == '\r')
	{
		buf[strlen(buf) - 1] = '\0';
	}

	return ans;
}

static char *ReadConfigToNextSection(FILE *f)
{
	char *line;
	while ((line = ReadConfigLine(f)))
	{
		if (*line == '[')
		{
			break;
		}
	}

	return line;
}

static int SplitString(char *string, char splitBy, char **left, char **right)
{
	char *ptr = string;
	*left = string;
	*right = NULL;

	while (*ptr != '\0')
	{
		if (*ptr == splitBy)
		{
			*ptr++ = '\0';
			*right = ptr;
			break;
		}

		ptr++;
	}

	return *right != NULL;
}

static void ParseLogLevel(char *string, int *source)
{
	if (stricmp(string, "fatal") == 0)
	{
		*source = LogFatal;
	}
	else if (stricmp(string, "error") == 0)
	{
		*source = LogError;
	}
	else if (stricmp(string, "warning") == 0)
	{
		*source = LogWarning;
	}
	else if (stricmp(string, "info") == 0)
	{
		*source = LogInfo;
	}
	else if (stricmp(string, "detail") == 0)
	{
		*source = LogDetail;
	}
	else if (stricmp(string, "verbose") == 0)
	{
		*source = LogVerbose;
	}
}

static void PurgeAdjacenciesCallback(rtimer_t *timer, char *name, void *context)
{
	PurgeAdjacencies();
}

static void LogAllStats(rtimer_t *timer, char *name, void *context)
{
	int i;
    Log(LogGeneral, LogFatal, "Statistics ****************\n");
    Log(LogGeneral, LogFatal, "\n");
    Log(LogGeneral, LogFatal, "Circuits ****************\n");
    Log(LogGeneral, LogFatal, "\n");
	for (i = 1; i <= numCircuits; i++)
	{
		circuit_t *circuit = &Circuits[i];
        LogCircuitStats(circuit);
	}
    Log(LogGeneral, LogFatal, "\n");
    Log(LogGeneral, LogFatal, "Lines ****************\n");
    Log(LogGeneral, LogFatal, "\n");
	for (i = 1; i <= numCircuits; i++)
	{
		circuit_t *circuit = &Circuits[i];
        LogLineStats(circuit->line);
	}
    Log(LogGeneral, LogFatal, "\n");
	Log(LogGeneral, LogFatal, "End Statistics ************\n");
}

static void LogCircuitStats(circuit_t *circuit)
{
    Log(LogGeneral, LogFatal, "Circuit %s\n", circuit->name);
    Log(LogGeneral, LogFatal, "  DECnet packets received:              %d\n", circuit->stats.decnetPacketsReceived);
    Log(LogGeneral, LogFatal, "  DECnet packets to this node received: %d\n", circuit->stats.decnetToThisNodePacketsReceived);
    Log(LogGeneral, LogFatal, "  Non-DECnet packets received:          %d\n", circuit->stats.nonDecnetPacketsReceived);
    Log(LogGeneral, LogFatal, "  Loopback packets received:            %d\n", circuit->stats.loopbackPacketsReceived);
    Log(LogGeneral, LogFatal, "  Valid raw packets received:           %d\n", circuit->stats.validRawPacketsReceived);
    Log(LogGeneral, LogFatal, "  Packets sent:                         %d\n", circuit->stats.packetsSent);
}

static void LogLineStats(line_t *line)
{
    Log(LogGeneral, LogFatal, "Line %s\n", line->name);
    Log(LogGeneral, LogFatal, "  Valid packets received:              %d\n", line->stats.validPacketsReceived);
    Log(LogGeneral, LogFatal, "  Invalid packets received:            %d\n", line->stats.invalidPacketsReceived);
}

void ProcessCircuitEvent(void *context) /* TODO: not sure this should in here */
{
	circuit_t *circuit;
	//int foundData;
	//int i;

	// TODO: Implement flow control. Look at routing spec.
	circuit = (circuit_t *)context;

    // Two processing methods available, not decided which one is best.
#if 1
	while (ProcessSingleCircuitPacket(circuit))
    {
    }
#else
	// Process the packet on the circuit that caused the event, and then round robin all the other circuits until none have any data to process.
    // TODO: Need to add the concept of a Line, so can poll for input when a line is up rather than when a circuit is up. Because we need data to be exchanged before a circuit can be up, so can't use circuit status to decide whether to read a line or not.
	ProcessSingleCircuitPacket(circuit);

	do
	{
		foundData = 0;
		for (i = 1; i <= numCircuits; i++)
		{
			if (ProcessSingleCircuitPacket(&Circuits[i]))
			{
				foundData = 1;
			}
		}
	}
	while (foundData);
#endif
}

static int ProcessSingleCircuitPacket(circuit_t *circuit)
{
	packet_t *packet;
	int ans = 0;

	packet = (*(circuit->ReadPacket))(circuit);
	if (packet != NULL)
	{
		QueuePacket(circuit, packet);
		ans = 1;
	}

	return ans;
}

void ProcessPacket(circuit_t *circuit, packet_t *packet)
{
	if (nodeInfo.state == Running)
	{
		static int n = 0;
		if (GetMessageBody(packet))
		{
			if (IsPhaseIIMessage(packet))
			{
				ProcessPhaseIIMessage(circuit, packet);
			}
			else
			{
				ProcessPhaseIVMessage(circuit, packet);
			}
		}
	}
}

static void ProcessPhaseIIMessage(circuit_t *circuit, packet_t *packet)
{
	if (IsPhaseIINodeInitializationMessage(packet))
	{
		node_init_phaseii_t *msg = NULL;
		LogMessage(circuit, packet, "Node Init (PhaseII)");
		msg = ValidateAndParseNodeInitPhaseIIMessage(packet);
		LogMessageEnd();
		if (msg != NULL)
		{
		    Log(LogMessages,
                LogInfo,
                "From %d %s, Funcs=0x%02X Reqs=0x%02X, BlkSize=%d NspSize=%d, Routver=%d.%d.%d Commver=%d.%d.%d Sysver=%s\n",
                msg->nodeaddr,
                msg->nodename,
                msg->functions,
                msg->requests,
                msg->blksize,
                msg->nspsize,
                msg->routver[0],
                msg->routver[1],
                msg->routver[2],
                msg->commver[0],
                msg->commver[1],
                msg->commver[2],
                msg->sysver);
			//check version support
			DdcmpInitProcessPhaseIINodeInitializationMessage(circuit, msg);
		}
	}
	else
	{
		DumpPacket(LogMessages, LogError, "Discarding unknown Phase II packet.", packet);
	}
}

static void ProcessPhaseIVMessage(circuit_t *circuit, packet_t *packet)
{
	if (IsInitializationMessage(packet))
	{
		LogMessage(circuit, packet, "Initialization");
		if (IsValidInitializationMessage(packet))
		{
			initialization_msg_t *msg = ParseInitializationMessage(packet);
			LogMessageEnd();
			if (msg != NULL)
			{
                DdcmpInitProcessInitializationMessage(circuit, msg);
			}
		}
		else
		{
			LogMessageEnd();
			DdcmpInitProcessInvalidMessage(circuit);
		}
	}
	else if (IsVerificationMessage(packet))
	{
		LogMessage(circuit, packet, "Verification");
		LogMessageEnd();
		if (IsValidVerificationMessage(packet))
		{
			verification_msg_t *msg = (verification_msg_t *)packet->payload;
            DdcmpInitProcessVerificationMessage(circuit, msg);
		}
		else
		{
            DdcmpInitProcessInvalidMessage(circuit);
		}
	}
	else if (IsHelloAndTestMessage(packet))
	{
		LogMessage(circuit, packet, "Hello and Test");
		LogMessageEnd();
		if (IsValidHelloAndTestMessage(packet))
        {
            hello_and_test_msg_t *msg = (hello_and_test_msg_t *)packet->payload;
			decnet_address_t from;
			GetDecnetAddressFromId((byte *)&msg->srcnode, &from);
            CheckCircuitAdjacency(&from, circuit);
        }
		else
		{
            DdcmpInitProcessInvalidMessage(circuit);
		}
	}
	else if (IsLevel1RoutingMessage(packet))
	{
		LogMessage(circuit, packet, "Level 1 Routing");
		if ((nodeInfo.level == 1 || nodeInfo.level == 2))
		{
			routing_msg_t *msg;
			msg = ParseRoutingMessage(packet);
			LogMessageEnd();
			if (msg != NULL)
			{
                CheckCircuitAdjacency(&packet->from, circuit);
				if (CompareDecnetAddress(&msg->srcnode, &nodeInfo.address))
				{
					LogLoopbackMessage(circuit, packet, "Level 1 Routing");
				}
				else if (msg->srcnode.area == nodeInfo.address.area)
				{
					ProcessLevel1RoutingMessage(msg);
				}

				FreeRoutingMessage(msg);
			}
		}
		else
		{
			LogMessageEnd();
		}
	}
	else if (IsLevel2RoutingMessage(packet))
	{
		LogMessage(circuit, packet, "Level 2 Routing");
		if (nodeInfo.level == 2)
		{
			routing_msg_t *msg;
			msg = ParseRoutingMessage(packet);
			LogMessageEnd();
			if (msg != NULL)
			{
                CheckCircuitAdjacency(&packet->from, circuit);
				if (CompareDecnetAddress(&msg->srcnode, &nodeInfo.address))
				{
					LogLoopbackMessage(circuit, packet, "Level 2 Routing");
				}
				else if (msg != NULL)
				{
					ProcessLevel2RoutingMessage(msg);
					FreeRoutingMessage(msg);
				}
			}
		}
		else
		{
			LogMessageEnd();
		}
	}
	else if (IsEthernetRouterHelloMessage(packet))
	{
		LogMessage(circuit, packet, "Ethernet Router Hello");
		Log(LogMessages, LogDetail, " Router List:");
		if (IsValidRouterHelloMessage(packet))
		{
			ethernet_router_hello_t *msg = (ethernet_router_hello_t *)packet->payload;
			decnet_address_t from;
			int i;
			int routersCount = msg->rslistlen / sizeof(rslist_t);

			for (i = 0; i < routersCount; i++)
			{
				decnet_address_t remoteAddress;
				GetDecnetAddress(&msg->rslist[i].router, &remoteAddress);
				Log(LogMessages, LogDetail, " ");
				LogDecnetAddress(LogMessages, LogDetail, &remoteAddress);
				Log(LogMessages, LogDetail, msg->rslist[i].priority_state & 0x80 ? " Up" : " Down");
			}

			LogMessageEnd();

			GetDecnetAddress(&msg->id, &from);
			if (CompareDecnetAddress(&from, &nodeInfo.address))
			{
				LogLoopbackMessage(circuit, packet, "Ethernet Router Hello");
			}
			else
			{
				if (RouterHelloIsForThisNode(&from, msg->iinfo))
				{
					if (VersionSupported(msg->tiver))
					{
						AdjacencyType at;
						at = GetAdjacencyType(msg->iinfo);
						CheckRouterAdjacency(&from, circuit, at, msg->timer, msg->priority, msg->rslist, routersCount);
					}
				}
			}
		}
		else
		{
			LogMessageEnd();
		}
	}
	else if (IsEthernetEndNodeHelloMessage(packet))
	{
		LogMessage(circuit, packet, "Ethernet Endnode Hello");
		if (IsValidEndnodeHelloMessage(packet))
		{
			ethernet_endnode_hello_t *msg = (ethernet_endnode_hello_t *)packet->payload;
			decnet_address_t from;
			GetDecnetAddress(&msg->id, &from);
			if (CompareDecnetAddress(&from, &nodeInfo.address))
			{
				LogMessageEnd();
				LogLoopbackMessage(circuit, packet, "Ethernet Endnode Hello");
			}
			else if (EndnodeHelloIsForThisNode(&from, msg->iinfo))
			{
				if (VersionSupported(msg->tiver))
				{
					LogMessageEnd();
					CheckEndnodeAdjacency(&from, circuit, msg->timer);
				}
				else
				{
					LogMessageEnd();
				}
			}
			else
			{
				LogMessageEnd();
			}
		}
		else
		{
			LogMessageEnd();
		}
	}
	else if (IsDataMessage(packet))
	{
		LogMessage(circuit, packet, "Data message");
		LogMessageEnd();
		if (circuit->state == CircuitStateUp)
        {
            if (IsValidDataPacket(packet))
            {
                decnet_address_t srcNode;
                decnet_address_t dstNode;
                byte flags;
                int visits;
                byte *data;
                uint16 dataLength;

                ExtractDataPacketData(packet, &srcNode, &dstNode, &flags, &visits, &data, &dataLength);
                CheckCircuitAdjacency(&packet->from, circuit);

                if (CompareDecnetAddress(&srcNode, &nodeInfo.address))
                {
                    LogLoopbackMessage(circuit, packet, "Data message");
                }
                else if (CompareDecnetAddress(&dstNode, &nodeInfo.address))
                {
                    if (processHigherLevelProtocolPacket != NULL)
                    {

                        processHigherLevelProtocolPacket(&srcNode, data, dataLength);
                    }
                }
                else
                {
                    ForwardPacket(circuit, packet);
                }
            }
            else
            {
                Log(LogMessages, LogVerbose, "Discarding data message as circuit is down\n");
            }
        }
	}
	else
	{
		DumpPacket(LogMessages, LogError, "Discarding unknown packet.", packet);
	}
}

static int RouterHelloIsForThisNode(decnet_address_t *from, int iinfo)
{
	/* See section 9.1.6. for the rules */
	int ans;
	int fromLevel = GetRouterLevel(iinfo);
	if (nodeInfo.level == 1)
	{
		ans = from->area == nodeInfo.address.area;
	}
	else
	{
		ans = fromLevel == 2 || from->area == nodeInfo.address.area;
	}

	return ans;
}

static int EndnodeHelloIsForThisNode(decnet_address_t *from, int iinfo)
{
	/* See section 9.1.6. for the rules */
	int ans = 0;
	int fromLevel = GetRouterLevel(iinfo);
	if (fromLevel == 3 && (nodeInfo.level == 1 || nodeInfo.level == 2))
	{
		ans = from->area == nodeInfo.address.area;
	}

	return ans;
}

static void LogMessage(circuit_t *circuit, packet_t *packet, char *messageName)
{
	//Log(LogInfo, "Process pkt from %6s from ", circuit->name);
	Log(LogMessages, LogDetail, "Process %s on %s from ", messageName, circuit->name);
	LogDecnetAddress(LogMessages, LogDetail, &packet->from);
}

static void LogMessageEnd(void)
{
	Log(LogMessages, LogDetail, "\n");
}

static void LogLoopbackMessage(circuit_t *circuit, packet_t *packet, char *messageName)
{
	//Log(LogInfo, "Process pkt from %6s from ", circuit->name);
	Log(LogMessages, LogWarning, "Loopback pkt on %s from ", circuit->name);
	LogDecnetAddress(LogMessages, LogWarning, &packet->from);
	Log(LogMessages, LogWarning, " %s\n", messageName);
}
