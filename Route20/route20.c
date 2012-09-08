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

#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include "platform.h"
#include "route20.h"
#include "circuit.h"
#include "messages.h"
#include "decnet.h"
#include "adjacency.h"
#include "timer.h"
#include "init_layer.h"
#include "routing_database.h"
#include "decision.h"
#include "forwarding.h"
#include "update.h"
#include "dns.h"

static int dnsNeeded = 0;
static int numCircuits = 0;
static init_layer_t *ethernetInitLayer;

// TODO: Add Phase III support
static int ReadConfig(char *fileName);
static char *ReadConfigLine(FILE *f);
static char *ReadNodeConfig(FILE *f, int *ans);
static char *ReadEthernetConfig(FILE *f, int *ans);
static char *ReadBridgeConfig(FILE *f, int *ans);
static char *ReadDnsConfig(FILE *f, int *ans);
static int SplitString(char *string, char splitBy, char **left, char **right);
static void PurgeAdjacenciesCallback(rtimer_t *, char *, void *);
static void ProcessPacket(circuit_t *circuit, packet_t *packet);
static int RouterHelloIsForThisNode(decnet_address_t *from, int iinfo);
static int EndnodeHelloIsForThisNode(decnet_address_t *from, int iinfo);
static int VersionSupported(byte tiver[3]);
static void LogMessage(circuit_t *circuit, packet_t *packet, char *messageName);

#pragma warning(disable : 4996)

int Initialise(char *configFileName)
{
	int ans;
	int i;
	time_t now;

	DnsConfig.dnsConfigured = 0;

	ans = ReadConfig(configFileName);
	if (ans)
	{
		InitialiseAdjacencies();
		InitialiseDecisionProcess();
		InitialiseUpdateProcess();
		SetAdjacencyStateChangeCallback(ProcessAdjacencyStateChange);
		SetCircuitStateChangeCallback(ProcessCircuitStateChange);
	    nodeInfo.state = Running;
		for (i = 1; i <= numCircuits; i++)
		{
		    ans &= (*(Circuits[i].Open))(&Circuits[i]);
		    (*(Circuits[i].Start))(&Circuits[i]);
		}
		time(&now);
		CreateTimer("PurgeAdjacencies", now + 1, 1, NULL, PurgeAdjacenciesCallback);
		ethernetInitLayer = CreateEthernetInitializationSublayer();
		ethernetInitLayer->Start(Circuits, numCircuits);

		if (DnsConfig.dnsConfigured && dnsNeeded)
		{
			DnsOpen(DnsConfig.serverName);
		}
		else
		{
			DnsWaitHandle = -1;
		}
	}

	return ans;
}

void MainLoop(void)
{
	Log(LogInfo, "Main loop start\n");

	ProcessEvents(Circuits, numCircuits, ProcessPacket);

	Log(LogInfo, "Main loop terminated\n");
	nodeInfo.state = Stopping;

	StopAllTimers();
	ethernetInitLayer->Stop();
	Log(LogInfo, "Shutdown complete\n");
}

static int ReadConfig(char *fileName)
{
	FILE *f;
	int ans = 1;
	int nodePresent = 0;
	if ((f = fopen(fileName, "r")) == NULL)
	{
		Log(LogError, "Could not open the configuration file: %s", fileName);
		ans = 0;
	}

	if (ans)
	{
		char *line = "";
		while(line != NULL)
		{
			if (stricmp(line, "[node]") == 0)
			{
				nodePresent = 1;
				line = ReadNodeConfig(f, &ans);
			}
			else if (stricmp(line, "[ethernet]") == 0)
			{
				line = ReadEthernetConfig(f, &ans);
			}
			else if (stricmp(line, "[bridge]") == 0)
			{
				line = ReadBridgeConfig(f, &ans);
			}
			else if (stricmp(line, "[dns]") == 0)
			{
				line = ReadDnsConfig(f, &ans);
			}
			else
			{
				line = ReadConfigLine(f);
			}
		}

		fclose(f);
	}

	if (!nodePresent)
	{
		Log(LogError, "Node section missing from configuration file\n");
		ans = 0;
	}
	else if (numCircuits <= 0)
	{
		Log(LogError, "No circuits defined\n");
		ans = 0;
	}

	return ans;
}

static char *ReadNodeConfig(FILE *f, int *ans)
{
	char *line;
	char *name;
	char *value;
	int addressPresent = 0;

	nodeInfo.priority = 64;
	nodeInfo.level = 2;

	while (line = ReadConfigLine(f))
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
					Log(LogError, "Node address must be in the form <area>.<node>\n");
				}
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
		Log(LogError, "Node address must be defined in the configuration file\n");
	}

	return line;
}

static char *ReadEthernetConfig(FILE *f, int *ans)
{
	char *line;
	char *name;
	char *value;
	int cost = 3;
	char pcapInterface[80] = "";

	while (line = ReadConfigLine(f))
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
		Log(LogError, "Interface not defined for ethernet circuit\n");
	}
	else
	{
		if (numCircuits >= NC)
		{
			Log(LogError, "Too many circuit definitions, ignoring ethernet interface %s\n", pcapInterface);
		}
		else
		{
			Log(LogInfo, "Ethernet interface is: %s\n", pcapInterface);
			CircuitCreateEthernetPcap(&Circuits[1 + numCircuits++], pcapInterface, cost);
		}
	}

	return line;
}

static char *ReadBridgeConfig(FILE *f, int *ans)
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

	while (line = ReadConfigLine(f))
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
					Log(LogError, "Bridge address must be of the form <host>:<port>\n");
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
		Log(LogError, "Address not defined for bridge circuit\n");
	}
	else if (!receivePortPresent)
	{
		*ans = 0;
		Log(LogError, "Port not defined for bridge circuit\n");
	}
	else
	{
		if (numCircuits >= NC)
		{
			Log(LogError, "Too many circuit definitions, ignoring bridge interface %s\n", hostName);
		}
		else
		{
			Log(LogInfo, "Bridge interface sends to %s:%d and listens on %d\n", hostName, destPort, receivePort);
			CircuitCreateEthernetSocket(&Circuits[1 + numCircuits++], hostName, receivePort, destPort, cost);
			dnsNeeded = 1;
		}
	}

	return line;
}

static char *ReadDnsConfig(FILE *f, int *ans)
{
	char *line;
	char *name;
	char *value;
	char  addressPresent = 0;
	int   pollPresent = 0;

	while (line = ReadConfigLine(f))
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
		Log(LogError, "Address not defined for DNS\n");
	}
	else if (!pollPresent)
	{
		*ans = 0;
		Log(LogError, "Poll period not defined for DNS\n");
	}
	else
	{
		DnsConfig.dnsConfigured = 1;
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

	return ans;
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

		*ptr++;
	}

	return *right != NULL;
}

static void PurgeAdjacenciesCallback(rtimer_t *timer, char *name, void *context)
{
	PurgeAdjacencies();
}

static void ProcessPacket(circuit_t *circuit, packet_t *packet)
{
	if (nodeInfo.state == Running)
	{
		static int n = 0;
		if (GetMessageBody(packet))
		{
			if (IsInitializationMessage(packet))
			{
				//LogMessage(circuit, packet, "Initialization");
			}
			else if (IsVerificationMessage(packet))
			{
				//LogMessage(circuit, packet, "Verification");
			}
			else if (IsHelloAndTestMessage(packet))
			{
				//LogMessage(circuit, packet, "Hello and Test");
			}
			else if (IsLevel1RoutingMessage(packet))
			{
				routing_msg_t *msg;
				//LogMessage(circuit, packet, "Level 1 Routing");
				msg = ParseRoutingMessage(packet);
				if (msg != NULL)
				{
					ProcessLevel1RoutingMessage(msg);
					FreeRoutingMessage(msg);
				}
			}
			else if (IsLevel2RoutingMessage(packet) && nodeInfo.level == 2)
			{
				routing_msg_t *msg;
				//LogMessage(circuit, packet, "Level 2 Routing");
				msg = ParseRoutingMessage(packet);
				if (msg != NULL)
				{
					ProcessLevel2RoutingMessage(msg);
					FreeRoutingMessage(msg);
				}
			}
			else if (IsEthernetRouterHelloMessage(packet))
			{
				//LogMessage(circuit, packet, "Ethernet Router Hello");
				if (IsValidRouterHelloMessage(packet))
				{
					ethernet_router_hello_t *msg = (ethernet_router_hello_t *)packet->payload;
					decnet_address_t from;
					GetDecnetAddress(&msg->id, &from);
					if (RouterHelloIsForThisNode(&from, msg->iinfo))
					{
						if (VersionSupported(msg->tiver))
						{
							AdjacencyType at = GetRouterLevel(msg->iinfo) == 1 ? Level1RouterAdjacency : Level2RouterAdjacency;
							CheckRouterAdjacency(&from, circuit, at, msg->timer, msg->priority, msg->rslist, msg->rslistlen/sizeof(rslist_t));
						}
					}
				}
			}
			else if (IsEthernetEndNodeHelloMessage(packet))
			{
				//LogMessage(circuit, packet, "Ethernet Endnode Hello");
				if (IsValidEndnodeHelloMessage(packet))
				{
					ethernet_endnode_hello_t *msg = (ethernet_endnode_hello_t *)packet->payload;
					decnet_address_t from;
					GetDecnetAddress(&msg->id, &from);
					if (EndnodeHelloIsForThisNode(&from, msg->iinfo))
					{
						if (VersionSupported(msg->tiver))
						{
							CheckEndnodeAdjacency(&from, circuit, msg->timer);
						}
					}
				}
			}
			else if (IsDataMessage(packet))
			{
				//LogMessage(circuit, packet, "Data message");
				if (IsValidDataPacket(packet))
				{
	    			ForwardPacket(packet);
				}
			}
			else
			{
				DumpPacket(packet, "Discarding unknown packet.");
			}
		}
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

static int VersionSupported(byte tiver[3])
{
	int ans = 0;
	if (tiver[0] == 2 && tiver[1] == 0 && tiver[2] == 0)
	{
		ans = 1;
	}

	if (ans == 0)
	{
		Log(LogInfo, "Received message for unsupported routing specification version %d.%d.%d\n", tiver[0], tiver[1], tiver[2]);
	}

	return ans;
}

static void LogMessage(circuit_t *circuit, packet_t *packet, char *messageName)
{
	//Log(LogInfo, "Process pkt from %6s from ", circuit->name);
	Log(LogInfo, "Process pkt from ", circuit->name);
	LogDecnetAddress(LogInfo, &packet->from);
	Log(LogInfo, " %s\n", messageName);
}