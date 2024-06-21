/* dns.c: DNS support
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

/* Implemented using http://datatracker.ietf.org/doc/rfc1035/?include_text=1 */

#include <string.h>
#include <stdlib.h>
#if !defined(__VAX)
#include <ctype.h>
#endif
#include "basictypes.h"
#include "platform.h"
#include "route20.h"
#include "dns.h"
#include "socket.h"

dns_config_t DnsConfig;

typedef struct
{
	uint16 id;
	uint16 flags;
	uint16 qdcount;
	uint16 ancount;
	uint16 nscount;
	uint16 arcount;
} DnsQueryHeader;

typedef struct callback_entry *callback_entry_ptr;

typedef struct callback_entry
{
	int id;
	void (*callback)(byte *, void *);
	void *callbackContext;
	callback_entry_ptr next;
} callback_entry_t;

typedef struct
{
	DnsQueryHeader header;
	byte   data[8192];
} DnsQuery;

static socket_t DnsSocket;
static sockaddr_t DnsServer;
static callback_entry_t *callbackList = NULL;

static int IsValidNameToQuery(char *name);
static void DnsProcessResponse(void *context);
static callback_entry_t *FindCallbackEntry(int id);
static callback_entry_t *CreateCallbackEntry(int id);
static int ParseQuestion(packet_t *packet, int *currentOffset, char **name);
static int ParseResource(packet_t *packet, int *currentOffset, uint16 *type, byte **data, int *dataLength);

int DnsOpen(char *serverName)
{
	int ans;

    InitialiseSocket(&DnsSocket, "DNS");
	ans = OpenUdpSocket(&DnsSocket, 0);
	if (ans)
	{
		memcpy(&DnsServer, GetSocketAddressFromName(serverName, 53), sizeof(DnsServer));
		RegisterEventHandler(DnsSocket.waitHandle, "DNS socket", NULL, DnsProcessResponse);
	}

	return ans;
}

void DnsSendQuery(char *name, uint16 id, void (*callback)(byte *, void *), void *callbackContext)
{
	packet_t packet;
	DnsQuery query;
	char *namePtr;
	byte *dataPtr;
	byte i;
	callback_entry_t *callbackEntry;

    if (IsValidNameToQuery(name))
    {
        query.header.id = id;
        query.header.flags = Uint16ToBigEndian(0x0100);
        query.header.qdcount = Uint16ToBigEndian(0x0001);
        query.header.ancount = 0;
        query.header.nscount = 0;
        query.header.arcount = 0;

        strncpy((char *)(query.data + 1), name, sizeof(query.data) - 5);

        namePtr = name;
        dataPtr = query.data;
        i = 0;

        while (*namePtr != '\0')
        {
            if (*namePtr != '.')
            {
                i++;
            }
            else
            {
                *dataPtr = i;
                dataPtr += i + 1;
                i = 0;
            }

            namePtr++;
        }

        *dataPtr = i;
        dataPtr += i + 2;


        *dataPtr++ = 0;
        *dataPtr++ = 1;
        *dataPtr++ = 0;
        *dataPtr++ = 1;

        packet.rawData = (byte *)&query;
        packet.rawLen = (int)(dataPtr - (byte *)&query);

        callbackEntry = FindCallbackEntry(id);
        if (callbackEntry == NULL)
        {
            callbackEntry = CreateCallbackEntry(id);
        }

        callbackEntry->callback = callback;
        callbackEntry->callbackContext = callbackContext;

        Log(LogDns, LogDetail, "Sending DNS query for %s\n", name);
        SendToSocket(&DnsSocket, &DnsServer, &packet);
    }
    else
    {
	    Log(LogDns, LogDetail, "Not sending DNS query for %s as it is already an IP address\n", name);
    }
}

static int IsValidNameToQuery(char *name)
{
    int ans = 0;
    int i;

    for (i = 0; i < (int)strlen(name); i++)
    {
        if (!isdigit(name[i]) && name[i] != '.')
        {
            ans = 1;
            break;
        }
    }

    return ans;
}

static void DnsProcessResponse(void *context)
{
	packet_t packet;
	sockaddr_t receivedFrom;
	if (ReadFromDatagramSocket(&DnsSocket, &packet, &receivedFrom))
	{
	    int ok = 0;
		int haveIp = 0;
		int requestId;
		/*DumpPacket(&packet, "DNS packet.");*/
		if (packet.rawLen >= sizeof(DnsQueryHeader))
		{
			int i;
			int currentOffset = sizeof(DnsQueryHeader);
			uint16 type;
			byte *data;
			int dataLength;
		    DnsQueryHeader *header = (DnsQueryHeader *)packet.rawData;

			ok = 1;
			requestId = header->id;
		    header->qdcount = BigEndianToUint16(header->qdcount);
		    header->ancount = BigEndianToUint16(header->ancount);
		    Log(LogDns, LogVerbose, "DNS response, questions: %d, answers: %d\n", header->qdcount, header->ancount);
			for (i = 0; i < header->qdcount && ok; i++)
			{
                char *name;
				ok = ParseQuestion(&packet, &currentOffset, &name);
                Log(LogDns, LogDetail, "Processing DNS response for %s", name);
			}

			for (i = 0; i < header->ancount && ok; i++)
			{
				ok = ParseResource(&packet, &currentOffset, &type, &data, &dataLength);
				if (type == 1 && dataLength == 4)
				{
					callback_entry_t *callbackEntry = FindCallbackEntry(requestId);
					haveIp = 1;
					if (callbackEntry != NULL)
					{
                        Log(LogDns, LogDetail, " address is %d.%d.%d.%d", data[0], data[1], data[2], data[3]);
						callbackEntry->callback(data, callbackEntry->callbackContext);
					}
				}
			}

            Log(LogDns, LogDetail, "\n");
		}

		if (!ok)
		{
			Log(LogDns, LogWarning, "Invalid DNS response ignored\n");
		}
		else if (!haveIp)
		{
			Log(LogDns, LogWarning, "DNS response without host address ignored\n");
		}
	}
	else
	{
		Log(LogDns, LogWarning, "Failed to read DNS response\n");
	}
}

static callback_entry_t *FindCallbackEntry(int id)
{
	callback_entry_t *ans = callbackList;

	while (ans != NULL)
	{
		if (ans->id == id)
		{
			break;
		}

		ans = ans->next;
	}

	return ans;
}

static callback_entry_t *CreateCallbackEntry(int id)
{
	callback_entry_t *callbackEntry = (callback_entry_t *)malloc(sizeof(callback_entry_t));
	callbackEntry->id = id;
	callbackEntry->next = callbackList;
	callbackList = callbackEntry;
	return callbackEntry;
}


static int ParseQuestion(packet_t *packet, int *currentOffset, char **name)
{
    static char parsedName[1024];
	int ans = 0;

    parsedName[0] = 0;
    *name = parsedName;
	if (packet->rawLen >= *currentOffset + 1)
	{
		int ok = 1;
		int totalLength = *currentOffset + 4;
		int segLength;
		do
		{
			segLength = (((int)packet->rawData[*currentOffset]) & 0xFF) + 1;
			totalLength += segLength;

            if (strlen(parsedName) > 0)
            {
                strcat(parsedName, ".");
            }
            if ((strlen(parsedName) + segLength - 2) < sizeof(parsedName))
            {
                    strncat(parsedName, (char *)&packet->rawData[*currentOffset + 1], segLength - 1);
            }

			*currentOffset += segLength;
		    ok = packet->rawLen >= totalLength;
		} while (ok && segLength > 1);

		if (packet->rawLen >= totalLength)
		{
			ans = 1;
			*currentOffset = totalLength;
		}
	}

	return ans;
}

static int ParseResource(packet_t *packet, int *currentOffset, uint16 *type, byte **data, int *dataLength)
{
	int ans = 0;
	if (packet->rawLen >= *currentOffset + 12)
	{
		int reslength;
		*dataLength = BigEndianBytesToUint16(&packet->rawData[*currentOffset + 10]);
		reslength = *dataLength + 12;
		if (packet->rawLen >= *currentOffset + reslength)
		{
			ans = 1;
			*type = BigEndianBytesToUint16(&packet->rawData[*currentOffset + 2]);
			*data = &packet->rawData[*currentOffset + 12];
			*currentOffset += reslength;
		}
	}

	return ans;
}
