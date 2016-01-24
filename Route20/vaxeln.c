/* vaxeln.c: VAXELN specific support
  ------------------------------------------------------------------------------

   Copyright (c) 2016, Robert M. A. Jarratt

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
#if defined(__VAX)
#include $vaxelnc
#include $nidefs
#include $ni_utility
#include $netman_utility
#include $kernelmsg /* message symbols */
#include descrip
#include "platform.h"
#include <if.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include "route20.h"
#include "logging.h"
#include "constants.h"
#include "node.h"
#include "circuit.h"
#include "routing_database.h"
#include <stdio.h>

#define PACKET_BUFFER_LEN 1600
#define PACKET_HEADER_LEN 14

static char *GetMsg(int);
static void OpenLog(void);
static void CloseLog(void);
static int ElnConfig(char *fileName, ConfigReadMode mode);

int numCircuits;

FILE *logFile;
typedef struct pcap_vaxeln
{
    PORT dispatchPort;
    PORT controlPort;
    PORT dataPort;
    PORT transmitReplyPort;
    int portalId;
} pcap_vaxeln_t;

route20()
{
    int status;
    /*int arguments=eln$program_argument_count();
    VARYING_STRING(255) configFileName;*/
    $DESCRIPTOR(startTime, "23-JAN-2016 09:00:00");
    LARGE_INTEGER tvalue;

    tvalue = eln$time_value (&startTime);
    ker$set_time (NULL, &tvalue);
    
    InitialiseLogging();
    if (0/*arguments < 1*/)
    {
        Log(LogGeneral, LogFatal, "Program must be configured with an argument, which is the path to the configuration file\n");
    }
    else
    {
        /*eln$program_argument(&configFileName, 1);
        configFileName.data[configFileName.count] = '\0';
        Log(LogGeneral, LogInfo, "Configuration file is %s\n", configFileName.data);*/
        /* As there is no obvious way to set the Ethernet physical address, we include DECnet in the image, so that
           it can set the physical address. Then we stop it, here, and take over DECnet operation
        */
        eln$netman_stop_network(&status);
        Log(LogGeneral, LogInfo, "Stop DECnet status %s(%d)\n", GetMsg(status), status);
        if (Initialise(ElnConfig, "" /*configFileName.data*/))
        {
            NspInitialise();
            NetManInitialise();
            MainLoop();
        }
    }

    Log(LogGeneral, LogInfo, "Exited");
}

int stricmp(char *str1, char *str2)
{
    return strcmp(str1, str2);
}

struct hostent *gethostbyname(const char *name)
{
    return NULL;
}

double difftime(time_t time2, time_t time1)
{
    return (double)(time2 - time1);
}

size_t strftime(char *s, size_t smax, const char *fmt, const struct tm *tp)
{
    sprintf(s, "%04d-%02d-%02d %02d:%02d:%02d", tp->tm_year + 1900, tp->tm_mon + 1, tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec);
    return 0;
}

int isdigit(char c)
{
    return c >= '0' && c <= '9';
}

static char *GetMsg(int status)
{
    char * result;
    static VARYING_STRING(255) message;
    eln$get_status_text(status, 0, &message);
    message.data[message.count] = '\0';
    result = message.data;
    return result;
}

static void OpenLog(void)
{
	logFile = fopen("Route20.log", "w+");
}

static void CloseLog(void)
{
	fclose(logFile);
}

void VLog(LogSource source, LogLevel level, char *format, va_list argptr)
{
	int n;
	char buf[MAX_LOG_LINE_LEN];
	static int onNewLine = 1;

	time_t now;

	if (level <= LoggingLevels[source])
	{
		if (onNewLine)
		{
			time(&now);
			strftime(buf, 80, "%Y-%m-%d %H:%M:%S", localtime(&now));
			fprintf(logFile, buf);
            fprintf(logFile, "\t");
            printf(buf);
            printf(" ");

            fprintf(logFile, "%s\t", LogSourceName[source]);
            printf("%s ", LogSourceName[source]);
		}

		n = vsprintf(buf, format, argptr);
		onNewLine = buf[n-1] == '\n';
		fprintf(logFile, buf);
        printf(buf);
		fflush(logFile);
	}
}

int ElnConfig(char *fileName, ConfigReadMode mode)
{
    LoggingLevels[LogGeneral] = LogInfo;
    LoggingLevels[LogMessages] = LogInfo;
    LoggingLevels[LogEthPcapLine] = LogInfo;
    nodeInfo.address.area = 5;
    nodeInfo.address.node = 30;
    nodeInfo.level = 2;
    nodeInfo.priority = 64;
    strcpy(nodeInfo.name, "A5RTR2");
	CircuitCreateEthernetPcap(&Circuits[1],"eth0", 3, ProcessCircuitEvent);
    Log(LogGeneral, LogDetail, "Finished hard coded configuration.\n");

    return 1;
}

void ProcessEvents(circuit_t circuits[], int numCircuits, void (*process)(circuit_t *, packet_t *))
{
    int i;
    int status;
    int waitResult;
    LARGE_INTEGER timeout;
    unsigned int handles[MAX_EVENT_HANDLERS];
    static $DESCRIPTOR(timeoutString,"0 00:00:01.00"); /* TODO: calculate timeout properly with seconds to next due timer */

    timeout = eln$time_value(&timeoutString);

    while(1)
    {
		if (eventHandlersChanged)
		{
            if (numEventHandlers > 2)
            {
                Log(LogGeneral, LogFatal, "Cannot handle more than 2 event handlers, there are now %d event handlers\n", numEventHandlers);
                break;
            }

            Log(LogGeneral, LogVerbose, "Refreshing event handles to wait for after a change in event handlers, there are now %d event handlers\n", numEventHandlers);
			for (i = 0; i < numEventHandlers; i++)
			{
				handles[i] = eventHandlers[i].waitHandle;
 			}

			eventHandlersChanged = 0;
		}

        /* TODO: pass handle array as variable arg list */
        if (numEventHandlers == 2)
        {
            ker$wait_any(&status, &waitResult, &timeout, handles[0], handles[1]);
        }
        else
        {
            ker$wait_any(&status, &waitResult, &timeout, handles[0]);
        }

        if ((status % 2) == 0)
        {
    	    Log(LogGeneral, LogFatal, "Wait failed: %s(%d)\n", GetMsg(status), status);
        }
        else
        {
    	    Log(LogGeneral, LogVerbose, "Wait return is %d, processing timers\n", waitResult);
			ProcessTimers();
            Log(LogGeneral, LogVerbose, "Finished processing timers\n");
			if (waitResult > 0)
			{
                Log(LogGeneral, LogDetail, "Processing event handler for %s\n", eventHandlers[waitResult - 1].name);
				eventHandlers[waitResult - 1].eventHandler(eventHandlers[waitResult - 1].context);
			}
        }
    }
}

void pcap_close(pcap_t *p)
{
    pcap_vaxeln_t *connection = (pcap_vaxeln_t *)p;
    eln$ni_disconnect(NULL, &connection->portalId, &connection->controlPort);
    ker$delete(NULL, &connection->dispatchPort);
}

pcap_t *pcap_open_live (const char *device, int snaplen, int promisc, int to_ms, char *ebuf)
{
    pcap_t *result = NULL;
    int status;
    int count;
    int portalId;
    PORT dispatchPort;
    PORT transmitReplyPort;
    pcap_vaxeln_t *connection;
    struct eln$ni_configuration config;
    struct eln$ni_format_and_mux form;
    int mode;
    int pad;
    eln$ni_byte multicastCount;
    struct eln$ni_multicast_list multicastList;
    int i;
    static struct pcap_if dev[8];

    Log(LogEthPcapLine, LogDetail, "pcap_open_live() called for device %s\n", device);

    eln$ni_get_configuration(&status, &count, &config);

    if (status == ELN$_SUCCESS)
    {
        for (i = 0; i < count; i++)
        {
            if (strncmp(device, config.clist.list[i].name.string_text, config.clist.list[i].name.string_length)==0)
            {
                break;
            }
        }

        if (i >= count)
        {
            Log(LogEthPcapLine, LogError, "Device %s does not exist\n", device);
        }
        else
        {
            ker$create_port(&status, &dispatchPort, 4);
            ker$create_port(&status, &transmitReplyPort, 4);
            form.format = ELN$K_NI_PTT;
            form.mux.ptt = 0x0360;
            mode = 0;
            pad = 0;

            multicastCount = 3;

            /* All routers */
            multicastList.list[0].address[0] = 0xAB;
            multicastList.list[0].address[1] = 0x00;
            multicastList.list[0].address[2] = 0x00;
            multicastList.list[0].address[3] = 0x03;
            multicastList.list[0].address[4] = 0x00;
            multicastList.list[0].address[5] = 0x00;

            /* All Level 2 Routers */
            multicastList.list[1].address[0] = 0x09;
            multicastList.list[1].address[1] = 0x00;
            multicastList.list[1].address[2] = 0x2B;
            multicastList.list[1].address[3] = 0x02;
            multicastList.list[1].address[4] = 0x00;
            multicastList.list[1].address[5] = 0x00;

            /* All end nodes */
            multicastList.list[2].address[0] = 0xAB;
            multicastList.list[2].address[1] = 0x00;
            multicastList.list[2].address[2] = 0x00;
            multicastList.list[2].address[3] = 0x04;
            multicastList.list[2].address[4] = 0x00;
            multicastList.list[2].address[5] = 0x00;

            eln$ni_connect(&status, &portalId, config.clist.list[i].control_port, &dispatchPort, &form, NULL, &mode, &multicastCount, NULL, NULL, &multicastList, NULL, &pad);
            if (status % 2)
            {
                Log(LogEthPcapLine, LogInfo, "Connected to %s. Portal id is %d\n", device, portalId);
                connection = (pcap_vaxeln_t *)malloc(sizeof(pcap_vaxeln_t));
                memcpy(&connection->dispatchPort, &dispatchPort, sizeof(PORT));
                memcpy(&connection->controlPort, config.clist.list[i].control_port, sizeof(PORT));
                memcpy(&connection->dataPort, config.clist.list[i].data_port, sizeof(PORT));
                memcpy(&connection->transmitReplyPort, &transmitReplyPort, sizeof(PORT));
                connection->portalId = portalId;
                result = (pcap_t *)connection;
            }
            else
            {
                Log(LogEthPcapLine, LogError, "Failed to connect to %s. Error is %s\n", device, GetMsg(status));
                ker$delete(NULL, &dispatchPort);
                ker$delete(NULL, &transmitReplyPort);
            }
        }
    }
    else
    {
        Log(LogEthPcapLine, LogError, "eln$ni_get_configuration failed with status %s(%d)\n", GetMsg(status), status);
    }

    return result;
}

int	pcap_fileno(pcap_t *p)
{
    pcap_vaxeln_t *connection = (pcap_vaxeln_t *)p;
    return (int)&connection->dispatchPort;
}

int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{
    int status;
    int count;
    struct eln$ni_configuration config;
    int i;
    static struct pcap_if dev[8];

    eln$ni_get_configuration(&status, &count, &config);

    if (status == ELN$_SUCCESS)
    {
        *alldevsp = &dev;
        for (i = 0; i < count; i++)
        {
            dev[i].name = config.clist.list[i].name.string_text;
            dev[i].description = "<test>";
            dev[i].flags = 0;
            dev[i].next = NULL;
            if (i > 0)
            {
                dev[i-1].next = &dev[i];
            }
        }
    }
    else
    {
        Log(LogEthPcapLine, LogError, "eln$ni_get_configuration failed with status %s(%d)\n", GetMsg(status), status);
    }

    return (status == ELN$_SUCCESS) ? 0 : -1;
}

void pcap_freealldevs(pcap_if_t *alldevs)
{
}

char *pcap_geterr(pcap_t *p)
{
    return "";
}

int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data)
{
    pcap_vaxeln_t *connection = (pcap_vaxeln_t *)p;
    int status;
    MESSAGE msg;
    char *dataPtr;
    unsigned int dataSize;
    struct eln$ni_datalink_address destAddress;
    struct eln$ni_datalink_address srcAddress;
    struct eln$ni_format_and_mux form;
    int result = 0;
    static struct pcap_pkthdr headerResult;
    static u_char buffer[PACKET_BUFFER_LEN];

    eln$ni_receive(&status, &connection->dispatchPort, &msg, &dataPtr, &dataSize, &destAddress, &srcAddress, &form, NULL, NULL);

    if ((status % 2) == 1)
    {
        if (form.format == ELN$K_NI_PTT && form.mux.ptt == 0x0360)
        {
            result = 1;
            *pkt_header = &headerResult;
            if ((dataSize + 14) > sizeof(buffer))
            {
                Log(LogEthPcapLine, LogError, "Truncating large packet, received packet of %d bytes\n", dataSize);
                dataSize = sizeof(buffer) - PACKET_HEADER_LEN;
            }
            headerResult.caplen = dataSize + PACKET_HEADER_LEN;
            memcpy(&buffer[0], &destAddress, 6);
            memcpy(&buffer[6], &srcAddress, 6);
            buffer[12] = 0x60;
            buffer[13] = 0x03;
            memcpy(&buffer[PACKET_HEADER_LEN], dataPtr, dataSize);
            *pkt_data = buffer;
        }
        ker$delete(NULL, msg);
    }
    else if (status != KER$_NO_MESSAGE)
    {
        Log(LogEthPcapLine, LogError, "eln$ni_receive returned status %s(%d)\n", GetMsg(status), status);
    }

    return result;
}

int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
{
    pcap_vaxeln_t *connection = (pcap_vaxeln_t *)p;
    int status;
    MESSAGE msg;
    u_char *buffer;
    struct eln$ni_datalink_address dest;
    struct eln$ni_format_and_mux form;
    int dataSize = size - PACKET_HEADER_LEN;

    eln$ni_allocate_buffer(&status, dataSize, &msg, &buffer);
    if ((status % 2) == 1)
    {
        memcpy(buffer, &buf[PACKET_HEADER_LEN], dataSize);
        memcpy(dest.address, buf, 6);
        form.format = ELN$K_NI_PTT;
        form.mux.ptt = 0x0360;
        eln$ni_transmit(&status, connection->portalId, &connection->dataPort, buffer, &msg, dataSize, &dest, &form, &connection->transmitReplyPort);
        if ((status % 2) != 1)
        {
            Log(LogEthPcapLine, LogError, "Failed to transmit buffer. Reason: %s(%d)\n", GetMsg(status), status);
        }
        else
        {
            Log(LogEthPcapLine, LogDetail, "Transmitted packet\n");
            ker$wait_any(&status, NULL, NULL, &connection->transmitReplyPort);
            if ((status % 2) != 1)
            {
                Log(LogEthPcapLine, LogError, "Wait for reply failed. Reason: %s(%d)\n", GetMsg(status), status);
            }
            else
            {
                eln$ni_transmit_status(&status, &connection->transmitReplyPort, &msg, NULL);
                if ((status % 2) != 1)
                {
                    Log(LogEthPcapLine, LogError, "Transmit status: %s(%d)\n", GetMsg(status), status);
                }
                ker$delete(NULL, msg);
            }
        }
    }
    else
    {
        Log(LogEthPcapLine, LogError, "Could not allocate transmit buffer, packet lost. Reason: %s(%d)\n", GetMsg(status), status);
    }

    return (status % 2) != 1;
}

int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
{
    return 0;
}

int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)
{
    return 0;
}

#endif
