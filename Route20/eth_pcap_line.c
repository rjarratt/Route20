/* eth_pcap_line.c: Ethernet PCAP line
------------------------------------------------------------------------------

Copyright (c) 2014, Robert M. A. Jarratt
Portions Johnny Billquist

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

#pragma warning( push, 3 )
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#if !defined(__VAX)
#include <ctype.h>
#endif
#if !defined(WIN32)
#include <unistd.h>
#include <pcap/bpf.h>
//#include <sys/ioctl.h>
#endif
#pragma warning( pop )

#include "platform.h"
#include "route20.h"
#include "timer.h"
#include "eth_decnet.h"
#include "eth_line.h"
#include "eth_pcap_line.h"

#define ETH_MAX_DEVICE        20                        /* maximum ethernet devices */
#define ETH_DEV_NAME_MAX     256                        /* maximum device name size */
#define ETH_DEV_DESC_MAX     256                        /* maximum device description size */
#define ETH_PROMISC            1                        /* promiscuous mode = true */
#define PCAP_ERRBUF_SIZE     256
#define MIN_PACKET_SIZE      128

struct eth_list {
    int     num;
    char    name[ETH_DEV_NAME_MAX];
    char    desc[ETH_DEV_DESC_MAX];
};

static int eth_translate(char* name, char* translated_name);

int EthPcapLineStart(line_t* line)
{
    int ans = 0;
    eth_pcap_t* pcapContext = (eth_pcap_t*)line->lineContext;
    char devname[1024];
    char ebuf[PCAP_ERRBUF_SIZE];

    Log(LogEthPcapLine, LogInfo, "Starting line %s\n", line->name);

    pcapContext->pcap = NULL;

    if (eth_translate(line->name, devname))
    {
        Log(LogEthPcapLine, LogInfo, "Opening %s for packet capture\n", devname);
 
        if ((pcapContext->pcap = pcap_create(devname, ebuf)) == NULL)
        {
            Log(LogEthPcapLine, LogError, "Error creating device %s\n", ebuf);
        }
        else
        {
            if (pcap_set_promisc(pcapContext->pcap, ETH_PROMISC) != 0)
            {
                Log(LogEthPcapLine, LogError, "Error setting promiscuous mode\n");
            }
            else if (pcap_set_immediate_mode(pcapContext->pcap, 1) != 0)
            {
                Log(LogEthPcapLine, LogError, "Could not set immediate mode\n");
            }
            else if (pcap_activate(pcapContext->pcap) != 0)
            {
                Log(LogEthPcapLine, LogError, "Error activating packet capture\n");
            }
            else
            {
#if defined(WIN32)
                line->waitHandle = (int)pcap_getevent(pcapContext->pcap);
                if (pcap_setmintocopy(pcapContext->pcap, 0) != 0)
                {
                    Log(LogEthPcapLine, LogError, "Error setting min to copy\n");
                }
#else
                int one = 1;
                line->waitHandle = pcap_get_selectable_fd(pcapContext->pcap);
                if (line->waitHandle == PCAP_ERROR)
                {
                    Log(LogEthPcapLine, LogError, "Error getting selectable file descriptor: %s\n", pcap_geterr(pcapContext->pcap));
                }
                else if (pcap_setdirection(pcapContext->pcap, PCAP_D_IN) == PCAP_ERROR)
                {
                    Log(LogEthPcapLine, LogError, "Error setting direction of packet capture: %s\n", pcap_geterr(pcapContext->pcap));
                }
                //if (ioctl(line->waitHandle,BIOCSHDRCMPLT,&i))
                //{
                //	Log(LogError, "ioctl BIOCSHDRCMPLT failed\n");
                //}
#endif
                RegisterEventHandler(line->waitHandle, "EthPcap Line", line, line->LineWaitEventHandler);
                if (pcap_setnonblock(pcapContext->pcap, 1, ebuf) != 0)
                {
                    Log(LogEthPcapLine, LogError, "Error setting nonblock mode.\n%s\n", ebuf);
                }
                else
                {
                    struct bpf_program pgm;
                    if (pcap_compile(pcapContext->pcap, &pgm, "decnet or moprc or mopdl", 1, PCAP_NETMASK_UNKNOWN) == -1)
                    {
                        Log(LogEthPcapLine, LogError, "Failed to compile filter: %s\n", pcap_geterr(pcapContext->pcap));
                    }
                    if (pcap_setfilter(pcapContext->pcap, &pgm) == -1) // TODO: change filter not to pass LAT.
                    {
                        Log(LogEthPcapLine, LogError, "loading filter program");
                    }
                    else
                    {
                        QueueImmediate(line, (void (*)(void*))(line->LineUp));
                        ans = 1;
                    }
                }
            }

            if (!ans)
            {
                EthPcapLineStop(line);
            }
        }
    }


    if (!ans)
    {
        Log(LogEthPcapLine, LogError, "Could not open circuit for %s\n", line->name);
    }

    return ans;
}

void EthPcapLineStop(line_t* line)
{
    eth_pcap_t* pcapContext = (eth_pcap_t*)line->lineContext;

    pcap_close(pcapContext->pcap);
}

packet_t* EthPcapLineReadPacket(line_t* line)
{
    eth_pcap_t* pcapContext = (eth_pcap_t*)line->lineContext;

    static int hadErrorLastTime = 0;
    static packet_t packet;
    packet_t* ans;
    struct pcap_pkthdr* h;
    int pcapRes;
    struct pcap_stat stats;
    static unsigned int lastDroppedPacketCount = 0;

    pcap_stats(pcapContext->pcap, &stats);
    if (stats.ps_drop > lastDroppedPacketCount)
    {
        Log(LogEthPcapLine, LogError, "%u packets dropped since the last read on line %s\n", stats.ps_drop - lastDroppedPacketCount, line->name);
        lastDroppedPacketCount = stats.ps_drop;
    }

    do
    {
        if (hadErrorLastTime)
        {
            Log(LogEthPcapLine, LogError, "About to try reading again after error last time around\n");
        }

        ans = &packet;
        ans->IsDecnet = EthPcapIsDecnet;
        pcapRes = pcap_next_ex(pcapContext->pcap, &h, (const u_char**)&packet.rawData);
        if (hadErrorLastTime)
        {
            Log(LogEthPcapLine, LogError, "Completed reading again after error last time around\n");
        }

        if (pcapRes == 1) /* success */
        {
            hadErrorLastTime = 0;
            packet.rawLen = h->caplen;
            if (EthValidPacket(&packet))
            {
                if (packet.IsDecnet(&packet))
                {
                    GetDecnetAddress((decnet_eth_address_t*)&packet.rawData[0], &packet.to);
                    GetDecnetAddress((decnet_eth_address_t*)&packet.rawData[6], &packet.from);
                    Log(LogEthPcapLine, LogVerbose, "Packet from : "); LogDecnetAddress(LogEthPcapLine, LogVerbose, &packet.from); Log(LogEthPcapLine, LogVerbose, " received on line %s\n", line->name);
                    line->stats.validPacketsReceived++;
                    EthSetPayload(&packet);
                }
                else
                {
                    Log(LogEthPcapLine, LogVerbose, "Discarding valid non-DECnet Ethernet packet from %s\n", line->name);
                    ans = NULL;
                }
            }
            else
            {
                Log(LogEthPcapLine, LogWarning, "Discarding invalid Ethernet packet from %s\n", line->name);
                line->stats.invalidPacketsReceived++;
                ans = NULL;
            }
        }
        else if (pcapRes == 0) /* timeout */
        {
            hadErrorLastTime = 0;
            Log(LogEthPcapLine, LogVerbose, "No data from %s\n", line->name);
            ans = NULL;
        }
        else
        {
            Log(LogEthPcapLine, LogError, "Error reading from pcap: %s\n", pcap_geterr(pcapContext->pcap));
            ans = NULL;
            hadErrorLastTime = 1;
        }
    } while (pcapRes == 1 && ans == NULL); /* keep reading packets if we have discarded a loopback packet */

    return ans;
}

int EthPcapLineWritePacket(line_t* line, packet_t* packet)
{
    eth_pcap_t* pcapContext = (eth_pcap_t*)line->lineContext;
    u_char smallBuf[MIN_PACKET_SIZE];
    u_char* data = packet->rawData;
    int len = packet->rawLen;
    int retries = 0;
    char* pcapErr;

#define PCAP_WARN_RETRY 10
#define PCAP_ERROR_RETRY 50

    if (packet->rawLen < MIN_PACKET_SIZE)
    {
        memset(smallBuf, 0, MIN_PACKET_SIZE);
        memcpy(smallBuf, packet->rawData, packet->rawLen);
        data = smallBuf;
        len = MIN_PACKET_SIZE;
    }

    while (pcap_sendpacket(pcapContext->pcap, (const u_char*)data, len) != 0 && retries <= PCAP_ERROR_RETRY)
    {
        pcapErr = pcap_geterr(pcapContext->pcap);
        if (strcpy(pcapErr, "Bad file descriptor") == 0)
        {
            retries = PCAP_ERROR_RETRY + 1;
            break;
        }

        if (retries != 0 && (retries % PCAP_WARN_RETRY) == 0)
        {
            // TODO: Orderly shutdown hangs if this happens
            Log(LogEthPcapLine, LogWarning, "Experiencing problems writing to %s using pcap, retrying: %s\n", line->name, pcapErr);
        }

        Sleep(1);
        retries++;
    }

    if (retries > PCAP_ERROR_RETRY)
    {
        Log(LogEthPcapLine, LogError, "Error writing to %s using pcap: %s\n", line->name, pcap_geterr(pcapContext->pcap));
        return 0; // TODO: Not sure we handle return value 0, make sure we do something sensible with it, kill the circuit, try to bring it up again.
    }

    return 1;
}

/*
The libpcap provided API pcap_findalldevs() on most platforms, will
leverage the getifaddrs() API if it is available in preference to
alternate platform specific methods of determining the interface list.

A limitation of getifaddrs() is that it returns only interfaces which
have associated addresses.  This may not include all of the interesting
interfaces that we are interested in since a host may have dedicated
interfaces for a simulator, which is otherwise unused by the host.

One could hand craft the the build of libpcap to specifically use
alternate methods to implement pcap_findalldevs().  However, this can
get tricky, and would then result in a sort of deviant libpcap.

This routine exists to allow platform specific code to validate and/or
extend the set of available interfaces to include any that are not
returned by pcap_findalldevs.

*/
//int eth_host_devices(int used, int max, struct eth_list* list)
//{
//	pcap_t* conn;
//	int i, j, datalink;
//	char errbuf[PCAP_ERRBUF_SIZE];
//
//	for (i=0; i<used; ++i) {
//		/* Cull any non-ethernet interface types */
//		conn = pcap_open_live(list[i].name, ETH_MAX_PACKET, ETH_PROMISC, PCAP_READ_TIMEOUT, errbuf);
//		if (NULL != conn) datalink = pcap_datalink(conn), pcap_close(conn);
//		if ((NULL == conn) || (datalink != DLT_EN10MB)) {
//			for (j=i; j<used-1; ++j)
//				list[j] = list[j+1];
//			--used;
//			--i;
//		}
//	} /* for */
//
//#if defined(_WIN32)
//	/* replace device description with user-defined adapter name (if defined) */
//	for (i=0; i<used; i++) {
//		char regkey[2048];
//		char regval[2048];
//		LONG status;
//		DWORD reglen, regtype;
//		HKEY reghnd;
//
//		/* These registry keys don't seem to exist for all devices, so we simply ignore errors. */
//		/* Windows XP x64 registry uses wide characters by default,
//		so we force use of narrow characters by using the 'A'(ANSI) version of RegOpenKeyEx.
//		This could cause some problems later, if this code is internationalized. Ideally,
//		the pcap lookup will return wide characters, and we should use them to build a wide
//		registry key, rather than hardcoding the string as we do here. */
//		if(list[i].name[strlen( "\\Device\\NPF_" )] == '{') {
//			sprintf( regkey, "SYSTEM\\CurrentControlSet\\Control\\Network\\"
//				"{4D36E972-E325-11CE-BFC1-08002BE10318}\\%hs\\Connection", list[i].name+
//				strlen( "\\Device\\NPF_" ) );
//			if((status = RegOpenKeyExA (HKEY_LOCAL_MACHINE, regkey, 0, KEY_QUERY_VALUE, &reghnd)) != ERROR_SUCCESS) {
//				continue;
//			}
//			reglen = sizeof(regval);
//
//			/* look for user-defined adapter name, bail if not found */    
//			/* same comment about Windows XP x64 (above) using RegQueryValueEx */
//			if((status = RegQueryValueExA (reghnd, "Name", NULL, &regtype, regval, &reglen)) != ERROR_SUCCESS) {
//				RegCloseKey (reghnd);
//				continue;
//			}
//			/* make sure value is the right type, bail if not acceptable */
//			if((regtype != REG_SZ) || (reglen > sizeof(regval))) {
//				RegCloseKey (reghnd);
//				continue;
//			}
//			/* registry value seems OK, finish up and replace description */
//			RegCloseKey (reghnd );
//			sprintf (list[i].desc, "%s", regval);
//		}
//	} /* for */
//#endif
//
//	return used;
//}

static int eth_devices(int max, struct eth_list* list)
{
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

#ifndef DONT_USE_PCAP_FINDALLDEVS
    /* retrieve the device list */
    const char* pcap_version = pcap_lib_version();
    Log(LogEthPcapLine, LogInfo, "%s\n", pcap_version);

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        char* msg = "Eth: error in pcap_findalldevs: %s\r\n";
        Log(LogEthPcapLine, LogError, msg, errbuf);
    }
    else
    {
        /* copy device list into the passed structure */
        for (i = 0, dev = alldevs; dev; dev = dev->next)
        {
            //struct pcap_addr *addr = dev->addresses;
            Log(LogEthPcapLine, LogInfo, "Device list entry %d. Name %s. Description %s.\n", i, dev->name, (dev->description == NULL) ? "n/a" : dev->description);
            //while (addr != NULL)
            //{
            //	Log(LogInfo, "Address family %d: %d %d %d %d %d %d\n", addr->addr->sa_family, addr->addr->sa_data[0] & 0xFF, addr->addr->sa_data[1] & 0xFF, addr->addr->sa_data[2] & 0xFF, addr->addr->sa_data[3] & 0xFF, addr->addr->sa_data[4] & 0xFF, addr->addr->sa_data[5] & 0xFF);
            //	addr = addr->next;
            //}
            if ((dev->flags & PCAP_IF_LOOPBACK) || (!strcmp("any", dev->name))) continue;
            list[i].num = i;
            strncpy(list[i].name, dev->name, ETH_DEV_NAME_MAX);
            if (dev->description)
            {
                strncpy(list[i].desc, dev->description, ETH_DEV_DESC_MAX);
            }
            else
            {
                strncpy(list[i].desc, "No description available", ETH_DEV_DESC_MAX);
            }
            i++;
            if (i >= max)
            {
                Log(LogEthPcapLine, LogWarning, "Too many devices, the limit is %d\n", max);
                break;
            }
        }

        /* free device list */
        pcap_freealldevs(alldevs);
    }
#endif

    ///* Add any host specific devices and/or validate those already found */
    //i = eth_host_devices(i, max, list);

    /* return device count */
    return i;
}

static int eth_getname(int number, char* name, struct eth_list* list, int count)
{
    int result = 0;
    if (count > number)
    {
        strcpy(name, list[number].name);
        result = 1;
    }

    return result;
}

static int eth_checkname(char* name, struct eth_list* list, int count)
{
    int found = 0;
    int i;
    for (i = 0; i < count && !found; i++)
    {
        if (stricmp(name, list[i].name) == 0)
        {
            found = 1;
        }
    }

    return found;
}

static int eth_translate(char* name, char* translated_name)
{
    int result = 0;
    struct eth_list list[ETH_MAX_DEVICE];
    int count = eth_devices(ETH_MAX_DEVICE, list);

    if (eth_checkname(name, list, count))
    {
        strcpy(translated_name, name);
        result = 1;
    }
    else
    {
        char* numberPtr = name;
        while (!isdigit(*numberPtr) && *numberPtr != '\0')
        {
            numberPtr++;
        }

        if (numberPtr != NULL)
        {
            result = eth_getname(atoi(numberPtr), translated_name, list, count);
        }
    }

    if (!result)
    {
        Log(LogEthPcapLine, LogError, "Cannot find interface %s\n", name);
    }

    return result;
}
