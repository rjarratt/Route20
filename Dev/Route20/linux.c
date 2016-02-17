/* linux.c: Linux specific support
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
#if !defined(WIN32)

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <limits.h>
#include <signal.h>

#include "constants.h"
#include "platform.h"
#include "timer.h"
#include "route20.h"
#include "nsp.h"
#include "dns.h"

static void ProcessPackets(circuit_t *circuit, void (*process)(circuit_t *, packet_t *));
static void SigTermHandler(int signum);

int main(int argc, char *argv[])
{
	char configFileName[PATH_MAX];

    /* Our process ID and Session ID */
    pid_t pid, sid;

	if (argc > 1)
	{
		strncpy(configFileName, argv[1], PATH_MAX - 1);
		configFileName[PATH_MAX - 1] = '\0';
	}
	else
	{
		getcwd(configFileName, PATH_MAX - 1);
		strcat(configFileName, "/");
		strcat(configFileName, CONFIG_FILE_NAME);
	}

    InitialiseLogging();
    ReadConfig(configFileName, ConfigReadModeInitial);

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0)
	{
		printf("Fork failed\n");
        exit(EXIT_FAILURE);
    }

	/* If we got a good PID, then we can exit the parent process. */
    if (pid > 0)
	{
		printf("Daemon running with pid %d\n", pid);
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);
        
   openlog("Route20", 0, LOG_DAEMON);

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) 
	{
        Log(LogGeneral, LogFatal, "Failed to set SID");
        exit(EXIT_FAILURE);
    }
    
    /* Change the current working directory */
    if ((chdir("/")) < 0)
	{
        Log(LogGeneral, LogFatal, "Failed to change directory to root");
        exit(EXIT_FAILURE);
    }
    
    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    Log(LogGeneral, LogInfo, "Initialising");
	if (Initialise(ReadConfig, configFileName))
	{
        if (DecnetInitialise())
        {
		    NspInitialise();
		    NetManInitialise();
            MainLoop();
        }
	}

    Log(LogGeneral, LogInfo, "Exited");
    exit(EXIT_SUCCESS);
}

void VLog(LogSource source, LogLevel level, char *format, va_list argptr)
{
	static char line[MAX_LOG_LINE_LEN];
	static int  currentLen = 0;
	static int onNewLine = 1;

    if (level <= LoggingLevels[source])
	{
		int sysLevel;
		switch (level)
		{
		case LogVerbose:
			{
				sysLevel = LOG_DEBUG;
				break;
			}
		case LogWarning:
			{
				sysLevel = LOG_WARNING;
				break;
			}
		case LogInfo:
			{
				sysLevel = LOG_INFO;
				break;
			}
		case LogDetail:
			{
				sysLevel = LOG_DEBUG;
				break;
			}
		case LogError:
			{
				sysLevel = LOG_ERR;
				break;
			}
		case LogFatal:
			{
				sysLevel = LOG_CRIT;
				break;
			}
		default:
			{
				sysLevel = LOG_ERR;
				break;
			}
		}

		currentLen += vsprintf(&line[currentLen], format, argptr);
		onNewLine = line[currentLen-1] == '\n';

		if (onNewLine)
		{
			syslog(sysLevel, "%s %s", LogSourceName[source], line);
			currentLen = 0;
		}
	}
}

// TODO: Add threading to Linux implementation
void QueuePacket(circuit_t *circuit, packet_t *packet)
{
    ProcessPacket(circuit, packet);
}

void ProcessEvents(circuit_t circuits[], int numCircuits, void (*process)(circuit_t *, packet_t *))
{
	int i;
	int h;
	int nfds = 0;
	fd_set handles;

	signal(SIGTERM, SigTermHandler);

	while(1)
	{
		struct timespec timeout;
		timeout.tv_sec = SecondsUntilNextDue();
		timeout.tv_nsec = 0;

        for (h = 0; h < numEventHandlers; h++)
        {
            FD_SET(eventHandlers[h].waitHandle, &handles);
            if (eventHandlers[h].waitHandle > nfds)
            {
                nfds = eventHandlers[h].waitHandle;
            }
        }

		i = pselect(nfds + 1, &handles, NULL, NULL, &timeout, NULL);
		if (i == -1)
		{
			if (errno == EINTR)
			{
				break;
			}
			else
			{
			    Log(LogGeneral, LogError, "pselect error: %d\n", errno);
			}
		}
		else
		{
			ProcessTimers();
			if (i > 0)
			{
    			for (h = 0; h < numEventHandlers; h++)
	    		{
		    		if (FD_ISSET(eventHandlers[h].waitHandle, &handles))
                    {
				        eventHandlers[h].eventHandler(eventHandlers[h].context);
                    }
    			}
			}
		}
	}
}

static void ProcessPackets(circuit_t *circuit, void (*process)(circuit_t *, packet_t *))
{
	packet_t *packet;

	do
	{
	    packet = (*(circuit->ReadPacket))(circuit);
		if (packet != NULL)
		{
			process(circuit, packet);
		}
	} while (packet != NULL);
}

static void SigTermHandler(int signum)
{
}

#endif
