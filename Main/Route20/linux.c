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
        Log(LogError, "Failed to set SID");
        exit(EXIT_FAILURE);
    }
    
    /* Change the current working directory */
    if ((chdir("/")) < 0)
	{
        Log(LogError, "Failed to change directory to root");
        exit(EXIT_FAILURE);
    }
    
    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    Log(LogInfo, "Initialising");
	if (Initialise(configFileName))
	{
        Log(LogInfo, "Initialised");
        MainLoop();
	}

    Log(LogInfo, "Exited");
    exit(EXIT_SUCCESS);
}

void Log(LogLevel level, char *format, ...)
{
	va_list va;
	static char line[MAX_LOG_LINE_LEN];
	static int  currentLen = 0;
	static int onNewLine = 1;
	
	va_start(va, format);

	int sysLevel;
	switch (level)
	{
	case LogInfo:
		{
			sysLevel = LOG_INFO;
			break;
		}
	case LogError:
		{
			sysLevel = LOG_ERR;
			break;
		}
	default:
		{
			sysLevel = LOG_ERR;
			break;
		}
	}

	currentLen += vsprintf(&line[currentLen], format, va);
	onNewLine = line[currentLen-1] == '\n';

	if (onNewLine)
	{
	    syslog(sysLevel, "%s", line);
		currentLen = 0;
	}

	va_end(va);
}

int IsStopping()
{
	return 0;
}

void ProcessEvents(circuit_t circuits[], int numCircuits, void (*process)(circuit_t *, packet_t *))
{
	int i;
	int nfds = 0;
	fd_set handles;

	signal(SIGTERM, SigTermHandler);

	while(1)
	{
		struct timespec timeout;
		timeout.tv_sec = SecondsUntilNextDue();
		timeout.tv_nsec = 0;

		FD_ZERO(&handles);
		for(i = 1; i <= numCircuits; i++)
		{
			FD_SET(circuits[i].waitHandle, &handles);
			if (circuits[i].waitHandle > nfds)
			{
				nfds = circuits[i].waitHandle;
			}
		}

		if (DnsWaitHandle != -1)
		{
			FD_SET(DnsWaitHandle, &handles);
			if (DnsWaitHandle > nfds)
			{
				nfds = DnsWaitHandle;
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
			    Log(LogError, "pselect error: %d\n", errno);
			}
		}
		else
		{
			ProcessTimers();
			if (i > 0)
			{
				if (FD_ISSET(DnsWaitHandle, &handles))
				{
					DnsProcessResponse();
				}

				for( i = 1; i <= numCircuits; i++)
				{
					if (FD_ISSET(circuits[i].waitHandle, &handles))
					{
				        ProcessPackets(&circuits[i], process);
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
