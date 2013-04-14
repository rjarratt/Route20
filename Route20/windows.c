/* windows.c: Windows support
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

#if defined(WIN32)

#include <pcap.h>
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>

#include "constants.h"
#include "platform.h"
#include "timer.h"
#include "route20.h"
#include "nsp.h"
#include "netman.h"
#include "dns.h"

#pragma comment(lib, "advapi32.lib")

#define SVCNAME TEXT("DECnet 2.0 Router")

static VOID SvcInstall(void);
static VOID WINAPI SvcCtrlHandler( DWORD ); 
static VOID WINAPI SvcMain( DWORD, LPTSTR * ); 
static void OpenLog();
static void CloseLog();
static void LogWin32Error(char *format, DWORD err);
static void ProcessPackets(circuit_t circuits[], int numCircuits, void (*process)(circuit_t *, packet_t *));

static VOID ReportSvcStatus(DWORD, DWORD, DWORD );
static VOID SvcInit( DWORD, LPTSTR * ); 
static VOID SvcReportEvent( LPTSTR );

SERVICE_STATUS          gSvcStatus; 
SERVICE_STATUS_HANDLE   gSvcStatusHandle; 
HANDLE                  ghSvcStopEvent = NULL;
FILE                   *logFile;
SERVICE_TABLE_ENTRY DispatchTable[] = 
{ 
	{ SVCNAME, (LPSERVICE_MAIN_FUNCTION) SvcMain }, 
	{ NULL, NULL } 
}; 




void __cdecl _tmain(int argc, TCHAR *argv[]) 
{ 
	int err;

	// If command-line parameter is "install", install the service. 
	// Otherwise, the service is probably being started by the SCM.

	if( lstrcmpi( argv[1], TEXT("install")) == 0 )
	{
		SvcInstall();
		return;
	}

	/* This call returns when the service has stopped. 
	The process should simply terminate when the call returns.
	*/

	if (!StartServiceCtrlDispatcher(DispatchTable))
	{ 
		err = GetLastError();
		if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
		{
			logFile = stdout;
			__try
			{
				if (Initialise(CONFIG_FILE_NAME))
				{
					NspInitialise();
					NetManInitialise();
					MainLoop();
				}
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				Log(LogGeneral, LogFatal, "Exception: %d\n", GetExceptionCode());
			}
		}
		else if (!err)
		{ 
			SvcReportEvent(TEXT("StartServiceCtrlDispatcher")); 
		}
	}
} 

#pragma warning(disable : 4995)

void Log(LogSource source, LogLevel level, char *format, ...)
{
	int n;
	char buf[MAX_LOG_LINE_LEN];
	static int onNewLine = 1;

	time_t now;
	va_list va;

	va_start(va, format);

	if (level <= LoggingLevels[source])
	{
		if (onNewLine)
		{
			time(&now);
			strftime(buf, 80, "%Y-%m-%d %H:%M:%S ", localtime(&now));
			fprintf(logFile, buf);
		}

		n = vsprintf(buf, format, va);
		onNewLine = buf[n-1] == '\n';
		fprintf(logFile, buf);
		fflush(logFile);
	}

	va_end(va);
}

int IsStopping(void)
{
	return !WaitForSingleObject(ghSvcStopEvent, 0);
}

void ProcessEvents(circuit_t circuits[], int numCircuits, void (*process)(circuit_t *, packet_t *))
{
	int i;
	int handleCount = 0;
	HANDLE *handles = (HANDLE *)malloc((numCircuits + 2) * sizeof(HANDLE));
	//Log(LogInfo, "Process events %d\n", numCircuits);
	for(i = 1; i <= numCircuits; i++)
	{
		handles[i - 1] = (HANDLE)circuits[i].waitHandle;
		handleCount++;
    	Log(LogGeneral, LogVerbose, "Handle for %s (slot %d) is %u\n", circuits[i].name, circuits[i].slot, handles[i - 1]);
	}

	if (DnsWaitHandle != -1)
	{
	    handles[handleCount++] = (HANDLE)DnsWaitHandle;
	}

	if (ghSvcStopEvent != NULL)
	{
	    handles[handleCount++] = ghSvcStopEvent;
	}

	while(1)
	{
		int timeout = SecondsUntilNextDue(); /*INFINITE*/
		/*Log(LogInfo, "Waiting for events, timeout is %d\n", timeout);*/
		i = WaitForMultipleObjects(handleCount, handles, 0, timeout * 1000);
		if (i == -1)
		{
			DWORD err = GetLastError();
			LogWin32Error("WaitForMultipleObjects error: %s\n", err);
			break;
		}
		else
		{
			ProcessTimers();
			if (i != WAIT_TIMEOUT)
			{
				i = i - WAIT_OBJECT_0;
				ResetEvent(handles[i]);
				if (handles[i] == ghSvcStopEvent)
				{
					break;
				}
				else if (handles[i] == (HANDLE)DnsWaitHandle)
				{
					DnsProcessResponse();
				}
				else
				{
					ProcessPackets(circuits, numCircuits, process);
				}
			}
		}
	}
}

static void ProcessPackets(circuit_t circuits[], int numCircuits, void (*process)(circuit_t *, packet_t *))
{
	int i;
	int moreToRead;

	do
	{
		moreToRead = 0;
		for( i = 1; i <= numCircuits; i++)
		{
			packet_t *packet = (*(circuits[i].ReadPacket))(&circuits[i]);
			if (packet != NULL)
			{
				moreToRead = 1;
				process(&circuits[i], packet);
			}
			else
			{
				//Log(LogInfo, "NI %d - no packet\n", i);
			}
		}
	}
	while (moreToRead);
}

static VOID SvcInstall()
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	TCHAR szPath[MAX_PATH];

	if( !GetModuleFileName( NULL, szPath, MAX_PATH ) )
	{
		printf("Cannot install service (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager( 
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager) 
	{
		printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Create the service

	schService = CreateService( 
		schSCManager,              // SCM database 
		SVCNAME,                   // name of service 
		SVCNAME,                   // service name to display 
		SERVICE_ALL_ACCESS,        // desired access 
		SERVICE_WIN32_OWN_PROCESS, // service type 
		SERVICE_AUTO_START,        // start type 
		SERVICE_ERROR_NORMAL,      // error control type 
		szPath,                    // path to service's binary 
		NULL,                      // no load ordering group 
		NULL,                      // no tag identifier 
		NULL,                      // no dependencies 
		NULL,                      // LocalSystem account 
		NULL);                     // no password 

	if (schService == NULL) 
	{
		printf("CreateService failed (%d)\n", GetLastError()); 
		CloseServiceHandle(schSCManager);
		return;
	}
	else printf("Service installed successfully\n"); 

	CloseServiceHandle(schService); 
	CloseServiceHandle(schSCManager);
}

static VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR *lpszArgv )
{
	// Register the handler function for the service

	gSvcStatusHandle = RegisterServiceCtrlHandler( 
		SVCNAME, 
		SvcCtrlHandler);

	if( !gSvcStatusHandle )
	{ 
		SvcReportEvent(TEXT("RegisterServiceCtrlHandler")); 
		return; 
	} 

	// These SERVICE_STATUS members remain as set here

	gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
	gSvcStatus.dwServiceSpecificExitCode = 0;    

	// Report initial status to the SCM

	ReportSvcStatus( SERVICE_START_PENDING, NO_ERROR, 3000 );

	// Perform service-specific initialization and work.

	SvcInit( dwArgc, lpszArgv );
}

static void OpenLog()
{
	logFile = fopen("C:\\temp\\Route20.log", "w+");
}

static void CloseLog()
{
	fclose(logFile);
}

static void LogWin32Error(char *format, DWORD err)
{
	char buf[512];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, buf, sizeof(buf) - 1, NULL);
	Log(LogGeneral, LogError, format, buf);
}

static VOID SvcInit( DWORD dwArgc, LPTSTR *lpszArgv)
{
	// Create an event. The control handler function, SvcCtrlHandler,
	// signals this event when it receives the stop control code.

	ghSvcStopEvent = CreateEvent(
		NULL,    // default security attributes
		TRUE,    // manual reset event
		FALSE,   // not signaled
		NULL);   // no name

	if ( ghSvcStopEvent == NULL)
	{
		ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
		return;
	}

	// Report running status when initialization is complete.

	ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );

	OpenLog();
	__try
	{
		if (Initialise(CONFIG_FILE_NAME))
		{
			NspInitialise();
			NetManInitialise();
			MainLoop();
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		Log(LogGeneral, LogFatal, "Exception: %08X\n", GetExceptionCode());
	}

	CloseLog();

	ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
}

static VOID ReportSvcStatus( DWORD dwCurrentState,
	DWORD dwWin32ExitCode,
	DWORD dwWaitHint)
{
	static DWORD dwCheckPoint = 1;

	// Fill in the SERVICE_STATUS structure.

	gSvcStatus.dwCurrentState = dwCurrentState;
	gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
	gSvcStatus.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		gSvcStatus.dwControlsAccepted = 0;
	else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	if ( (dwCurrentState == SERVICE_RUNNING) ||
		(dwCurrentState == SERVICE_STOPPED) )
		gSvcStatus.dwCheckPoint = 0;
	else gSvcStatus.dwCheckPoint = dwCheckPoint++;

	// Report the status of the service to the SCM.
	SetServiceStatus( gSvcStatusHandle, &gSvcStatus );
}

static VOID WINAPI SvcCtrlHandler( DWORD dwCtrl )
{
	// Handle the requested control code. 

	switch(dwCtrl) 
	{  
	case SERVICE_CONTROL_STOP: 
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

		// Signal the service to stop.

		//Log(LogInfo, "Received stop request from service control manager\n");
		SetEvent(ghSvcStopEvent);
		ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);

		return;

	case SERVICE_CONTROL_INTERROGATE: 
		break; 

	default: 
		break;
	} 

}

static VOID SvcReportEvent(LPTSTR szFunction) 
{ 
	HANDLE hEventSource;
	LPCTSTR lpszStrings[2];
	TCHAR Buffer[80];
	DWORD lastError;

	lastError = GetLastError();

	hEventSource = RegisterEventSource(NULL, SVCNAME);

	if( NULL != hEventSource )
	{
		StringCchPrintf(Buffer, 80, TEXT("%s failed with %d"), szFunction, lastError);

		lpszStrings[0] = SVCNAME;
		lpszStrings[1] = Buffer;

		//ReportEvent(hEventSource,        // event log handle
		//            EVENTLOG_ERROR_TYPE, // event type
		//            0,                   // event category
		//            SVC_ERROR,           // event identifier
		//            NULL,                // no security identifier
		//            2,                   // size of lpszStrings array
		//            0,                   // no binary data
		//            lpszStrings,         // array of strings
		//            NULL);               // no binary data

		DeregisterEventSource(hEventSource);
	}
}

#endif