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

#pragma warning( push, 3 )
#include <pcap.h>
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <DbgHelp.h>
#pragma warning( pop )
#pragma warning( disable : 4710 )

#include "platform.h"
#include "constants.h"
#include "timer.h"
#include "route20.h"
#include "nsp.h"
#include "netman.h"
#include "dns.h"
#include "socket.h"

#pragma comment(lib, "advapi32.lib")

#define SVCNAME TEXT("DECnet 2.0 Router")

static VOID SvcInstall(void);
static VOID WINAPI SvcCtrlHandler( DWORD ); 
static VOID WINAPI SvcMain( DWORD, LPTSTR * ); 
static void OpenLog(void);
static void CloseLog(void);
static void LogWin32Error(char *format, DWORD err);
static void ProcessStopEvent(void *context);
static void ProcessPackets(circuit_t circuits[], int numCircuits, void (*process)(circuit_t *, packet_t *));
static BOOL WINAPI StopSignalHandler(DWORD controlType);
static void SetupConfigWatcher(void);
static void ConfigWatchHandler(void *context);

static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS* pExp, DWORD dwExpCode);
static void LogCallStack(CONTEXT *context, HANDLE thread, unsigned long code);

static VOID ReportSvcStatus(DWORD, DWORD, DWORD );
static VOID SvcInit( DWORD, LPTSTR * ); 
static VOID SvcReportEvent( LPTSTR );

volatile int stop = 0;
SERVICE_STATUS          gSvcStatus; 
SERVICE_STATUS_HANDLE   gSvcStatusHandle; 
HANDLE                  ghSvcStopEvent = NULL;
FILE                   *logFile;
int                     runningAsService = 1;
SERVICE_TABLE_ENTRY DispatchTable[] = 
{ 
	{ SVCNAME, (LPSERVICE_MAIN_FUNCTION) SvcMain }, 
	{ NULL, NULL } 
}; 

void __cdecl _tmain(int argc, TCHAR *argv[]) 
{ 
	int err;

    OpenLog();
    InitialiseLogging();
    ReadConfig(CONFIG_FILE_NAME, ConfigReadModeInitial);
	SetupConfigWatcher();
	SymSetOptions(SYMOPT_LOAD_LINES);

	// If command-line parameter is "install", install the service. 
	// Otherwise, the service is probably being started by the SCM.

	if( lstrcmpi( argv[1], TEXT("install")) == 0 )
	{
		SvcInstall();
		return;
	}

	// Create an event that is used to stop processing. The control handler function, SvcCtrlHandler,
	// signals this event when it receives the stop control code. In console mode it is signalled when
	// CTRL-C or CTRL-BREAK is pressed.

    ghSvcStopEvent = CreateEvent(
		NULL,    // default security attributes
		TRUE,    // manual reset event
		FALSE,   // not signaled
		NULL);   // no name

	RegisterEventHandler((unsigned int)ghSvcStopEvent, "Stop event", NULL, ProcessStopEvent);

	/* This call returns when the service has stopped. 
	The process should simply terminate when the call returns.
	*/

    Log(LogGeneral, LogVerbose, "Starting service control dispatcher\n");

	if (!StartServiceCtrlDispatcher(DispatchTable))
	{ 
        Log(LogGeneral, LogVerbose, "Failed to start service control dispatcher\n");

		err = GetLastError();
		if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
		{
			SetConsoleCtrlHandler(StopSignalHandler, TRUE);
            runningAsService = 0;
            /* Disable exception handlers in debug builds so that debugger can break at the exception location. */
#if !defined(_DEBUG)
			__try
			{
#endif
				if (Initialise(ReadConfig, CONFIG_FILE_NAME))
				{
					NspInitialise();
					NetManInitialise();
					MainLoop();
				}
#if !defined(_DEBUG)
			}
			__except(ExceptionFilter(GetExceptionInformation(), GetExceptionCode()))
			{
			}
#endif
		}
		else if (!err)
		{ 
			SvcReportEvent(TEXT("StartServiceCtrlDispatcher")); 
		}
	}
    else
    {
        Log(LogGeneral, LogVerbose, "Service control dispatcher has terminated\n");
    }
    
    CloseLog();
} 

LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS* pExp, DWORD dwExpCode)
{
	Log(LogGeneral, LogFatal, "Exception: %d\n", dwExpCode);
	LogCallStack(pExp->ContextRecord, GetCurrentThread(), dwExpCode);
	return EXCEPTION_EXECUTE_HANDLER;
}

#define MAX_CALL_STACK_DEPTH 1

void LogCallStack(CONTEXT *context, HANDLE thread, unsigned long code)
{
	DWORD64 addresses[MAX_CALL_STACK_DEPTH];
	int numAddresses;
	STACKFRAME64 stackFrame;
	HANDLE processHandle;
	int i;

	// Useful links:
	// http://stackoverflow.com/questions/9424568/c-stack-tracing-issue
	// http://www.codeproject.com/Articles/11132/Walking-the-callstack
	// http://www.codeproject.com/Articles/41923/Get-the-call-stack-when-an-exception-is-being-caug  (get line number)

	stackFrame.AddrPC.Offset = context->Eip;
	stackFrame.AddrPC.Mode = AddrModeFlat;
	stackFrame.AddrFrame.Offset = context->Ebp;
	stackFrame.AddrFrame.Mode = AddrModeFlat;
	stackFrame.AddrStack.Offset = context->Esp;
    stackFrame.AddrStack.Mode = AddrModeFlat;

	Log(LogGeneral, LogFatal, "EIP. %08x\n", context->Eip);
	Log(LogGeneral, LogFatal, "EBP. %08x\n", context->Ebp);
	Log(LogGeneral, LogFatal, "ESP. %08x\n", context->Esp);

	processHandle = GetCurrentProcess();
	
	SymInitialize(processHandle, NULL, TRUE);

	Log(LogGeneral, LogFatal, "Start of call stack==================================\n");

	numAddresses = 0;
	do
	{
		addresses[numAddresses++] = stackFrame.AddrPC.Offset;
		if (numAddresses >= MAX_CALL_STACK_DEPTH) break;
	}
	while(StackWalk64(IMAGE_FILE_MACHINE_I386, processHandle, thread, &stackFrame, context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL));

	for (i = 0; i < numAddresses; i++)
	{
		SYMBOL_INFO_PACKAGE symbol;
		IMAGEHLP_LINE64 line;
		DWORD displacement;

		symbol.si.SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol.si.MaxNameLen = MAX_SYM_NAME;

		line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

		if (SymFromAddr(processHandle, addresses[i], 0, &symbol.si))
		{
		    Log(LogGeneral, LogFatal, "Stack walk. 0x%08llx %s", stackFrame.AddrPC.Offset, symbol.si.Name);
			if (SymGetLineFromAddr64(processHandle, addresses[i], &displacement, &line))
			{
		        Log(LogGeneral, LogFatal, " %s(line %d)\n", line.FileName, line.LineNumber);
			}
			else
			{
                DWORD error = GetLastError();
		        Log(LogGeneral, LogFatal, " line error %08x\n", error);
			}
		}
		else
		{
		    Log(LogGeneral, LogFatal, "Stack walk. 0x%08llx symbol information not available.\n", stackFrame.AddrPC.Offset);
		}

	}

	Log(LogGeneral, LogFatal, "End of call stack=====================================\n");
}

#pragma warning(disable : 4995)

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
            if (!runningAsService)
            {
                printf(buf);
                printf(" ");
            }

            fprintf(logFile, "%s\t", LogSourceName[source]);
            if (!runningAsService) printf("%s ", LogSourceName[source]);
		}

		n = vsprintf(buf, format, argptr);
		onNewLine = buf[n-1] == '\n';
		fprintf(logFile, buf);
        if (!runningAsService) printf(buf);
		fflush(logFile);
	}
}

void ProcessEvents(circuit_t circuits[], int numCircuits, void (*process)(circuit_t *, packet_t *))
{
	int i;
	HANDLE handles[MAXIMUM_WAIT_OBJECTS];
	//Log(LogInfo, "Process events %d\n", numCircuits);

	while (!stop)
	{
		int timeout;

		if (eventHandlersChanged)
		{
            Log(LogGeneral, LogVerbose, "Refreshing event handles to wait for after a change in event handlers, there are now %d event handlers\n", numEventHandlers);
			for (i = 0; i < numEventHandlers; i++)
			{
				handles[i] = (HANDLE)eventHandlers[i].waitHandle;
 			}

			eventHandlersChanged = 0;
		}

		timeout = SecondsUntilNextDue();
		Log(LogGeneral, LogVerbose, "Waiting for %d events, timeout is %d\n", numEventHandlers, timeout);
		i = WaitForMultipleObjects(numEventHandlers, handles, 0, timeout * 1000);
		if (i == -1)
		{
			DWORD err = GetLastError();
			LogWin32Error("WaitForMultipleObjects error: %s. Handle list follows.\n", err);
			for (i = 0; i < numEventHandlers; i++)
			{
                Log(LogGeneral, LogError, "Wait handle %d\n", handles[i]);
			}
			break;
		}
		else
		{
    	    Log(LogGeneral, LogVerbose, "Wait return is %d, processing timers\n", i);
			ProcessTimers();
            Log(LogGeneral, LogVerbose, "Finished processing timers\n");
			if (i != WAIT_TIMEOUT)
			{
				i = i - WAIT_OBJECT_0;
				ResetEvent((HANDLE)eventHandlers[i].waitHandle);
                Log(LogGeneral, LogDetail, "Processing event handler for %s\n", eventHandlers[i].name);
				eventHandlers[i].eventHandler(eventHandlers[i].context);
			}
		}
	}
}

static BOOL WINAPI StopSignalHandler(DWORD controlType)
{
	Log(LogGeneral, LogInfo, "Stop signal received\n");
	SetEvent(ghSvcStopEvent);
	return TRUE;
}

static void SetupConfigWatcher(void)
{
	TCHAR path[MAX_PATH + 1];
	unsigned int watchHandle;
	GetCurrentDirectory(MAX_PATH + 1, path);
	watchHandle = (unsigned int)FindFirstChangeNotification(path, FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE);
	RegisterEventHandler(watchHandle, "FileWatcher", (void *)watchHandle, ConfigWatchHandler);
}

static void ConfigWatchHandler(void *context)
{
	FindNextChangeNotification((HANDLE)context);
	/* ought to check if the actual config file has changed, the notify just means any file in the current directory has changed */
    ReadConfig(CONFIG_FILE_NAME, ConfigReadModeUpdate);
}

static VOID SvcInstall(void)
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

static void OpenLog(void)
{
	logFile = fopen("C:\\temp\\Route20.log", "w+");
}

static void CloseLog(void)
{
	fclose(logFile);
}

static void LogWin32Error(char *format, DWORD err)
{
	char buf[512];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, buf, sizeof(buf) - 1, NULL);
	Log(LogGeneral, LogError, format, buf);
}

static void ProcessStopEvent(void *context)
{
	Log(LogGeneral, LogDetail, "Processing stop request\n");
	stop = 1;
}

static VOID SvcInit( DWORD dwArgc, LPTSTR *lpszArgv)
{
	if ( ghSvcStopEvent == NULL)
	{
		ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
		return;
	}

	// Report running status when initialization is complete.

	ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );

    /* Disable exception handlers in debug builds so that debugger can break at the exception location. */
#if !defined(_DEBUG)
	__try
	{
#endif
		if (Initialise(ReadConfig, CONFIG_FILE_NAME))
		{
			NspInitialise();
			NetManInitialise();
			MainLoop();
		}
#if !defined(_DEBUG)
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		Log(LogGeneral, LogFatal, "Exception: %08X\n", GetExceptionCode());
	}
#endif

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

		Log(LogGeneral, LogVerbose, "Received stop request from service control manager\n");
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