/* logging.c: logging
  ------------------------------------------------------------------------------

   Copyright (c) 2013, Robert M. A. Jarratt

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
#include "logging.h"

int LoggingLevels[LogEndMarker];
int SysLogLocalFacilityNumber; // used on Unix flavours for the facility part
char* LogSourceName[LogEndMarker + 1];

int IsLoggable(LogSource source, LogLevel level)
{
    return level <= LoggingLevels[source];
}

void Log(LogSource source, LogLevel level, char *format, ...)
{
	va_list va;

	va_start(va, format);

	VLog(source, level, format, va);

	va_end(va);
}

void LogBytes(LogSource source, LogLevel level, byte *buffer, int length)
{
    int i;
    if (IsLoggable(source, level))
    {
        for (i = 0; i < length; i++)
        {
            if ((i % 16) == 0)
            {
                Log(source, level, "%02X", buffer[i]);
            }
            else if ((i % 16) == 15)
            {
                Log(source, level, " %02X\n", buffer[i]);
            }
            else
            {
                Log(source, level, " %02X", buffer[i]);
            }
        }

        if (length != 0 && (length % 16) != 0)
        {
            Log(source, level, "\n", buffer[i]);
        }
    }
}
