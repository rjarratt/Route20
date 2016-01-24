/* platform.h: Platform specific support
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

#include <stdarg.h>
#include "circuit.h"

#define MAX_EVENT_HANDLERS 32

#if defined(WIN32)
#define uint_ptr UINT_PTR
#elif defined(__VAX)
#include <strings.h>
#define uint_ptr unsigned int
int stricmp(char *str1, char *str2);
struct hostent *gethostbyname(const char *name);
double difftime(time_t time2, time_t time1);
size_t strftime(char *s, size_t smax, const char *fmt, const struct tm *tp);
int isdigit(char c);
typedef unsigned int u_int;
typedef unsigned short u_short;
typedef unsigned char u_char;
#else
#define uint_ptr unsigned int
#define stricmp strcasecmp
#endif

void VLog(LogSource source, LogLevel level, char *format, va_list argptr);
void ProcessEvents(circuit_t circuits[], int numCircuits, void (*process)(circuit_t *, packet_t *));
