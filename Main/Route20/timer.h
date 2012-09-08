/* timer.h: Timer facilities
  ------------------------------------------------------------------------------

   Copyright (c) 2012, Robert M. A. Jarratt
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

#include <time.h>

typedef struct rtimer *timer_ptr;

typedef struct rtimer
{
	char *name;
	time_t due;
	int interval; /* seconds, =0 if one-shot, =-1 if stopped */
	void *context;
	void (*callback)(struct rtimer *, char *, void *);
	timer_ptr next;
} rtimer_t;

rtimer_t *CreateTimer(char *name, time_t due, int interval, void *context, void (*callback)(rtimer_t *, char *,void *));
void StopTimer(rtimer_t *);
void StopAllTimers(void);
void ProcessTimers(void);
int  SecondsUntilNextDue(void);