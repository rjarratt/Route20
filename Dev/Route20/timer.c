/* timer.c: Timer facilities
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

#include <stdlib.h>
#include <limits.h>
#include "timer.h"
#include "platform.h"

// TODO: change implementation so that changes in the system clock do not affect operation.

static rtimer_t *timerList = NULL;

rtimer_t *CreateTimer(char *name, time_t due, int interval, void *context, void (*callback)(rtimer_t *, char *,void *))
{
	rtimer_t *newTimer = (rtimer_t *)malloc(sizeof(rtimer_t));

	newTimer->name = name;
	newTimer->due = due;
	newTimer->interval = (interval <= 0) ? 0 : interval;
	newTimer->context = context;
	newTimer->callback = callback;
	newTimer->next = timerList;
	timerList = newTimer;

	return newTimer;
}

void StopTimer(rtimer_t *timer)
{
	timer->interval = -1;
	timer->due = 0;
}

void StopAllTimers(void)
{
	rtimer_t *timer = timerList;
	while (timer != NULL)
	{
		StopTimer(timer);
		timer = timer->next;
	}

	ProcessTimers();
}

void ProcessTimers(void)
{
	rtimer_t *timer = timerList;
	rtimer_t *prevTimer;
	rtimer_t *nextTimer;
	time_t now;
	int deleted;

	prevTimer = NULL;
	time(&now);
	while (timer != NULL)
	{
		deleted = 0;
		nextTimer = timer->next;
		if (timer->due <= now)
		{
			if (timer->interval >= 0)
			{
				timer->callback(timer, timer->name, timer->context);
			}

			/* the callback may have added more timers to the head of the list, if so, adjust prevTimer if we were at the head list before the callback */
			if (prevTimer == NULL && timerList != timer)
			{
				prevTimer = timerList;
				while(prevTimer->next != timer)
				{
					prevTimer = prevTimer->next;
				}
			}

			if (timer->interval > 0)
			{
				timer->due += timer->interval;
			}
			else
			{
				if (prevTimer == NULL)
				{
					timerList = nextTimer;
				}
				else
				{
					prevTimer->next = nextTimer;
				}

				free(timer);
				deleted = 1;
			}
		}

		if (!deleted)
		{
			prevTimer = timer;
		}

		timer = nextTimer;
	}
}

int  SecondsUntilNextDue(void)
{
	int ans = 0;
	rtimer_t *timer = timerList;
	time_t now;
	time_t minDue = LONG_MAX;

	if (timerList != NULL)
	{
		time(&now);
		while (timer != NULL)
		{
			if (difftime(minDue, timer->due) > 0)
			{
				minDue = timer->due;
			}

			timer = timer->next;
		}

		if (minDue < now)
		{
			ans = 0;
		}
		else
		{
			ans = (int)(minDue - now);
		}
	}
	else
	{
		ans = -1; /* INFINITE on Windows */
	}

	return ans;
}
