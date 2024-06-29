/* route20.h: DECnet Routing 2.0
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

#include "platform.h"
#include "logging.h"

#if !defined(ROUTE_H)

typedef enum
{
	ConfigReadModeInitial,
	ConfigReadModeFull,
	ConfigReadModeUpdate
}
ConfigReadMode;

typedef struct
{
	unsigned int waitHandle;
    char *name;
	void *context;
	void (*eventHandler)(void *context);

} event_handler_t;

extern event_handler_t eventHandlers[MAX_EVENT_HANDLERS];
extern int numEventHandlers;
extern int eventHandlersChanged;

void InitialiseLogging(void);
int ReadConfig(char *fileName, ConfigReadMode mode);
int InitialiseConfig(int (*ConfigReader)(char *fileName, ConfigReadMode mode), char *configFileName);
int DecnetInitialise(void);
void ProcessCircuitEvent(void *context);
void RoutingSetCallback(void (*callback)(decnet_address_t *from, byte *data, uint16 dataLength));
void RegisterEventHandler(unsigned int waitHandle, char *name, void *context, void (*eventHandler)(void *context));
void DeregisterEventHandler(unsigned int waitHandle);
void ProcessPacket(circuit_t *circuit, packet_t *packet);
void MainLoop(void);

#define ROUTE20_H
#endif