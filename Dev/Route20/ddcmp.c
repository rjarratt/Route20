/* ddcmp.c: DDCMP protocol
  ------------------------------------------------------------------------------

   Copyright (c) 2013, Robert M. A. Jarratt
   CRC-16 code Mark Pizzolato

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

// TODO: implement partial buffers
// TODO: implement timers

#include <stdlib.h>
#include "ddcmp.h"

#define MAX_STATE_TABLE_ACTIONS 3

#define ENQ 5u
#define SOH 129u
#define DLE 144u

#define CONTROL_ACK   0x01
#define CONTROL_REP   0x03
#define CONTROL_STRT  0x06
#define CONTROL_STACK 0x07

typedef enum
{
	Undefined,
	UserRequestsHalt,
	UserRequestsStartup,
	ReceiveStack,
	ReceiveStrt,
	TimerExpires,
	ReceiveAckResp0,
	ReceiveDataResp0,
	ReceiveRepNumEqualsR
} DdcmpEvent;

typedef struct
{
	byte *data;
	int length;
	int position;
} buffer_t;

typedef struct
{
	DdcmpEvent evt;
	DdcmpLineState currentState;
	DdcmpLineState newState;
	void (*action[MAX_STATE_TABLE_ACTIONS])(ddcmp_line_t *line);
} state_table_entry_t;

static void InitialiseBuffer(buffer_t *buffer, byte *data, int length);
static void ResetBuffer(buffer_t *buffer);
static int BufferFromSegment(buffer_t *buffer, int length, buffer_t *newBuffer);
static int ExtendBuffer(buffer_t *originalBuffer, buffer_t *buffer, int length);
static byte CurrentByte(buffer_t *buffer);
static void MoveToNextByte(buffer_t *buffer);
static void AdvanceBufferPostion(buffer_t *buffer, int count);
static int BufferStillHasData(buffer_t *buffer);
static int RemainingBytesInBuffer(buffer_t *buffer);
static int CurrentBufferPosition(buffer_t *buffer);
static void SetBufferPosition(buffer_t *buffer, int position);

static uint16 Crc16(uint16 crc, buffer_t *buffer);
static int SynchronizeMessageFrame(buffer_t *buffer);
static int ExtractMessage(ddcmp_line_t *ddcmpLine, buffer_t *buffer, buffer_t *message);
static int SendMessage(ddcmp_line_t *ddcmpLine, byte *data, int length);
static void ProcessEvent(ddcmp_line_t *ddcmpLine, DdcmpEvent evt);
static void ProcessControlMessage(ddcmp_line_t *ddcmpLine, buffer_t *message);
static void ProcessStartMessage(ddcmp_line_t *ddcmpLine, buffer_t *message);
static void ProcessStackMessage(ddcmp_line_t *ddcmpLine, buffer_t *message);
static void ProcessAckMessage(ddcmp_line_t *ddcmpLine, buffer_t *message);
static void ProcessRepMessage(ddcmp_line_t *ddcmpLine, buffer_t *message);

static void StopTimerAction(ddcmp_line_t *ddcmpLine);
static void StartTimerAction(ddcmp_line_t *ddcmpLine);
static void SendStartAction(ddcmp_line_t *ddcmpLine);
static void SendAckResp0Action(ddcmp_line_t *ddcmpLine);
static void SendAckRespRAction(ddcmp_line_t *ddcmpLine);
static void SendStackAction(ddcmp_line_t *ddcmpLine);
static void ResetVariablesAction(ddcmp_line_t *ddcmpLine);
static void NotifyHaltAction(ddcmp_line_t *ddcmpLine);

static byte station = 1;

static char * lineStateString[] =
{
	"Any",
	"Halted",
	"IStrt",
	"AStrt",
	"Running"
};

static state_table_entry_t stateTable[] =
{
	{ UserRequestsHalt,     DdcmpLineAny,      DdcmpLineHalted,   { StopTimerAction} },

	{ UserRequestsStartup,  DdcmpLineHalted,   DdcmpLineIStrt,    { SendStartAction, ResetVariablesAction, StartTimerAction } },

	{ ReceiveStack,         DdcmpLineIStrt,    DdcmpLineRunning,  { SendAckResp0Action, StopTimerAction } },
	{ ReceiveStrt,          DdcmpLineIStrt,    DdcmpLineAStrt,    { SendStackAction, StartTimerAction } },
	{ TimerExpires,         DdcmpLineIStrt,    DdcmpLineIStrt,    { SendStartAction, StartTimerAction } },

	{ ReceiveAckResp0,      DdcmpLineAStrt,    DdcmpLineRunning,  { StopTimerAction /* TODO see Data Transfer */ } },
	{ ReceiveDataResp0,     DdcmpLineAStrt,    DdcmpLineRunning,  { StopTimerAction /* TODO see Data Transfer */ } },
	{ ReceiveStack,         DdcmpLineAStrt,    DdcmpLineRunning,  { SendAckResp0Action, StopTimerAction } },
	{ ReceiveStrt,          DdcmpLineAStrt,    DdcmpLineAStrt,    { SendStackAction, StartTimerAction } },
	{ TimerExpires,         DdcmpLineAStrt,    DdcmpLineAStrt,    { SendStackAction, StartTimerAction } },

	{ ReceiveStrt,          DdcmpLineRunning,  DdcmpLineHalted,   { SendStackAction, StartTimerAction, NotifyHaltAction } },
	{ ReceiveStack,         DdcmpLineRunning,  DdcmpLineRunning,  { SendAckRespRAction } },

	{ ReceiveRepNumEqualsR, DdcmpLineRunning,  DdcmpLineRunning,  { SendAckRespRAction } },
	{ UserRequestsHalt,     DdcmpLineRunning,  DdcmpLineHalted,   { StopTimerAction} },

	{ Undefined,            DdcmpLineAny,      DdcmpLineAny,      NULL }
};

/* crc16 polynomial x^16 + x^15 + x^2 + 1 (0xA001) CCITT LSB */
static uint16 crc16_nibble[16] = {
    0x0000, 0xCC01, 0xD801, 0x1400, 0xF001, 0x3C00, 0x2800, 0xE401,
    0xA001, 0x6C00, 0x7800, 0xB401, 0x5000, 0x9C01, 0x8801, 0x4400,
    };

void DdcmpStart(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->state = DdcmpLineHalted;
	ProcessEvent(ddcmpLine, UserRequestsStartup);
}

void DdcmpHalt(ddcmp_line_t *ddcmpLine)
{
	ProcessEvent(ddcmpLine, UserRequestsHalt);
}

int DdcmpProcessReceivedData(ddcmp_line_t *ddcmpLine, byte *data, int length, byte **payload, int *payloadLength)
{
	int ans = 0;
	buffer_t buffer;
	buffer_t message;

	*payload = NULL;
	*payloadLength = 0;

	InitialiseBuffer(&buffer, data, length);

	while(BufferStillHasData(&buffer))
	{
	    if (SynchronizeMessageFrame(&buffer))
		{
			if (ExtractMessage(ddcmpLine, &buffer, &message))
			{
				switch (CurrentByte(&message))
				{
				case ENQ:
					{
						ProcessControlMessage(ddcmpLine, &message);
						break;
					}

				case SOH:
				case DLE:
					{
						ddcmpLine->Log(LogVerbose, "Data message received, total length=%d\n", message.length);
						break;
					}

				default:
					{
						ddcmpLine->Log(LogWarning, "Unknown message category\n");
						break;
					}
				}
			}
		}
	}

	return ans;
}

static void InitialiseBuffer(buffer_t *buffer, byte *data, int length)
{
	buffer->data = data;
	buffer->length = length;
	buffer->position = 0;
}

static void ResetBuffer(buffer_t *buffer)
{
	buffer->position = 0;
}

static int BufferFromSegment(buffer_t *buffer, int length, buffer_t *newBuffer)
{
	int ans = 0;
	if (RemainingBytesInBuffer(buffer) >= length)
	{
		newBuffer->data = &buffer->data[buffer->position];
		newBuffer->length = length;
		newBuffer->position = 0;
		AdvanceBufferPostion(buffer, length);
		ans = 1;
	}

	return ans;
}

static int ExtendBuffer(buffer_t *originalBuffer, buffer_t *buffer, int length)
{
	int ans = 0;
	if (RemainingBytesInBuffer(originalBuffer) >= length)
	{
	    buffer->length += length;
		ans = 1;
	}

	return ans;
}

static byte CurrentByte(buffer_t *buffer)
{
	return buffer->data[buffer->position];
}

static void MoveToNextByte(buffer_t *buffer)
{
	buffer->position++;
}

static void AdvanceBufferPostion(buffer_t *buffer, int count)
{
	buffer->position += count;
}

static int BufferStillHasData(buffer_t *buffer)
{
	return RemainingBytesInBuffer(buffer) > 0;
}

static int RemainingBytesInBuffer(buffer_t *buffer)
{
	return buffer->length - buffer->position;
}

static int CurrentBufferPosition(buffer_t *buffer)
{
	return buffer->position;
}

static void SetBufferPosition(buffer_t *buffer, int position)
{
	buffer->position = position;
}

static uint16 Crc16(uint16 crc, buffer_t *buffer)
{
	int savePos = CurrentBufferPosition(buffer);

	while(BufferStillHasData(buffer)) {
		byte b = CurrentByte(buffer);
		crc = (crc>>4) ^ crc16_nibble[(b ^ crc) & 0xF];
		crc = (crc>>4) ^ crc16_nibble[(b>>4 ^ crc) & 0xF];
		MoveToNextByte(buffer);
	};

	SetBufferPosition(buffer, savePos);
	return crc;
}


static int SynchronizeMessageFrame(buffer_t *buffer)
{
	int ans = 0;

	while (BufferStillHasData(buffer))
	{
		byte next = CurrentByte(buffer);
		if (next == ENQ || next == SOH || next == DLE)
		{
			ans = 1;
		}

		if (ans)
		{
			break;
		}
		else
		{
			MoveToNextByte(buffer);
		}
	}

	return ans;
}

static int ExtractMessage(ddcmp_line_t *ddcmpLine, buffer_t *buffer, buffer_t *message)
{
	int ans = 0;
	switch (CurrentByte(buffer))
	{
	case ENQ:
		{
			if (BufferFromSegment(buffer, 8, message))
			{
				if (Crc16(0, message) == 0)
				{
					ans = 1;
				}
				else
				{
					ddcmpLine->Log(LogWarning, "CRC error on recieved message\n");
				}
			}
			break;
		}

	case SOH:
	case DLE:
		{
			int savePos = CurrentBufferPosition(buffer);
			if (BufferFromSegment(buffer, 8, message))
			{
				if (Crc16(0, message) == 0)
				{
					unsigned int count;
					MoveToNextByte(message);
					count = CurrentByte(message) & 0xFF;
					MoveToNextByte(message);
					count += (CurrentByte(message) & 0x3F) << 8;
					AdvanceBufferPostion(message, 6);

					if (ExtendBuffer(buffer, message, count + 2))
					{
						if (Crc16( 0, message) == 0)
						{
							ResetBuffer(message);
							ans = 1;
						}
						else
						{
							ddcmpLine->Log(LogWarning, "CRC error on recieved data block\n");
						}
					}
					else
					{
						SetBufferPosition(buffer, savePos);
					}
				}
				else
				{
					ddcmpLine->Log(LogWarning, "CRC error on recieved message header\n");
				}
			}
			break;
		}

	default:
		{
			ans = 0;
			break;
		}
	}


	return ans;
}

static int SendMessage(ddcmp_line_t *ddcmpLine, byte *data, int length)
{
	byte crc[2];
	uint16 crc16;
	buffer_t msgBuf;

	InitialiseBuffer(&msgBuf, data, length);
    crc16 = Crc16 (0, &msgBuf);
	crc[0] = crc16 & 0xFF;
	crc[1] = crc16 >> 8;
	ddcmpLine->SendData(ddcmpLine->context, data, length);
	ddcmpLine->SendData(ddcmpLine->context, crc, 2);

	return 1;
}

static void ProcessEvent(ddcmp_line_t *ddcmpLine, DdcmpEvent evt)
{
	state_table_entry_t *entry;
	int i = 0;
	int match;

	do
	{
		entry = &stateTable[i++];
		match = entry->evt == Undefined || (entry->evt == evt && (entry->currentState == ddcmpLine->state || entry->currentState == DdcmpLineAny));
	}
	while (!match);

	if (entry->evt != Undefined)
	{
		if (ddcmpLine->state != entry->newState)
		{
			ddcmpLine->Log(LogVerbose, "Changing line state from %s to %s\n", lineStateString[(int)ddcmpLine->state], lineStateString[(int)entry->newState]);
		}

		ddcmpLine->state = entry->newState;

		for (i = 0; i < MAX_STATE_TABLE_ACTIONS; i++)
		{
			if (entry->action[i] != NULL)
			{
				entry->action[i](ddcmpLine);
			}
		}
	}
}

static void ProcessControlMessage(ddcmp_line_t *ddcmpLine, buffer_t *message)
{
	byte msgType;
	MoveToNextByte(message);
	msgType = CurrentByte(message);
	MoveToNextByte(message);
	switch (msgType)
	{
	case CONTROL_ACK:
		{
			ProcessAckMessage(ddcmpLine, message);
			break;
		}
	case CONTROL_REP:
		{
			ProcessRepMessage(ddcmpLine, message);
			break;
		}
	case CONTROL_STRT:
		{
			ProcessStartMessage(ddcmpLine, message);
			break;
		}
	case CONTROL_STACK:
		{
			ProcessStackMessage(ddcmpLine, message);
			break;
		}
	default:
		{
			ddcmpLine->Log(LogWarning, "Unknown control message type %d\n", msgType);
			break;
		}
	}
}

static void ProcessStartMessage(ddcmp_line_t *ddcmpLine, buffer_t *message)
{
	// TODO: proper message validation
	byte subTypeAndFlags;
	byte stationAddress;

	subTypeAndFlags = CurrentByte(message);
	AdvanceBufferPostion(message, 2);
	stationAddress = CurrentByte(message);

	ddcmpLine->Log(LogVerbose, "STRT, subtype & flags %02X, Station address %02X\n", subTypeAndFlags, stationAddress);
	ProcessEvent(ddcmpLine, ReceiveStrt);
}

static void ProcessStackMessage(ddcmp_line_t *ddcmpLine, buffer_t *message)
{
	// TODO: proper message validation
	byte subTypeAndFlags;
	byte stationAddress;

	subTypeAndFlags = CurrentByte(message);
	AdvanceBufferPostion(message, 2);
	stationAddress = CurrentByte(message);

	ddcmpLine->Log(LogVerbose, "STACK, subtype & flags %02X, Station address %02X\n", subTypeAndFlags, stationAddress);
	ProcessEvent(ddcmpLine, ReceiveStack);
}

static void ProcessAckMessage(ddcmp_line_t *ddcmpLine, buffer_t *message)
{
	// TODO: proper message validation
	byte subTypeAndFlags;
	byte stationAddress;
	byte resp;

	subTypeAndFlags = CurrentByte(message);
	AdvanceBufferPostion(message, 1);
	resp = CurrentByte(message);
	AdvanceBufferPostion(message, 1);
	stationAddress = CurrentByte(message);

	ddcmpLine->Log(LogVerbose, "ACK, subtype & flags %02X, Resp=%d, Station address %02X\n", subTypeAndFlags, resp, stationAddress);
	if (resp == 0)
	{
	    ProcessEvent(ddcmpLine, ReceiveAckResp0);
	}
	else
	{
	    //ProcessEvent(ddcmpLine, ReceiveAckResp);
	}
}

static void ProcessRepMessage(ddcmp_line_t *ddcmpLine, buffer_t *message)
{
	// TODO: proper message validation
	byte subTypeAndFlags;
	byte stationAddress;
	byte num;

	subTypeAndFlags = CurrentByte(message);
	AdvanceBufferPostion(message, 2);
	num = CurrentByte(message);
	stationAddress = CurrentByte(message);

	ddcmpLine->Log(LogVerbose, "REP, subtype & flags %02X, Num=%d, Station address %02X\n", subTypeAndFlags, num, stationAddress);

	if (num == ddcmpLine->R)
	{
		ProcessEvent(ddcmpLine, ReceiveRepNumEqualsR);
	}
}

static void StopTimerAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Stop timer action\n");
}

static void StartTimerAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Start timer action\n");
}

static void SendStartAction(ddcmp_line_t *ddcmpLine)
{
	byte start[] = { 0x05, CONTROL_STRT, 0xC0, 0x00, 0x00, station };
	ddcmpLine->Log(LogVerbose, "Send start action\n");
	SendMessage(ddcmpLine, start, sizeof(start));
}

static void SendAckResp0Action(ddcmp_line_t *ddcmpLine)
{
	byte ack[] = { 0x05, CONTROL_ACK, 0x00, 0x00, 0x00, station };
	ddcmpLine->Log(LogVerbose, "Send ack (resp=0) action\n");
	SendMessage(ddcmpLine, ack, sizeof(ack));
}

static void SendAckRespRAction(ddcmp_line_t *ddcmpLine)
{
	byte ack[] = { 0x05, CONTROL_ACK, 0x00, ddcmpLine->R, 0x00, station };
	ddcmpLine->Log(LogVerbose, "Send ack (resp=R) action\n");
	SendMessage(ddcmpLine, ack, sizeof(ack));
}

static void SendStackAction(ddcmp_line_t *ddcmpLine)
{
	byte stack[] = { 0x05, CONTROL_STACK, 0xC0, 0x00, 0x00, station };
	ddcmpLine->Log(LogVerbose, "Send stack action\n");
	SendMessage(ddcmpLine, stack, sizeof(stack));
}

static void ResetVariablesAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Reset variables action\n");
	ddcmpLine->R = 0;
	ddcmpLine->N = 0;
	ddcmpLine->A = 0;
	ddcmpLine->T = 1;
	ddcmpLine->X = 0;
}

static void NotifyHaltAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Notify halt action\n");
	if (ddcmpLine->NotifyHalt != NULL)
	{
		ddcmpLine->NotifyHalt(ddcmpLine->context);
	}
}
