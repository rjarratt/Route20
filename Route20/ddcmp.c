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
// TODO: Implement SELECT for half-duplex
// TODO: Send NAK if CRC is wrong (2.5.3.1)

#include <stdlib.h>
#include "ddcmp.h"

#define MAX_STATE_TABLE_ACTIONS 6

#define ENQ 5u
#define SOH 129u
#define DLE 144u

#define CONTROL_ACK   0x01
#define CONTROL_NAK   0x02
#define CONTROL_REP   0x03
#define CONTROL_STRT  0x06
#define CONTROL_STACK 0x07

typedef enum
{
	Undefined,
	UserRequestsHalt,
	UserRequestsStartup,
	UserRequestsDataSendAndReadyToSend,
	ReceiveStack,
	ReceiveStrt,
	TimerExpires,
	ReceiveAckResp0,
	ReceiveDataResp0,
	ReceiveRepNumEqualsR,
	ReceiveRepNumNotEqualsR,
	ReceiveDataMsgInSequence,
	ReceiveDataMsgOutOfSequence,
	ReceiveAckForOutstandingMsg
} DdcmpEvent;

typedef enum
{
	DdcmpLineAny,
	DdcmpLineHalted,
	DdcmpLineIStrt,
	DdcmpLineAStrt,
	DdcmpLineRunning
} DdcmpLineState;

typedef enum
{
	NotSet,
	SACK,
	SNAK
} SendAckNakFlagState;

typedef struct
{
	byte *data;
	int length;
	int position;
} buffer_t;

typedef struct
{
	DdcmpLineState state;
	byte R;
	byte N;
	byte A;
	byte T;
	byte X;
	SendAckNakFlagState SACKNAK;
	int SREP;
	byte NAKReason;
	buffer_t currentMessage;
	void *replyTimerHandle;

	byte residualData[MAX_DDCMP_BUFFER_LENGTH]; /* unprocessed incomplete data from last processed buffer of data */
} ddcmp_line_control_block_t;

typedef struct
{
	DdcmpEvent evt;
	DdcmpLineState currentState;
	DdcmpLineState newState;
	int (*action[MAX_STATE_TABLE_ACTIONS])(ddcmp_line_t *line);
} state_table_entry_t;

#define LOGFLAGS(flags) flags & 2 ? "S" : "", flags & 1 ? "Q" : ""

static void InitialiseBuffer(buffer_t *buffer, byte *data, int length);
static void ResetBuffer(buffer_t *buffer);
static int BufferFromSegment(buffer_t *buffer, int length, buffer_t *newBuffer);
static int ExtendBuffer(buffer_t *originalBuffer, buffer_t *buffer, int length);
static byte CurrentByte(buffer_t *buffer);
static void MoveToNextByte(buffer_t *buffer);
static byte ByteAt(buffer_t *buffer, int position);
static void AdvanceBufferPostion(buffer_t *buffer, int count);
static int BufferStillHasData(buffer_t *buffer);
static int RemainingBytesInBuffer(buffer_t *buffer);
static int CurrentBufferPosition(buffer_t *buffer);
static void SetBufferPosition(buffer_t *buffer, int position);

static ddcmp_line_control_block_t *GetControlBlock(ddcmp_line_t *ddcmpLine);
static uint16 Crc16(uint16 crc, buffer_t *buffer);
static void DoIdle(ddcmp_line_t *ddcmpLine);
static int SynchronizeMessageFrame(ddcmp_line_t *ddcmpLine, buffer_t *buffer);
static int ExtractMessage(ddcmp_line_t *ddcmpLine, buffer_t *buffer);
static int SendMessage(ddcmp_line_t *ddcmpLine, byte *data, int length);
static void ReplyTimerHandler(void *timerContext);
static void StartTimer(ddcmp_line_t *ddcmpLine, int seconds);
static void StopTimer(ddcmp_line_t *ddcmpLine);
static void ProcessEvent(ddcmp_line_t *ddcmpLine, DdcmpEvent evt);
static void ProcessControlMessage(ddcmp_line_t *ddcmpLine);
static void ProcessDataMessage(ddcmp_line_t *ddcmpLine);
static void ProcessStartMessage(ddcmp_line_t *ddcmpLine);
static void ProcessStackMessage(ddcmp_line_t *ddcmpLine);
static void ProcessAckMessage(ddcmp_line_t *ddcmpLine);
static void ProcessRepMessage(ddcmp_line_t *ddcmpLine);
static unsigned int GetDataMessageCount(buffer_t *message);
static unsigned int GetMessageFlags(buffer_t *message);
static byte GetMessageNum(buffer_t *message);
static byte GetMessageResp(buffer_t *message);
static void SendAck(ddcmp_line_t *ddcmpLine);
static void SendNak(ddcmp_line_t *ddcmpLine);
static void SendRep(ddcmp_line_t *ddcmpLine);

static int StopTimerAction(ddcmp_line_t *ddcmpLine);
static int StartTimerAction(ddcmp_line_t *ddcmpLine);
static int SendStartAction(ddcmp_line_t *ddcmpLine);
static int SendAckAction(ddcmp_line_t *ddcmpLine);
static int SendStackAction(ddcmp_line_t *ddcmpLine);
static int ResetVariablesAction(ddcmp_line_t *ddcmpLine);
static int NotifyHaltAction(ddcmp_line_t *ddcmpLine);
static int SetSackAction(ddcmp_line_t *ddcmpLine);
static int SetSnakAction(ddcmp_line_t *ddcmpLine);
static int ClearSackSnakAction(ddcmp_line_t *ddcmpLine);
static int SetNakReason3Action(ddcmp_line_t *ddcmpLine);
static int SetReceivedSequenceNumberAction(ddcmp_line_t *ddcmpLine);
static int GiveMessageToUserAction(ddcmp_line_t *ddcmpLine);
static int SendNextMessageAction(ddcmp_line_t *ddcmpLine);
static int IncrementNAction(ddcmp_line_t *ddcmpLine);
static int IncrementTAction(ddcmp_line_t *ddcmpLine);
static int SetAVarAction(ddcmp_line_t *ddcmpLine);
static int SetTVarFromAckAction(ddcmp_line_t *ddcmpLine);
static int SetXVarFromMsgNumAction(ddcmp_line_t *ddcmpLine);
static int CheckAckWaitTimerAction(ddcmp_line_t *ddcmpLine);
static int SetSrepAction(ddcmp_line_t *ddcmpLine);

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
	{ UserRequestsHalt,                   DdcmpLineAny,      DdcmpLineHalted,   { StopTimerAction} },

	{ UserRequestsStartup,                DdcmpLineHalted,   DdcmpLineIStrt,    { SendStartAction, ResetVariablesAction, StartTimerAction } },

	{ ReceiveStack,                       DdcmpLineIStrt,    DdcmpLineRunning,  { SendAckAction, StopTimerAction } },
	{ ReceiveStrt,                        DdcmpLineIStrt,    DdcmpLineAStrt,    { SendStackAction, StartTimerAction } },
	{ TimerExpires,                       DdcmpLineIStrt,    DdcmpLineIStrt,    { SendStartAction, StartTimerAction } },

	{ ReceiveAckResp0,                    DdcmpLineAStrt,    DdcmpLineRunning,  { StopTimerAction } },
	{ ReceiveDataResp0, /*notused?*/      DdcmpLineAStrt,    DdcmpLineRunning,  { StopTimerAction } },
	{ ReceiveStack,                       DdcmpLineAStrt,    DdcmpLineRunning,  { SendAckAction, StopTimerAction } },
	{ ReceiveStrt,                        DdcmpLineAStrt,    DdcmpLineAStrt,    { SendStackAction, StartTimerAction } },
	{ TimerExpires,                       DdcmpLineAStrt,    DdcmpLineAStrt,    { SendStackAction, StartTimerAction } },

	{ ReceiveStrt,                        DdcmpLineRunning,  DdcmpLineHalted,   { SendStackAction, StartTimerAction, NotifyHaltAction } },
	{ ReceiveStack,                       DdcmpLineRunning,  DdcmpLineRunning,  { SendAckAction } },

	{ ReceiveRepNumEqualsR,               DdcmpLineRunning,  DdcmpLineRunning,  { SetSackAction } },
	{ ReceiveRepNumNotEqualsR,            DdcmpLineRunning,  DdcmpLineRunning,  { SetNakReason3Action, SetSnakAction } },
	{ UserRequestsHalt,                   DdcmpLineRunning,  DdcmpLineHalted,   { StopTimerAction} },
	{ ReceiveDataMsgInSequence,           DdcmpLineRunning,  DdcmpLineRunning,  { GiveMessageToUserAction, SetReceivedSequenceNumberAction, SetSackAction } },
	{ ReceiveDataMsgOutOfSequence,        DdcmpLineRunning,  DdcmpLineRunning,  { NULL } },
	{ ReceiveAckResp0,                    DdcmpLineRunning,  DdcmpLineRunning,  { SetAVarAction, SetTVarFromAckAction, CheckAckWaitTimerAction } },
	{ ReceiveAckForOutstandingMsg,        DdcmpLineRunning,  DdcmpLineRunning,  { SetAVarAction, SetTVarFromAckAction, CheckAckWaitTimerAction } },

	{ UserRequestsDataSendAndReadyToSend, DdcmpLineRunning,  DdcmpLineRunning,  { SendNextMessageAction, IncrementNAction, IncrementTAction, ClearSackSnakAction, SetXVarFromMsgNumAction, CheckAckWaitTimerAction } },
	{ TimerExpires,                       DdcmpLineRunning,  DdcmpLineRunning,  { SetSrepAction } },

	{ Undefined,                          DdcmpLineAny,      DdcmpLineAny,      NULL }
};

/* crc16 polynomial x^16 + x^15 + x^2 + 1 (0xA001) CCITT LSB */
static uint16 crc16_nibble[16] = {
    0x0000, 0xCC01, 0xD801, 0x1400, 0xF001, 0x3C00, 0x2800, 0xE401,
    0xA001, 0x6C00, 0x7800, 0xB401, 0x5000, 0x9C01, 0x8801, 0x4400,
    };

void DdcmpStart(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb;
	if (ddcmpLine->controlBlock == NULL)
	{
		ddcmpLine->controlBlock = (ddcmp_line_control_block_t *)calloc(1, sizeof(ddcmp_line_control_block_t));
	}

	cb = GetControlBlock(ddcmpLine);
	cb->state = DdcmpLineHalted;
	cb->SACKNAK = NotSet;
	ProcessEvent(ddcmpLine, UserRequestsStartup);
}

void DdcmpHalt(ddcmp_line_t *ddcmpLine)
{
	ProcessEvent(ddcmpLine, UserRequestsHalt);
}

void DdcmpProcessReceivedData(ddcmp_line_t *ddcmpLine, byte *data, int length)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	buffer_t buffer;

	InitialiseBuffer(&buffer, data, length);

	while(BufferStillHasData(&buffer))
	{
	    if (SynchronizeMessageFrame(ddcmpLine, &buffer))
		{
			if (ExtractMessage(ddcmpLine, &buffer))
			{
				switch (CurrentByte(&cb->currentMessage))
				{
				case ENQ:
					{
						ProcessControlMessage(ddcmpLine);
						break;
					}

				case SOH:
					{
						ProcessDataMessage(ddcmpLine);
						break;
					}
				case DLE:
					{
						ddcmpLine->Log(LogVerbose, "Data message received, total length=%d\n", cb->currentMessage.length);
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

	DoIdle(ddcmpLine);
}

int DdcmpSendDataMessage(ddcmp_line_t *ddcmpLine, byte *data, int length)
{
	int ans = 0;
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	if (cb->state == DdcmpLineRunning)
	{
		InitialiseBuffer(&cb->currentMessage, data, length);
		if (cb->T == cb->N + 1 && cb->SACKNAK != SNAK && !cb->SREP)
		{
			ProcessEvent(ddcmpLine, UserRequestsDataSendAndReadyToSend);
		}
		ans = 1;
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
		AdvanceBufferPostion(originalBuffer, length);
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

static byte ByteAt(buffer_t *buffer, int position)
{
	return buffer->data[position];
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

static ddcmp_line_control_block_t *GetControlBlock(ddcmp_line_t *ddcmpLine)
{
	return (ddcmp_line_control_block_t *)ddcmpLine->controlBlock;
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

static void DoIdle(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	if (cb->SACKNAK == SACK)
	{
		SendAck(ddcmpLine);
	}
	else if (cb->SACKNAK == SNAK)
	{
		SendNak(ddcmpLine);
	}

	if (cb->SREP)
	{
		SendRep(ddcmpLine);
	}
}

static int SynchronizeMessageFrame(ddcmp_line_t *ddcmpLine, buffer_t *buffer)
{
	int ans = 0;
	int skipCount = 0;

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
			skipCount++;
		}
	}

	if (skipCount > 0)
	{
		ddcmpLine->Log(LogVerbose, "Synch skipped %d bytes\n", skipCount);
	}

	return ans;
}

static int ExtractMessage(ddcmp_line_t *ddcmpLine, buffer_t *buffer)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int ans = 0;
	switch (CurrentByte(buffer))
	{
	case ENQ:
		{
			if (BufferFromSegment(buffer, 8, &cb->currentMessage))
			{
				if (Crc16(0, &cb->currentMessage) == 0)
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
			if (BufferFromSegment(buffer, 8, &cb->currentMessage))
			{
				if (Crc16(0, &cb->currentMessage) == 0)
				{
					unsigned int count = GetDataMessageCount(&cb->currentMessage);
					SetBufferPosition(&cb->currentMessage, 8);

					if (ExtendBuffer(buffer, &cb->currentMessage, count + 2))
					{
						if (Crc16( 0, &cb->currentMessage) == 0)
						{
							ResetBuffer(&cb->currentMessage);
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

static void ReplyTimerHandler(void *timerContext)
{
	ddcmp_line_t *ddcmpLine = (ddcmp_line_t *)timerContext;
	ProcessEvent(ddcmpLine, TimerExpires);
	DoIdle(ddcmpLine);
}

static void StartTimer(ddcmp_line_t *ddcmpLine, int seconds)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	if (cb->replyTimerHandle == NULL)
	{
		cb->replyTimerHandle = ddcmpLine->CreateOneShotTimer(ddcmpLine, "Reply timer", seconds, ReplyTimerHandler);
	}
}

static void StopTimer(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	if (cb->replyTimerHandle != NULL)
	{
		ddcmpLine->CancelOneShotTimer(cb->replyTimerHandle);
		cb->replyTimerHandle = NULL;
	}
}

static void ProcessEvent(ddcmp_line_t *ddcmpLine, DdcmpEvent evt)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	state_table_entry_t *entry;
	int i = 0;
	int match;

	do
	{
		entry = &stateTable[i++];
		match = entry->evt == Undefined || (entry->evt == evt && (entry->currentState == cb->state || entry->currentState == DdcmpLineAny));
	}
	while (!match);

	if (entry->evt != Undefined)
	{
		int ok = 1;
		if (cb->state != entry->newState)
		{
			ddcmpLine->Log(LogVerbose, "Changing line state from %s to %s\n", lineStateString[(int)cb->state], lineStateString[(int)entry->newState]);
		}

		cb->state = entry->newState;

		for (i = 0; i < MAX_STATE_TABLE_ACTIONS && ok; i++)
		{
			if (entry->action[i] != NULL)
			{
				ok = entry->action[i](ddcmpLine);
			}
		}
	}
}

static void ProcessControlMessage(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte msgType;
	MoveToNextByte(&cb->currentMessage);
	msgType = CurrentByte(&cb->currentMessage);
	MoveToNextByte(&cb->currentMessage);
	switch (msgType)
	{
	case CONTROL_ACK:
		{
			ProcessAckMessage(ddcmpLine);
			break;
		}
	case CONTROL_REP:
		{
			ProcessRepMessage(ddcmpLine);
			break;
		}
	case CONTROL_STRT:
		{
			ProcessStartMessage(ddcmpLine);
			break;
		}
	case CONTROL_STACK:
		{
			ProcessStackMessage(ddcmpLine);
			break;
		}
	default:
		{
			ddcmpLine->Log(LogWarning, "Unknown control message type %d\n", msgType);
			break;
		}
	}
}

static void ProcessDataMessage(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	unsigned int count;
	int flags;
	int resp;
	byte num;
	int addr;
	count = GetDataMessageCount(&cb->currentMessage);
	flags = GetMessageFlags(&cb->currentMessage);
	resp = GetMessageResp(&cb->currentMessage);
	num = GetMessageNum(&cb->currentMessage);
	addr = ByteAt(&cb->currentMessage, 5);
	ddcmpLine->Log(LogInfo, "Received DATA message. Len=%d, Flags=%s%s, R=%d, N=%d, A=%d\n", count, LOGFLAGS(flags), resp, num, addr);

	if (cb->A < resp && resp <= cb->N)
	{
		ProcessEvent(ddcmpLine, ReceiveAckForOutstandingMsg);
	}

	if (num == cb->R + 1)
	{
		ProcessEvent(ddcmpLine, ReceiveDataMsgInSequence);
	}
	else
	{
		ProcessEvent(ddcmpLine, ReceiveDataMsgOutOfSequence);
	}
}

static void ProcessStartMessage(ddcmp_line_t *ddcmpLine)
{
	// TODO: proper message validation
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int flags;
	int addr;

	flags = GetMessageFlags(&cb->currentMessage);
	addr = ByteAt(&cb->currentMessage, 5);

	ddcmpLine->Log(LogInfo, "Received STRT message. Flags=%s%s, A=%d\n", LOGFLAGS(flags), addr);
	ProcessEvent(ddcmpLine, ReceiveStrt);
}

static void ProcessStackMessage(ddcmp_line_t *ddcmpLine)
{
	// TODO: proper message validation
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int flags;
	int addr;

	flags = GetMessageFlags(&cb->currentMessage);
	addr = ByteAt(&cb->currentMessage, 5);

	ddcmpLine->Log(LogInfo, "Received STACK message. Flags=%s%s, A=%d\n", LOGFLAGS(flags), addr);
	ProcessEvent(ddcmpLine, ReceiveStack);
}

static void ProcessAckMessage(ddcmp_line_t *ddcmpLine)
{
	// TODO: proper message validation
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int flags;
	int addr;
	int resp;

	flags = GetMessageFlags(&cb->currentMessage);
	resp = GetMessageResp(&cb->currentMessage);
	addr = ByteAt(&cb->currentMessage, 5);

	ddcmpLine->Log(LogInfo, "Received ACK message. Flags=%s%s, R=%d, A=%d\n", LOGFLAGS(flags), resp, addr);
	if (resp == 0)
	{
	    ProcessEvent(ddcmpLine, ReceiveAckResp0);
	}
	else if (cb->A < resp && resp <= cb->N)
	{
	    ProcessEvent(ddcmpLine, ReceiveAckForOutstandingMsg);
	}
}

static void ProcessRepMessage(ddcmp_line_t *ddcmpLine)
{
	// TODO: proper message validation
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int flags;
	int addr;
	int num;

	flags = GetMessageFlags(&cb->currentMessage);
	num = GetMessageNum(&cb->currentMessage);
	addr = ByteAt(&cb->currentMessage, 5);

	ddcmpLine->Log(LogInfo, "Received REP message. Flags=%s%s, N=%d, A=%d\n", LOGFLAGS(flags), num, addr);

	if (num == cb->R)
	{
		ProcessEvent(ddcmpLine, ReceiveRepNumEqualsR);
	}
	else
	{
		ProcessEvent(ddcmpLine, ReceiveRepNumNotEqualsR);
	}
}

static unsigned int GetDataMessageCount(buffer_t *message)
{
	unsigned int count;

    count = ByteAt(message, 1) & 0xFF;
	count += (ByteAt(message,2) & 0x3F) << 8;

	return count;
}

static unsigned int GetMessageFlags(buffer_t *message)
{
	return (ByteAt(message, 2) >> 6) & 3;
}

static byte GetMessageNum(buffer_t *message)
{
	return ByteAt(message, 4);
}

static byte GetMessageResp(buffer_t *message)
{
	return ByteAt(message, 3);
}

static void SendAck(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte ack[] = { 0x05, CONTROL_ACK, 0x00, 0x00, 0x00, 0x00 };
	ack[3] = cb->R;
	ack[5] = station;
	ddcmpLine->Log(LogInfo, "Sending ACK. Num=%d\n", cb->R);
	SendMessage(ddcmpLine, ack, sizeof(ack));
	cb->SACKNAK = NotSet;
}

static void SendNak(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte nak[] = { ENQ, CONTROL_NAK, 0x00, 0x00, 0x00, 0x00 };
	nak[2] = cb->NAKReason;
	nak[3] = cb->R;
	nak[5] = station;
	ddcmpLine->Log(LogInfo, "Sending NAK. Num=%d, Reason=%d\n", cb->R, cb->NAKReason);
	SendMessage(ddcmpLine, nak, sizeof(nak));
	cb->SACKNAK = NotSet;
}

static void SendRep(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte rep[] = { ENQ, CONTROL_REP, 0x00, 0x00, 0x00, 0x00 };
	rep[4] = cb->N;
	rep[5] = station;
	ddcmpLine->Log(LogInfo, "Sending REP. Num=%d\n", cb->N);
	SendMessage(ddcmpLine, rep, sizeof(rep));
	cb->SREP = 0;
	StartTimer(ddcmpLine, 15);
}

static int StopTimerAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Stop timer action\n");
	StopTimer(ddcmpLine);
	return 1;
}

static int StartTimerAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Start timer action\n");
	StartTimer(ddcmpLine, 3);
	return 1;
}

static int SendStartAction(ddcmp_line_t *ddcmpLine)
{
	byte start[] = { ENQ, CONTROL_STRT, 0xC0, 0x00, 0x00, 0x00 };
	start[5] = station;
	ddcmpLine->Log(LogVerbose, "Send start action\n");
	ddcmpLine->Log(LogInfo, "Sending STRT. A=%d\n", station);
	SendMessage(ddcmpLine, start, sizeof(start));
	return 1;
}

static int SendAckAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Send ack action\n");
	SendAck(ddcmpLine);
	return 1;
}

static int SendStackAction(ddcmp_line_t *ddcmpLine)
{
	byte stack[] = { ENQ, CONTROL_STACK, 0xC0, 0x00, 0x00, 0x00 };
	stack[5] = station;
	ddcmpLine->Log(LogVerbose, "Send stack action\n");
	ddcmpLine->Log(LogInfo, "Sending STACK. A=%d\n", station);
	SendMessage(ddcmpLine, stack, sizeof(stack));
	return 1;
}

static int ResetVariablesAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Reset variables action\n");
	cb->R = 0;
	cb->N = 0;
	cb->A = 0;
	cb->T = 1;
	cb->X = 0;
	return 1;
}

static int NotifyHaltAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Notify halt action\n");
	if (ddcmpLine->NotifyHalt != NULL)
	{
		ddcmpLine->NotifyHalt(ddcmpLine->context);
	}

	return 1;
}

static int SetSackAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set SACK action\n");
	cb->SACKNAK = SACK;
	return 1;
}

static int SetSnakAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set SNAK action\n");
	cb->SACKNAK = SNAK;
	return 1;
}

static int ClearSackSnakAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Clear SACK/SNAK action\n");
	cb->SACKNAK = NotSet;
	return 1;
}

static int SetNakReason3Action(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set NAK reason 3 action\n");
	cb->NAKReason = 3;
	return 1;
}

static int SetReceivedSequenceNumberAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set received sequence number action\n");
	cb->R = cb->R + 1;
	return 1;
}

static int GiveMessageToUserAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int ans = 1;
	ddcmpLine->Log(LogVerbose, "Give message to user action\n");
	if (!ddcmpLine->NotifyDataMessage(ddcmpLine->context, &cb->currentMessage.data[8], GetDataMessageCount(&cb->currentMessage)))
	{
		cb->NAKReason = 8;
		cb->SACKNAK = SNAK;
		ans = 0;
	}

	return ans;
}

static int SendNextMessageAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte hdr[6];
	ddcmpLine->Log(LogVerbose, "Send next message action\n");
	ddcmpLine->Log(LogInfo, "Sending Data. N=%d, R=%d\n", cb->N +1, cb->R);
	hdr[0] = SOH;
	hdr[1] = cb->currentMessage.length & 0xFF;
	hdr[2] = (cb->currentMessage.length >> 8) & 0x3F;
	hdr[3] = cb->R;
	hdr[4] = cb->N + 1;
	hdr[5] = station;
	SendMessage(ddcmpLine, hdr, sizeof(hdr));
	SendMessage(ddcmpLine, cb->currentMessage.data, cb->currentMessage.length);
	return 1;
}

static int IncrementNAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Increment N action\n");
	cb->N = cb->N + 1;
	return 1;
}

static int IncrementTAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Increment T action\n");
	cb->T = cb->N + 1;
	return 1;
}

static int SetAVarAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set A variable action\n");
	cb->A = GetMessageResp(&cb->currentMessage);
	return 1;
}

static int SetTVarFromAckAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set T variable from ack action\n");
	if (cb->T <= cb->A)
	{
		cb->T = cb-> A + 1;
	}

	return 1;
}

static int SetXVarFromMsgNumAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set T variable from ack action\n");
	cb->X = GetMessageNum(&cb->currentMessage);
	return 1;
}

static int CheckAckWaitTimerAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Check ack wait timer action\n");
	if (cb->A < cb->X)
	{
		StartTimer(ddcmpLine, 15);
	}
	else
	{
		StopTimer(ddcmpLine);
	}

	return 1;
}

static int SetSrepAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set Srep action\n");
	cb->SREP = 1;
	return 1;
}