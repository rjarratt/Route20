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

// TODO: Make sure buffers cannot overflow if receive malformed message (test with a buffer size that is too small).
// TODO: Implement SELECT for half-duplex
// TODO: perhaps remove position stuff from buffer.

#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "ddcmp.h"

#define MAX_STATE_TABLE_ACTIONS 6
#define MAX_TRANSMIT_QUEUE_LEN 5

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
	ReceiveAckForOutstandingMsg,
	ReceiveNakForOutstandingMsg,
	ReadyToRetransmitMsg,
	ReceiveMaintenanceMessage
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

typedef enum
{
	Incomplete,
	CompleteBad,
	CompleteGood
} ExtractBufferResult;

typedef struct
{
	byte *data;
	int length;
	int position;
} buffer_t;

#pragma pack(push)
#pragma pack(1)

typedef struct transmit_queue_entry
{
	struct transmit_queue_entry *next;
	int                          slotNumber;
	buffer_t                     buffer;
	int                          slotInUse;
	byte                         header[8];
	byte                         data[MAX_DDCMP_DATA_LENGTH];
} transmit_queue_entry_t;

typedef struct
{
	transmit_queue_entry_t transmitQueue[MAX_TRANSMIT_QUEUE_LEN];
	transmit_queue_entry_t *firstUnacknowledgedTransmitQueueEntry; /* transmit queue entry for the first transmit unacknowledged queue entry that needs to be transmitted */
	transmit_queue_entry_t *currentTransmitQueueEntry; /* transmit queue entry for the current transmit queue entry that needs to be transmitted */
	transmit_queue_entry_t *lastAllocatedTransmitQueueEntry; /* last transmit queue entry that was allocated */
} transmit_queue_ctrl_t;

#pragma pack(pop)

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
	buffer_t *currentMessage;
	void *replyTimerHandle;
	byte partialBufferData[MAX_DDCMP_BUFFER_LENGTH];
	buffer_t partialBuffer;
	int partialBufferIsSynchronized;
	transmit_queue_ctrl_t transmitQueueCtrl;
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
static void AppendBuffer(buffer_t *dst, buffer_t *src);
static void TruncateUsedBufferPortion(buffer_t *buffer);
static void LogBuffer(ddcmp_line_t *line, LogLevel level, buffer_t *buffer);
static void LogFullBuffer(ddcmp_line_t *line, LogLevel level, buffer_t *buffer);

static void InitialiseTransmitQueue(transmit_queue_ctrl_t *transmitQueueCtrl);
static transmit_queue_entry_t *AllocateNextTransmitQueueEntry(transmit_queue_ctrl_t *transmitQueueCtrl);
static transmit_queue_entry_t *GetFirstUnacknowledgedTransmitQueueEntry(transmit_queue_ctrl_t *transmitQueueCtrl);
static transmit_queue_entry_t *GetCurrentTransmitQueueEntry(transmit_queue_ctrl_t *transmitQueueCtrl);
static void FreeTransmitQueueEntry(transmit_queue_ctrl_t *transmitQueueCtrl);

static ddcmp_line_control_block_t *GetControlBlock(ddcmp_line_t *ddcmpLine);
static int Mod256Cmp(byte a, byte b);
static uint16 Crc16(uint16 crc, buffer_t *buffer);
static void AddCrc16ToBuffer(byte *data, int length);
static void DoIdle(ddcmp_line_t *ddcmpLine);
static int SynchronizeMessageFrame(ddcmp_line_t *ddcmpLine, buffer_t *buffer);
static ExtractBufferResult ExtractMessage(ddcmp_line_t *ddcmpLine, buffer_t *buffer);
static int SendMessageAddingCrc16(ddcmp_line_t *ddcmpLine, byte *data, int length);
static int SendRawMessage(ddcmp_line_t *ddcmpLine, byte *data, int length);
static void ReplyTimerHandler(void *timerContext);
static void StartTimer(ddcmp_line_t *ddcmpLine, int seconds);
static void StopTimer(ddcmp_line_t *ddcmpLine);
static int IsTimerRunning(ddcmp_line_t *ddcmpLine);
static void ProcessEvent(ddcmp_line_t *ddcmpLine, DdcmpEvent evt);
static void ProcessControlMessage(ddcmp_line_t *ddcmpLine);
static void ProcessDataMessage(ddcmp_line_t *ddcmpLine);
static void ProcessStartMessage(ddcmp_line_t *ddcmpLine);
static void ProcessStackMessage(ddcmp_line_t *ddcmpLine);
static void ProcessAckMessage(ddcmp_line_t *ddcmpLine);
static void ProcessNakMessage(ddcmp_line_t *ddcmpLine);
static void ProcessRepMessage(ddcmp_line_t *ddcmpLine);
static void ValidateMessage(ddcmp_line_t *ddcmpLine, int *valid, int validTerm, char *messageName, char *errorMessage);
static unsigned int GetDataMessageCount(buffer_t *message);
static byte GetSubtype(buffer_t *message);
static byte GetMessageFlags(buffer_t *message);
static byte GetMessageNum(buffer_t *message);
static byte GetMessageResp(buffer_t *message);
static void UpdateTransmitHeader(buffer_t *message, ddcmp_line_control_block_t *cb);
static void SendAck(ddcmp_line_t *ddcmpLine);
static void SendNak(ddcmp_line_t *ddcmpLine);
static void SendRep(ddcmp_line_t *ddcmpLine);

static int StopTimerAction(ddcmp_line_t *ddcmpLine);
static int StartTimerAction(ddcmp_line_t *ddcmpLine);
static int SendStartAction(ddcmp_line_t *ddcmpLine);
static int SendAckAction(ddcmp_line_t *ddcmpLine);
static int SendStackAction(ddcmp_line_t *ddcmpLine);
static int ResetVariablesAction(ddcmp_line_t *ddcmpLine);
static int NotifyRunningAction(ddcmp_line_t *ddcmpLine);
static int NotifyHaltAction(ddcmp_line_t *ddcmpLine);
static int SetSackAction(ddcmp_line_t *ddcmpLine);
static int SetSnakAction(ddcmp_line_t *ddcmpLine);
static int ClearSackSnakAction(ddcmp_line_t *ddcmpLine);
static int SetNakReason3Action(ddcmp_line_t *ddcmpLine);
static int SetReceivedSequenceNumberAction(ddcmp_line_t *ddcmpLine);
static int GiveMessageToUserAction(ddcmp_line_t *ddcmpLine);
static int SendMessageAction(ddcmp_line_t *ddcmpLine);
static int IncrementNAction(ddcmp_line_t *ddcmpLine);
static int IncrementTAction(ddcmp_line_t *ddcmpLine);
static int SetAVarAction(ddcmp_line_t *ddcmpLine);
static int SetTVarFromAckAction(ddcmp_line_t *ddcmpLine);
static int SetTVarFromNakAction(ddcmp_line_t *ddcmpLine);
static int SetXVarFromMsgNumAction(ddcmp_line_t *ddcmpLine);
static int CheckAckWaitTimerAction(ddcmp_line_t *ddcmpLine);
static int SetSrepAction(ddcmp_line_t *ddcmpLine);
static int CompleteMessageAction(ddcmp_line_t *ddcmpLine);

static int messageReadyToRead;

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
	{ UserRequestsHalt,                   DdcmpLineAny,      DdcmpLineHalted,   { StopTimerAction } },

	{ UserRequestsStartup,                DdcmpLineHalted,   DdcmpLineIStrt,    { StopTimerAction, SendStartAction, ResetVariablesAction, StartTimerAction } },

	{ ReceiveStack,                       DdcmpLineIStrt,    DdcmpLineRunning,  { SendAckAction, StopTimerAction, NotifyRunningAction } },
	{ ReceiveStrt,                        DdcmpLineIStrt,    DdcmpLineAStrt,    { SendStackAction, StartTimerAction } },
	{ TimerExpires,                       DdcmpLineIStrt,    DdcmpLineIStrt,    { SendStartAction, StartTimerAction } },

	{ ReceiveAckResp0,                    DdcmpLineAStrt,    DdcmpLineRunning,  { StopTimerAction, NotifyRunningAction } },
	{ ReceiveDataResp0, /*notused?*/      DdcmpLineAStrt,    DdcmpLineRunning,  { StopTimerAction, NotifyRunningAction } },
	{ ReceiveStack,                       DdcmpLineAStrt,    DdcmpLineRunning,  { SendAckAction, StopTimerAction, NotifyRunningAction } },
	{ ReceiveStrt,                        DdcmpLineAStrt,    DdcmpLineAStrt,    { SendStackAction, StartTimerAction } },
	{ TimerExpires,                       DdcmpLineAStrt,    DdcmpLineAStrt,    { SendStackAction, StartTimerAction } },

	{ ReceiveStrt,                        DdcmpLineRunning,  DdcmpLineHalted,   { NotifyHaltAction } },
	{ ReceiveStack,                       DdcmpLineRunning,  DdcmpLineRunning,  { SendAckAction } },

	{ ReceiveRepNumEqualsR,               DdcmpLineRunning,  DdcmpLineRunning,  { SetSackAction } },
	{ ReceiveRepNumNotEqualsR,            DdcmpLineRunning,  DdcmpLineRunning,  { SetNakReason3Action, SetSnakAction } },
	{ UserRequestsHalt,                   DdcmpLineRunning,  DdcmpLineHalted,   { StopTimerAction} },
	{ ReceiveDataMsgInSequence,           DdcmpLineRunning,  DdcmpLineRunning,  { GiveMessageToUserAction, SetReceivedSequenceNumberAction, SetSackAction } },
	{ ReceiveDataMsgOutOfSequence,        DdcmpLineRunning,  DdcmpLineRunning,  { NULL } },
	{ ReceiveAckResp0,                    DdcmpLineRunning,  DdcmpLineRunning,  { CompleteMessageAction, SetAVarAction, SetTVarFromAckAction, CheckAckWaitTimerAction } },
	{ ReceiveAckForOutstandingMsg,        DdcmpLineRunning,  DdcmpLineRunning,  { CompleteMessageAction, SetAVarAction, SetTVarFromAckAction, CheckAckWaitTimerAction } },
	{ ReceiveNakForOutstandingMsg,        DdcmpLineRunning,  DdcmpLineRunning,  { SetAVarAction, SetTVarFromNakAction, StopTimerAction } },

	{ ReadyToRetransmitMsg,               DdcmpLineRunning,  DdcmpLineRunning,  { SendMessageAction, IncrementTAction, ClearSackSnakAction, SetXVarFromMsgNumAction, CheckAckWaitTimerAction } },
	{ UserRequestsDataSendAndReadyToSend, DdcmpLineRunning,  DdcmpLineRunning,  { SendMessageAction, IncrementNAction, IncrementTAction, ClearSackSnakAction, SetXVarFromMsgNumAction, CheckAckWaitTimerAction } },
	{ TimerExpires,                       DdcmpLineRunning,  DdcmpLineRunning,  { SetSrepAction } },

	{ ReceiveMaintenanceMessage,          DdcmpLineAny,      DdcmpLineHalted,   { NotifyHaltAction } },

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
	else
	{
		memset(ddcmpLine->controlBlock, 0, sizeof(ddcmp_line_control_block_t));
	}

	cb = GetControlBlock(ddcmpLine);
	InitialiseTransmitQueue(&cb->transmitQueueCtrl);
	cb->state = DdcmpLineHalted;
	cb->SACKNAK = NotSet;
	InitialiseBuffer(&cb->partialBuffer, cb->partialBufferData, 0);
	ProcessEvent(ddcmpLine, UserRequestsStartup);
}

void DdcmpHalt(ddcmp_line_t *ddcmpLine)
{
	ProcessEvent(ddcmpLine, UserRequestsHalt);
}

void DdcmpProcessReceivedData(ddcmp_line_t *ddcmpLine, byte *data, int length)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	buffer_t incomingBuffer;
	buffer_t extractedBuffer;

	InitialiseBuffer(&incomingBuffer, data, length);
	AppendBuffer(&cb->partialBuffer, &incomingBuffer);
	//ddcmpLine->Log(LogFatal, "Partial(Pos:%d of %d): ", cb->partialBuffer.position, cb->partialBuffer.length);
	//LogBuffer(ddcmpLine, LogFatal, &cb->partialBuffer);
	//ddcmpLine->Log(LogFatal, "\n");

	messageReadyToRead = 0;

	/* to avoid overrunning the single-message buffer, stop the loop if a message is ready to be read */
	while(BufferStillHasData(&cb->partialBuffer) && !messageReadyToRead)
	{
		if (!cb->partialBufferIsSynchronized)
		{
			cb->partialBufferIsSynchronized = SynchronizeMessageFrame(ddcmpLine, &cb->partialBuffer);
			TruncateUsedBufferPortion(&cb->partialBuffer);
		}

		if (cb->partialBufferIsSynchronized)
		{
			ExtractBufferResult extractResult;
			cb->currentMessage = &extractedBuffer; /* set up location to store buffer to */
			extractResult = ExtractMessage(ddcmpLine, &cb->partialBuffer);
			if (extractResult == CompleteGood)
			{
				switch (CurrentByte(cb->currentMessage))
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
						ddcmpLine->Log(LogError, "Maintenance message received, halting as maintenance mode is not supported\n");
						ProcessEvent(ddcmpLine, ReceiveMaintenanceMessage);
						break;
					}

				default:
					{
						ddcmpLine->Log(LogWarning, "Unknown message category\n");
						break;
					}
				}
			}
			else if (extractResult == CompleteBad && CurrentByte(cb->currentMessage) == SOH)
			{
				SendNak(ddcmpLine); /* NAK reason has been set up in ExtractMessage */
			}

			if (extractResult == Incomplete)
			{
				break;
			}
			else
			{
				TruncateUsedBufferPortion(&cb->partialBuffer);
			}
		}
	}

	DoIdle(ddcmpLine);
}

int DdcmpSendDataMessage(ddcmp_line_t *ddcmpLine, byte *data, int length)
{
	int ans = 0;
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	if (length > (MAX_DDCMP_BUFFER_LENGTH - 6 - 2 - 2))
	{
		ddcmpLine->Log(LogError, "Request to send message longer than maximum permitted buffer length, requested data length is %d\n", length);
	}
	else if (cb->state == DdcmpLineRunning)
	{
		if (cb->T == ((cb->N + (byte)1) & 0xFF) && cb->SACKNAK != SNAK && !cb->SREP)
		{
			transmit_queue_entry_t *entry = AllocateNextTransmitQueueEntry(&cb->transmitQueueCtrl);
			if (entry != NULL)
			{
				entry->header[0] = SOH;
				entry->header[1] = length & 0xFF;
				entry->header[2] = (length >> 8) & 0x3F;
				entry->header[3] = cb->R;
				entry->header[4] = cb->N + (byte)1;
				entry->header[5] = station;
				AddCrc16ToBuffer(entry->header, 6);
				memcpy(entry->data, data, length);
				AddCrc16ToBuffer(entry->data, length);
				InitialiseBuffer(&entry->buffer, entry->header, 8 + length +2);
				cb->currentMessage = &entry->buffer;
				ProcessEvent(ddcmpLine, UserRequestsDataSendAndReadyToSend);
				ans = 1;
			}
		}
	}

	DoIdle(ddcmpLine);

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

static void AppendBuffer(buffer_t *dst, buffer_t *src)
{
	int len = RemainingBytesInBuffer(src);
	memcpy(&dst->data[dst->length], &src->data[src->position], len); // TODO: check for buffer overflow, will need a buffer size field in the buffer type
	dst->length += len;
	AdvanceBufferPostion(src, len);
}

static void TruncateUsedBufferPortion(buffer_t *buffer)
{
	int len = RemainingBytesInBuffer(buffer);
	memmove(buffer->data, buffer->data + buffer->position, len);
	buffer->length = len;
	buffer->position = 0;
}

static void LogBuffer(ddcmp_line_t *line, LogLevel level, buffer_t *buffer)
{
	int i;
	int len = RemainingBytesInBuffer(buffer);
	for (i = 0; i < len; i++)
	{
		line->Log(level, "%02X ", ByteAt(buffer, buffer->position + i));
	}
}

static void LogFullBuffer(ddcmp_line_t *line, LogLevel level, buffer_t *buffer)
{
	ResetBuffer(buffer);
	LogBuffer(line, level, buffer);
	line->Log(level, "\n");
}

static void InitialiseTransmitQueue(transmit_queue_ctrl_t *transmitQueueCtrl)
{
	int i;
	transmitQueueCtrl->lastAllocatedTransmitQueueEntry = NULL;
	transmitQueueCtrl->firstUnacknowledgedTransmitQueueEntry = &transmitQueueCtrl->transmitQueue[0];
	transmitQueueCtrl->currentTransmitQueueEntry = &transmitQueueCtrl->transmitQueue[0];
	for (i = 0; i < MAX_TRANSMIT_QUEUE_LEN; i++)
	{
		transmitQueueCtrl->transmitQueue[i].slotNumber = i;
		transmitQueueCtrl->transmitQueue[i].slotInUse = 0;
		if (i + 1 < MAX_TRANSMIT_QUEUE_LEN)
		{
			transmitQueueCtrl->transmitQueue[i].next = &transmitQueueCtrl->transmitQueue[i + 1];
		}
		else
		{
			transmitQueueCtrl->transmitQueue[i].next = &transmitQueueCtrl->transmitQueue[0];
		}
	}
}

static transmit_queue_entry_t *AllocateNextTransmitQueueEntry(transmit_queue_ctrl_t *transmitQueueCtrl)
{
	transmit_queue_entry_t *ans = NULL;
	if (transmitQueueCtrl->lastAllocatedTransmitQueueEntry == NULL)
	{
		ans = &transmitQueueCtrl->transmitQueue[0];
	}
	else
	{
		transmit_queue_entry_t *temp = transmitQueueCtrl->lastAllocatedTransmitQueueEntry;
		do
		{
			if (temp->slotInUse)
			{
				temp = temp->next;
			}
			else
			{
				ans = temp;
				break;
			}
		}
		while (temp != transmitQueueCtrl->lastAllocatedTransmitQueueEntry);
	}

	if (ans != NULL)
	{
		transmitQueueCtrl->lastAllocatedTransmitQueueEntry = ans;
		transmitQueueCtrl->lastAllocatedTransmitQueueEntry->slotInUse = 1;
	}

	return ans;
}

static transmit_queue_entry_t *GetFirstUnacknowledgedTransmitQueueEntry(transmit_queue_ctrl_t *transmitQueueCtrl)
{
	transmit_queue_entry_t *ans = NULL;
	if (transmitQueueCtrl->firstUnacknowledgedTransmitQueueEntry->slotInUse)
	{
		ans = transmitQueueCtrl->firstUnacknowledgedTransmitQueueEntry;
		transmitQueueCtrl->currentTransmitQueueEntry = ans;
	}

	return ans;
}

static transmit_queue_entry_t *GetCurrentTransmitQueueEntry(transmit_queue_ctrl_t *transmitQueueCtrl)
{
	transmit_queue_entry_t *ans = NULL;
	if (transmitQueueCtrl->currentTransmitQueueEntry->slotInUse)
	{
		ans = transmitQueueCtrl->currentTransmitQueueEntry;
	}

	return ans;
}

static void FreeTransmitQueueEntry(transmit_queue_ctrl_t *transmitQueueCtrl)
{
	transmitQueueCtrl->firstUnacknowledgedTransmitQueueEntry->slotInUse = 0;
	if (transmitQueueCtrl->firstUnacknowledgedTransmitQueueEntry != transmitQueueCtrl->lastAllocatedTransmitQueueEntry)
	{
		transmitQueueCtrl->firstUnacknowledgedTransmitQueueEntry = transmitQueueCtrl->firstUnacknowledgedTransmitQueueEntry->next;
	}
}

static ddcmp_line_control_block_t *GetControlBlock(ddcmp_line_t *ddcmpLine)
{
	return (ddcmp_line_control_block_t *)ddcmpLine->controlBlock;
}

static int Mod256Cmp(byte a, byte b)
{
	int ans;
	int abdiff = b - a;
	int badiff = a - b;

	if (abdiff == 0)
	{
		ans = 0;
	}
	else if (abdiff < 0)
	{
		ans = -1;
	}
	else
	{
		ans = 1;
	}

	if (abs(badiff) <= MAX_TRANSMIT_QUEUE_LEN)
	{
		ans = -1 * ans;
	}

	return ans;
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

static void AddCrc16ToBuffer(byte *data, int length)
{
	buffer_t buf;
	uint16 crc16;
	InitialiseBuffer(&buf, data, length);
	crc16 = Crc16(0, &buf);
	data[length] = crc16 & 0xFF;
	data[length + 1] = crc16 >> 8;
}

static void DoIdle(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);

	/* Order is as per note 5 of section 5.3.9 of the spec */

	if (cb->SACKNAK == SNAK)
	{
		SendNak(ddcmpLine);
	}

	if (cb->SREP)
	{
		SendRep(ddcmpLine);
	}

	if (cb->SACKNAK != SNAK && !cb->SREP && cb->T < (cb->N + (byte)1) && !IsTimerRunning(ddcmpLine))
	{
		transmit_queue_entry_t *entry = GetFirstUnacknowledgedTransmitQueueEntry(&cb->transmitQueueCtrl);
		if (entry != NULL)
		{
			cb->currentMessage = &entry->buffer;
			ProcessEvent(ddcmpLine, ReadyToRetransmitMsg);
		}
	}

	if (cb->SACKNAK == SACK)
	{
		SendAck(ddcmpLine);
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

static ExtractBufferResult ExtractMessage(ddcmp_line_t *ddcmpLine, buffer_t *buffer)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ExtractBufferResult ans = Incomplete;
	int savePos = CurrentBufferPosition(buffer);
	switch (CurrentByte(buffer))
	{
	case ENQ:
		{
			if (BufferFromSegment(buffer, 8, cb->currentMessage))
			{
				if (Crc16(0, cb->currentMessage) == 0)
				{
					ans = CompleteGood;
				}
				else
				{
					ans = CompleteBad;
					ddcmpLine->Log(LogWarning, "CRC error on received message: ");
					LogFullBuffer(ddcmpLine, LogWarning, cb->currentMessage);
				}
			}
			else
			{
				ans = Incomplete;
			}
			break;
		}

	case SOH:
	case DLE:
		{
			if (BufferFromSegment(buffer, 8, cb->currentMessage))
			{
				if (Crc16(0, cb->currentMessage) == 0)
				{
					unsigned int count = GetDataMessageCount(cb->currentMessage);
					SetBufferPosition(cb->currentMessage, 8);

					if (ExtendBuffer(buffer, cb->currentMessage, count + 2))
					{
						if (Crc16( 0, cb->currentMessage) == 0)
						{
							ResetBuffer(cb->currentMessage);
							ans = CompleteGood;
						}
						else
						{
							ans = CompleteBad;
							cb->NAKReason = 2;
							ddcmpLine->Log(LogWarning, "CRC error on received data block: ");
					        LogFullBuffer(ddcmpLine, LogWarning, cb->currentMessage);
						}
					}
					else
					{
						ans = Incomplete;
					}
				}
				else
				{
					ans = CompleteBad;
					cb->NAKReason = 1;
					ddcmpLine->Log(LogWarning, "CRC error on received message header: ");
					LogFullBuffer(ddcmpLine, LogWarning, cb->currentMessage);
				}
			}
			else
			{
				ans = Incomplete;
			}
			break;
		}

	default:
		{
			ans = CompleteBad;
			break;
		}
	}

	if (ans == Incomplete)
	{
		SetBufferPosition(buffer, savePos);
	}

	return ans;
}

static int SendMessageAddingCrc16(ddcmp_line_t *ddcmpLine, byte *data, int length)
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

static int SendRawMessage(ddcmp_line_t *ddcmpLine, byte *data, int length)
{
	ddcmpLine->SendData(ddcmpLine->context, data, length);
	return 1;
}

static void ReplyTimerHandler(void *timerContext)
{
	ddcmp_line_t *ddcmpLine = (ddcmp_line_t *)timerContext;
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	cb->replyTimerHandle = NULL;
	ddcmpLine->Log(LogVerbose, "Processing timer expiry\n");
	ProcessEvent(ddcmpLine, TimerExpires);
	DoIdle(ddcmpLine);
}

static void StartTimer(ddcmp_line_t *ddcmpLine, int seconds)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	if (cb->replyTimerHandle == NULL)
	{
		ddcmpLine->Log(LogVerbose, "Starting timer for %d seconds\n", seconds);
		cb->replyTimerHandle = ddcmpLine->CreateOneShotTimer(ddcmpLine, "Reply timer", seconds, ReplyTimerHandler);
	}
}

static void StopTimer(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	if (cb->replyTimerHandle != NULL)
	{
		ddcmpLine->Log(LogVerbose, "Stopping timer\n");
		ddcmpLine->CancelOneShotTimer(cb->replyTimerHandle);
		cb->replyTimerHandle = NULL;
	}
}

static int IsTimerRunning(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	return cb->replyTimerHandle != NULL;
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
			ddcmpLine->Log(LogVerbose, "Changing line state for %s from %s to %s\n", ddcmpLine->name, lineStateString[(int)cb->state], lineStateString[(int)entry->newState]);
		}

		cb->state = entry->newState;

		for (i = 0; i < MAX_STATE_TABLE_ACTIONS && ok; i++)
		{
			if (entry->action[i] != NULL)
			{
				ok = entry->action[i](ddcmpLine);
			}
		}

		ddcmpLine->Log(LogVerbose, "Variables after processing event. N=%d, A=%d, R=%d, T=%d, X=%d\n", cb->N, cb->A, cb->R, cb->T, cb->X);
	}
}

static void ProcessControlMessage(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte msgType;
	MoveToNextByte(cb->currentMessage);
	msgType = CurrentByte(cb->currentMessage);
	MoveToNextByte(cb->currentMessage);
	switch (msgType)
	{
	case CONTROL_ACK:
		{
			ProcessAckMessage(ddcmpLine);
			break;
		}
	case CONTROL_NAK:
		{
			ProcessNakMessage(ddcmpLine);
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
			ddcmpLine->Log(LogWarning, "Unknown control message type %d from %s\n", msgType, ddcmpLine->name);
			break;
		}
	}
}

static void ProcessDataMessage(ddcmp_line_t *ddcmpLine)
{
	// TODO: validate data message
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	unsigned int count;
	int flags;
	byte resp;
	byte num;
	int addr;
	int valid = 1;
	char *msgName = "DATA";

	count = GetDataMessageCount(cb->currentMessage);
	flags = GetMessageFlags(cb->currentMessage);
	resp = GetMessageResp(cb->currentMessage);
	num = GetMessageNum(cb->currentMessage);
	addr = ByteAt(cb->currentMessage, 5);
	ddcmpLine->Log(LogDetail, "Received %s message from %s. Len=%d, Flags=%s%s, R=%d, N=%d, Addr=%d\n", msgName, ddcmpLine->name, count, LOGFLAGS(flags), resp, num, addr);

	ValidateMessage(ddcmpLine, &valid, addr == 1, msgName, "Address should be 1");
	ValidateMessage(ddcmpLine, &valid, count == cb->currentMessage->length - 10, msgName, "Data length does not match count in header");

	if (valid)
	{
		if (Mod256Cmp(cb->A, resp) < 0 && Mod256Cmp(resp, cb->N) <= 0)
		{
			ProcessEvent(ddcmpLine, ReceiveAckForOutstandingMsg);
		}

		if (num == ((cb->R + 1) & 0xFF))
		{
			ProcessEvent(ddcmpLine, ReceiveDataMsgInSequence);
		}
		else
		{
			ProcessEvent(ddcmpLine, ReceiveDataMsgOutOfSequence);
		}
	}
	else
	{
		cb->NAKReason = 17;
		SendNak(ddcmpLine);
	}
}

static void ProcessStartMessage(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int flags;
	int addr;
	int valid = 1;
	char *msgName = "STRT";

	flags = GetMessageFlags(cb->currentMessage);
	addr = ByteAt(cb->currentMessage, 5);

	ValidateMessage(ddcmpLine, &valid, GetSubtype(cb->currentMessage) == 0, msgName, "Subtype should be 0");
	ValidateMessage(ddcmpLine, &valid, flags == 3, msgName, "Flags should be 3");
	ValidateMessage(ddcmpLine, &valid, ByteAt(cb->currentMessage, 3) == 0, msgName, "Fill byte should be 0");
	ValidateMessage(ddcmpLine, &valid, ByteAt(cb->currentMessage, 4) == 0, msgName, "Fill byte should be 0");
	ValidateMessage(ddcmpLine, &valid, addr == 1, msgName, "Address should be 1");

	if (valid)
	{
		ddcmpLine->Log(LogDetail, "Received %s message from %s. Flags=%s%s, Addr=%d\n", msgName, ddcmpLine->name, LOGFLAGS(flags), addr);
		ProcessEvent(ddcmpLine, ReceiveStrt);
	}
	else
	{
		ddcmpLine->Log(LogWarning, "Invalid %s message from %s ignored: ", msgName, ddcmpLine->name);
		LogFullBuffer(ddcmpLine, LogWarning, cb->currentMessage);
	}
}

static void ProcessStackMessage(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int flags;
	int addr;
	int valid = 1;
	char *msgName = "STACK";

	flags = GetMessageFlags(cb->currentMessage);
	addr = ByteAt(cb->currentMessage, 5);

	ValidateMessage(ddcmpLine, &valid, GetSubtype(cb->currentMessage) == 0, msgName, "Subtype should be 0");
	ValidateMessage(ddcmpLine, &valid, flags == 3, msgName, "Flags should be 3");
	ValidateMessage(ddcmpLine, &valid, ByteAt(cb->currentMessage, 3) == 0, msgName, "Fill byte should be 0");
	ValidateMessage(ddcmpLine, &valid, ByteAt(cb->currentMessage, 4) == 0, msgName, "Fill byte should be 0");
	ValidateMessage(ddcmpLine, &valid, addr == 1, msgName, "Address should be 1");

	if (valid)
	{
	    ddcmpLine->Log(LogDetail, "Received %s message from %s. Flags=%s%s, Addr=%d\n", msgName, ddcmpLine->name, LOGFLAGS(flags), addr);
	    ProcessEvent(ddcmpLine, ReceiveStack);
	}
	else
	{
		ddcmpLine->Log(LogWarning, "Invalid %s message from %s ignored: ", msgName, ddcmpLine->name);
		LogFullBuffer(ddcmpLine, LogWarning, cb->currentMessage);
	}
}

static void ProcessAckMessage(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte flags;
	byte addr;
	byte resp;
	int valid = 1;
	char *msgName = "ACK";

	flags = GetMessageFlags(cb->currentMessage);
	resp = GetMessageResp(cb->currentMessage);
	addr = ByteAt(cb->currentMessage, 5);

	ValidateMessage(ddcmpLine, &valid, GetSubtype(cb->currentMessage) == 0, msgName, "Subtype should be 0");
	ValidateMessage(ddcmpLine, &valid, ByteAt(cb->currentMessage, 4) == 0, msgName, "Fill byte should be 0");
	ValidateMessage(ddcmpLine, &valid, addr == 1, msgName, "Address should be 1");

	if (valid)
	{
		ddcmpLine->Log(LogDetail, "Received %s message from %s. Flags=%s%s, R=%d, Addr=%d\n", msgName, ddcmpLine->name, LOGFLAGS(flags), resp, addr);
		if (resp == 0)
		{
			ProcessEvent(ddcmpLine, ReceiveAckResp0);
		}
		else if (Mod256Cmp(cb->A, resp) < 0 && Mod256Cmp(resp, cb->N) <= 0)
		{
			ProcessEvent(ddcmpLine, ReceiveAckForOutstandingMsg);
		}
	}
	else
	{
		ddcmpLine->Log(LogWarning, "Invalid %s message from %s ignored: ", msgName, ddcmpLine->name);
		LogFullBuffer(ddcmpLine, LogWarning, cb->currentMessage);
	}
}

static void ProcessNakMessage(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte reason;
	byte flags;
	byte addr;
	byte resp;
	int valid = 1;
	char *msgName = "NAK";

	reason = GetSubtype(cb->currentMessage);
	flags = GetMessageFlags(cb->currentMessage);
	resp = GetMessageResp(cb->currentMessage);
	addr = ByteAt(cb->currentMessage, 5);

	ValidateMessage(ddcmpLine, &valid, ByteAt(cb->currentMessage, 4) == 0, msgName, "Fill byte should be 0");
	ValidateMessage(ddcmpLine, &valid, addr == 1, msgName, "Address should be 1");

	if (valid)
	{
		ddcmpLine->Log(LogDetail, "Received %s message from %s. Flags=%s%s, Reason=%d, R=%d, Addr=%d\n", msgName, ddcmpLine->name, LOGFLAGS(flags), reason, resp, addr);
		if (Mod256Cmp(cb->A, resp) <= 0 || Mod256Cmp(resp, cb->N) > 0)
		{
			ProcessEvent(ddcmpLine, ReceiveNakForOutstandingMsg);
		}
	}
	else
	{
		ddcmpLine->Log(LogWarning, "Invalid %s message from %s ignored: ", msgName, ddcmpLine->name);
		LogFullBuffer(ddcmpLine, LogWarning, cb->currentMessage);
	}
}

static void ProcessRepMessage(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int flags;
	int addr;
	int num;
	int valid = 1;
	char *msgName = "REP";

	flags = GetMessageFlags(cb->currentMessage);
	num = GetMessageNum(cb->currentMessage);
	addr = ByteAt(cb->currentMessage, 5);

	ValidateMessage(ddcmpLine, &valid, GetSubtype(cb->currentMessage) == 0, msgName, "Subtype should be 0");
	ValidateMessage(ddcmpLine, &valid, ByteAt(cb->currentMessage, 3) == 0, msgName, "Fill byte should be 0");
	ValidateMessage(ddcmpLine, &valid, addr == 1, msgName, "Address should be 1");

	if (valid)
	{
		ddcmpLine->Log(LogDetail, "Received %s message from %s. Flags=%s%s, N=%d, Addr=%d\n", msgName, ddcmpLine->name, LOGFLAGS(flags), num, addr);

		if (num == cb->R)
		{
			ProcessEvent(ddcmpLine, ReceiveRepNumEqualsR);
		}
		else
		{
			ProcessEvent(ddcmpLine, ReceiveRepNumNotEqualsR);
		}
	}
	else
	{
		ddcmpLine->Log(LogWarning, "Invalid %s message from %s ignored: ", msgName, ddcmpLine->name);
		LogFullBuffer(ddcmpLine, LogWarning, cb->currentMessage);
	}
}

static void ValidateMessage(ddcmp_line_t *ddcmpLine, int *valid, int validTerm, char *messageName, char *errorMessage)
{
	if (!validTerm)
	{
		ddcmpLine->Log(LogWarning, "Invalid %s message from %s: %s\n", messageName, ddcmpLine->name, errorMessage);
	}

	*valid = *valid && validTerm;
}

static unsigned int GetDataMessageCount(buffer_t *message)
{
	unsigned int count;

	count = ByteAt(message, 1) & 0xFF;
	count += (ByteAt(message,2) & 0x3F) << 8;

	return count;
}

static byte GetSubtype(buffer_t *message)
{
	return ByteAt(message, 2) & 0x3F;
}

static byte GetMessageFlags(buffer_t *message)
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

static void UpdateTransmitHeader(buffer_t *message, ddcmp_line_control_block_t *cb)
{
	message->data[3] = cb->R;
	AddCrc16ToBuffer(message->data, 6);
}

static void SendAck(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte ack[] = { 0x05, CONTROL_ACK, 0x00, 0x00, 0x00, 0x00 };
	ack[3] = cb->R;
	ack[5] = station;
	ddcmpLine->Log(LogDetail, "Sending ACK to %s. Num=%d\n", ddcmpLine->name, cb->R);
	SendMessageAddingCrc16(ddcmpLine, ack, sizeof(ack));
	cb->SACKNAK = NotSet;
}

static void SendNak(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte nak[] = { ENQ, CONTROL_NAK, 0x00, 0x00, 0x00, 0x00 };
	nak[2] = cb->NAKReason;
	nak[3] = cb->R;
	nak[5] = station;
	ddcmpLine->Log(LogDetail, "Sending NAK to %s. Num=%d, Reason=%d\n", ddcmpLine->name, cb->R, cb->NAKReason);
	SendMessageAddingCrc16(ddcmpLine, nak, sizeof(nak));
	cb->SACKNAK = NotSet;
}

static void SendRep(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte rep[] = { ENQ, CONTROL_REP, 0x00, 0x00, 0x00, 0x00 };
	rep[4] = cb->N;
	rep[5] = station;
	ddcmpLine->Log(LogDetail, "Sending REP to %s. Num=%d\n", ddcmpLine->name, cb->N);
	SendMessageAddingCrc16(ddcmpLine, rep, sizeof(rep));
	cb->SREP = 0;
	StartTimer(ddcmpLine, 15);
}

static int StopTimerAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Stop timer action for %s\n", ddcmpLine->name);
	StopTimer(ddcmpLine);
	return 1;
}

static int StartTimerAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Start timer action for %s\n", ddcmpLine->name);
	StartTimer(ddcmpLine, 3);
	return 1;
}

static int SendStartAction(ddcmp_line_t *ddcmpLine)
{
	byte start[] = { ENQ, CONTROL_STRT, 0xC0, 0x00, 0x00, 0x00 };
	start[5] = station;
	ddcmpLine->Log(LogVerbose, "Send start action for %s\n", ddcmpLine->name);
	ddcmpLine->Log(LogDetail, "Sending STRT to %s. Addr=%d\n", ddcmpLine->name, station);
	SendMessageAddingCrc16(ddcmpLine, start, sizeof(start));
	return 1;
}

static int SendAckAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Send ack action for %s\n", ddcmpLine->name);
	SendAck(ddcmpLine);
	return 1;
}

static int SendStackAction(ddcmp_line_t *ddcmpLine)
{
	byte stack[] = { ENQ, CONTROL_STACK, 0xC0, 0x00, 0x00, 0x00 };
	stack[5] = station;
	ddcmpLine->Log(LogVerbose, "Send stack action for %s\n", ddcmpLine->name);
	ddcmpLine->Log(LogDetail, "Sending STACK to %s. Addr=%d\n", ddcmpLine->name, station);
	SendMessageAddingCrc16(ddcmpLine, stack, sizeof(stack));
	return 1;
}

static int ResetVariablesAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Reset variables action for %s\n", ddcmpLine->name);
	cb->R = 0;
	cb->N = 0;
	cb->A = 0;
	cb->T = 1;
	cb->X = 0;
	return 1;
}

static int NotifyRunningAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Notify running action for %s\n", ddcmpLine->name);
	if (ddcmpLine->NotifyRunning != NULL)
	{
		ddcmpLine->NotifyRunning(ddcmpLine->context);
	}

	return 1;
}

static int NotifyHaltAction(ddcmp_line_t *ddcmpLine)
{
	ddcmpLine->Log(LogVerbose, "Notify halt action for %s\n", ddcmpLine->name);
	if (ddcmpLine->NotifyHalt != NULL)
	{
		ddcmpLine->NotifyHalt(ddcmpLine->context);
	}

	return 1;
}

static int SetSackAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set SACK action for %s\n", ddcmpLine->name);
	cb->SACKNAK = SACK;
	return 1;
}

static int SetSnakAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set SNAK action for %s\n", ddcmpLine->name);
	cb->SACKNAK = SNAK;
	return 1;
}

static int ClearSackSnakAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Clear SACK/SNAK action for %s\n", ddcmpLine->name);
	cb->SACKNAK = NotSet;
	return 1;
}

static int SetNakReason3Action(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set NAK reason 3 action for %s\n", ddcmpLine->name);
	cb->NAKReason = 3;
	return 1;
}

static int SetReceivedSequenceNumberAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set received sequence number action for %s\n", ddcmpLine->name);
	cb->R = cb->R + (byte)1;
	return 1;
}

static int GiveMessageToUserAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int ans = 1;
	ddcmpLine->Log(LogVerbose, "Give message to user action for %s\n", ddcmpLine->name);
	if (!ddcmpLine->NotifyDataMessage(ddcmpLine->context, &cb->currentMessage->data[8], GetDataMessageCount(cb->currentMessage)))
	{
		cb->NAKReason = 8;
		cb->SACKNAK = SNAK;
		ans = 0;
	}
	else
	{
		messageReadyToRead = 1;
	}

	return ans;
}

static int SendMessageAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	int num;
	int resp;
	UpdateTransmitHeader(cb->currentMessage, cb);
	num = GetMessageNum(cb->currentMessage);
	resp = GetMessageResp(cb->currentMessage);
	ddcmpLine->Log(LogVerbose, "Send next message action for %s\n", ddcmpLine->name);
	ddcmpLine->Log(LogDetail, "Sending Data to %s. N=%d, R=%d\n", ddcmpLine->name, num, resp);
	SendRawMessage(ddcmpLine, cb->currentMessage->data, cb->currentMessage->length);
	return 1;
}

static int IncrementNAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Increment N action for %s\n", ddcmpLine->name);
	cb->N = cb->N + (byte)1;
	return 1;
}

static int IncrementTAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Increment T action for %s\n", ddcmpLine->name);
	cb->T = cb->N + (byte)1;
	return 1;
}

static int SetAVarAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set A variable action for %s\n", ddcmpLine->name);
	cb->A = GetMessageResp(cb->currentMessage);
	return 1;
}

static int SetTVarFromAckAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set T variable from ack action for %s\n", ddcmpLine->name);
	if (Mod256Cmp(cb->T, cb->A) <= 0)
	{
		cb->T = cb-> A + (byte)1;
	}

	return 1;
}

static int SetTVarFromNakAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set T variable from nak action for %s\n", ddcmpLine->name);
	cb->T = cb-> A + (byte)1;
	return 1;
}

static int SetXVarFromMsgNumAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Set T variable from ack action for %s\n", ddcmpLine->name);
	cb->X = GetMessageNum(cb->currentMessage);
	return 1;
}

static int CheckAckWaitTimerAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	ddcmpLine->Log(LogVerbose, "Check ack wait timer action for %s\n", ddcmpLine->name);
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
	ddcmpLine->Log(LogVerbose, "Set Srep action for %s\n", ddcmpLine->name);
	cb->SREP = 1;
	return 1;
}

static int CompleteMessageAction(ddcmp_line_t *ddcmpLine)
{
	ddcmp_line_control_block_t *cb = GetControlBlock(ddcmpLine);
	byte resp = GetMessageResp(cb->currentMessage);
	ddcmpLine->Log(LogVerbose, "Complete message action for %s\n", ddcmpLine->name);

	while (1)
	{
		transmit_queue_entry_t *entry = GetFirstUnacknowledgedTransmitQueueEntry(&cb->transmitQueueCtrl);
		if (entry == NULL)
		{
			break;
		}
		else
		{
			byte N = GetMessageNum(&entry->buffer);
			if (Mod256Cmp(N, resp) <= 0)
			{
				FreeTransmitQueueEntry(&cb->transmitQueueCtrl);
			}
			else
			{
				break;
			}
		}
	}

	return 1;
}
