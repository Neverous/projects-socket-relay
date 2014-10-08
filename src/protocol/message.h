/* 2014
 * Maciej Szeptuch (neverous) <neverous@neverous.info>
 */
#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdint.h>
#include "auth.h"

#pragma pack(push, 1)

typedef enum _msg_type
{
    NOP,
    PING,
    PONG,
    CHALLENGE,
    RESPONSE,
    OPEN_CHANNEL,
    CLOSE_CHANNEL,
} MsgType; // enum MsgType

typedef struct _msg
{
    uint8_t type;
} Msg; // struct Msg

static_assert(sizeof(Msg) == 1, "Invalid Msg structure size");

typedef struct _msg_nop
{
    uint8_t type;
} MsgNop; // struct MsgNop

static_assert(sizeof(MsgNop) == 1, "Invalid MsgNop structure size");

typedef struct _msg_ping
{
    uint8_t type;
    uint8_t seq;
} MsgPing; // struct MsgPing

static_assert(sizeof(MsgPing) == 2, "Invalid MsgPing structure size");

typedef struct _msg_poing
{
    uint8_t type;
    uint8_t seq;
} MsgPong; // struct MsgPong

static_assert(sizeof(MsgPong) == 2, "Invalid MsgPong structure size");

typedef struct _msg_challenge
{
    uint8_t     type;
    AuthHash    challenge;
} MsgChallenge; // struct MsgChallenge

static_assert(  sizeof(MsgChallenge) == 1 + sizeof(AuthHash),
                "Invalid MsgChallenge structure size");

typedef struct _msg_response
{
    uint8_t     type;
    AuthHash    response;
} MsgResponse; // struct MsgResponse

static_assert(  sizeof(MsgResponse) == 1 + sizeof(AuthHash),
                "Invalid MsgResponse structure size");

typedef struct _msg_open_channel
{
    uint8_t     type;
    AuthHash    challenge;
    uint16_t    port;
    uint8_t     proto;
} MsgOpenChannel; // struct MsgOpenChannel

static_assert(  sizeof(MsgOpenChannel) == 4 + sizeof(AuthHash),
                "Invalid MsgOpenChannel structure size");

typedef struct _msg_close_channel
{
    uint8_t     type;
    AuthHash    response;
} MsgCloseChannel; // struct MsgCloseChannel

static_assert(  sizeof(MsgCloseChannel) == 1 + sizeof(AuthHash),
                "Invalid MsgCloseChannel structure size");

#pragma pack(pop)

const char *mGetTypeStr(uint8_t type);

#endif // __MESSAGE_H__
