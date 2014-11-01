/* 2014
 * Maciej Szeptuch (neverous) <neverous@neverous.info>
 */
#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <stdint.h>
#include <assert.h>
#include "authentication.h"

#pragma pack(push, 1)

enum MessageType
{
    NOOP,
    PING,
    PONG,
    CHALLENGE,
    RESPONSE,
    OPEN_CHANNEL,
    CLOSE_CHANNEL,
}; // enum MessageType

struct Message
{
    uint8_t type;
}; // struct Message

static_assert(sizeof(struct Message) == 1, "Invalid Message structure size!");

struct MessageNoop
{
    uint8_t type;
}; // struct MessageNoop

static_assert(  sizeof(struct MessageNoop) == 1,
                "Invalid MessageNoop structure size!");

struct MessagePing
{
    uint8_t type;
    uint8_t seq;
}; // struct MessagePing

static_assert(  sizeof(struct MessagePing) == 2,
                "Invalid MessagePing structure size!");

struct MessagePong
{
    uint8_t type;
    uint8_t seq;
}; // struct MessagePong

static_assert(  sizeof(struct MessagePong) == 2,
                "Invalid MessagePong structure size!");

struct MessageChallenge
{
    uint8_t                     type;
    struct AuthenticationHash   challenge;
}; // struct MessageChallenge

static_assert(
            sizeof(struct MessageChallenge)
        ==  1 + sizeof(struct AuthenticationHash),
        "Invalid MessageChallenge structure size!");

struct MessageResponse
{
    uint8_t                     type;
    struct AuthenticationHash   response;
}; // struct MessageResponse

static_assert(
        sizeof(struct MessageResponse) == 1 + sizeof(struct AuthenticationHash),
        "Invalid MessageResponse structure size!");

struct MessageOpenChannel
{
    uint8_t                     type;
    struct AuthenticationHash   challenge;
    uint16_t                    port;
    uint8_t                     proto;
}; // struct MessageOpenChannel

static_assert(
            sizeof(struct MessageOpenChannel)
        ==  4 + sizeof(struct AuthenticationHash),
        "Invalid MessageOpenChannel structure size!");

struct MessageCloseChannel
{
    uint8_t                     type;
    struct AuthenticationHash   response;
}; // struct MessageCloseChannel

static_assert(
            sizeof(struct MessageCloseChannel)
        ==  1 + sizeof(struct AuthenticationHash),
        "Invalid MessageCloseChannel structure size!");

#pragma pack(pop)

inline
static
size_t message_get_size(const struct Message *msg)
{
    assert(msg);
    switch(msg->type)
    {
        case NOOP:
            return sizeof(struct MessageNoop);

        case PING:
            return sizeof(struct MessagePing);

        case PONG:
            return sizeof(struct MessagePong);

        case CHALLENGE:
            return sizeof(struct MessageChallenge);

        case RESPONSE:
            return sizeof(struct MessageResponse);

        case OPEN_CHANNEL:
            return sizeof(struct MessageOpenChannel);

        case CLOSE_CHANNEL:
            return sizeof(struct MessageCloseChannel);
    }

    return -1; // INVALID
}

inline
static
const char *message_get_type_string(const struct Message *msg)
{
    assert(msg);
    switch(msg->type)
    {
        case NOOP:
            return "No-op";

        case PING:
            return "Ping";

        case PONG:
            return "Pong";

        case CHALLENGE:
            return "Challenge";

        case RESPONSE:
            return "Response";

        case OPEN_CHANNEL:
            return "Open Channel";

        case CLOSE_CHANNEL:
            return "Close Channel";
    }

    return "Invalid"; // INVALID
}

#endif // __MESSAGE_H__
