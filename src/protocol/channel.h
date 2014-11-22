/* 2014
 * Maciej Szeptuch (neverous) <neverous@neverous.info>
 */
#ifndef __CHANNEL_H__
#define __CHANNEL_H__

#include <event2/bufferevent.h>
#include "authentication.h"

struct Channel
{
    struct Channel              *next;
    struct Channel              *prev;

    uint8_t                     proto;
    uint8_t                     alive;
    struct AuthenticationHash   token;

    uint8_t                     __alignment__[16];
}; // struct Channel

struct SimpleChannel
{
    struct Channel              *next;
    struct Channel              *prev;

    uint8_t                     proto;
    uint8_t                     alive;
    struct AuthenticationHash   token;

    uint32_t                    channel_fd;
    uint32_t                    peer_fd;

    uint8_t                     __alignment__[8];
}; // struct SimpleChannel

struct BufferedChannel
{
    struct Channel              *next;
    struct Channel              *prev;

    uint8_t                     proto;
    uint8_t                     alive;
    struct AuthenticationHash   token;

    struct bufferevent          *channel_buffers;
    struct bufferevent          *peer_buffers;
}; // struct BufferedChannel

static_assert(
    sizeof(struct Channel) == sizeof(struct SimpleChannel),
    "Invalid SimpleChannel structure size");

static_assert(
    sizeof(struct Channel) == sizeof(struct BufferedChannel),
    "Invalid BufferedChannel structure size");

#endif // __CHANNEL_H__
