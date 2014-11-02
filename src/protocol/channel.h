/* 2014
 * Maciej Szeptuch (neverous) <neverous@neverous.info>
 */
#ifndef __CHANNEL_H__
#define __CHANNEL_H__

#include <event2/bufferevent.h>
#include "authentication.h"

#pragma pack(push, 1)

struct Channel
{
    struct AuthenticationHash   token;
    struct bufferevent          *channel_buffers;
    struct bufferevent          *peer_buffers;

    struct Channel              *next;
    struct Channel              *prev;

    uint8_t                     marked;
}; // struct Channel

#pragma pack(pop)

#endif // __CHANNEL_H__
