/* 2014
 * Maciej Szeptuch (neverous) <neverous@neverous.info>
 */
#ifndef __RELAY_LISTENER_H__
#define __RELAY_LISTENER_H__

#include <stdint.h>
#include <event2/listener.h>

#pragma pack(push, 1)

struct RelayListener
{
    uint8_t     proto;
    uint16_t    port;
    union
    {
        struct evconnlistener   *tcp_listener;
        // TODO: udp support
    };
}; // struct RelayListener

#pragma pack(pop)

#endif // __RELAY_LISTENER_H__
