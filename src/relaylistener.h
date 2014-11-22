/* 2014
 * Maciej Szeptuch (neverous) <neverous@neverous.info>
 */
#ifndef __RELAY_LISTENER_H__
#define __RELAY_LISTENER_H__

#include <stdint.h>
#include <event2/listener.h>

struct RelayListener
{
    uint8_t     proto;
    uint16_t    port;
    union
    {
        struct evconnlistener   *tcp_listener;
        struct event            *listener;
    };
}; // struct RelayListener

#endif // __RELAY_LISTENER_H__
