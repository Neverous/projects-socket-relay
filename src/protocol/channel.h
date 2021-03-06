/* 2014
 * Maciej Szeptuch (neverous) <neverous@neverous.info>
 */
#ifndef __CHANNEL_H__
#define __CHANNEL_H__

#include <event2/bufferevent.h>
#include <event2/util.h>

#include "authentication.h"

struct BaseChannel
{
    struct BaseChannel          *next;
    struct BaseChannel          *prev;

    uint8_t                     proto;
    uint8_t                     alive;
    struct AuthenticationHash   token;
}; // struct BaseChannel

struct UDPChannel
{
    struct BaseChannel          base;

    struct event                *channel_event;
    evutil_socket_t             channel_fd;
    struct sockaddr_in          channel_addr;

    struct event                *peer_event;
    evutil_socket_t             peer_fd;
    struct sockaddr_in          peer_addr;

    struct evbuffer             *pre_buffer;
}; // struct UDPChannel

struct TCPChannel
{
    struct BaseChannel          base;

    struct bufferevent          *channel_buffers;
    struct bufferevent          *peer_buffers;
}; // struct TCPChannel

union Channel
{
    struct BaseChannel  base;
    struct UDPChannel   udp;
    struct TCPChannel   tcp;
};

#endif // __CHANNEL_H__
