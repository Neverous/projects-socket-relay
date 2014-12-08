/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 */
#ifndef __COMMON_H__

#include <stdint.h>
#include <assert.h>
#include <time.h>

// EVENT
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include "protocol/channel.h"

#define BUFFER_LIMIT 262144

const char *VERSION = "0.1.0";

// SIMPLE LOGGING
inline
static
void debug(const char *fmt, ...)
{
    char        buffer[32];
    time_t      raw;
    struct tm   *local;
    va_list     args;

    time(&raw);
    local = localtime(&raw);
    strftime(buffer, 32, "%Y-%m-%d %H:%M:%S", local);
    fprintf(stderr, "[%s] ", buffer);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputs("\n", stderr);
    fflush(stderr);
}

// COMMON FUNCTIONS

static
void read_control_connection(struct bufferevent *buffevent, void *args)
{
    debug("control connection: reading data");
    context.alive = 1;
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    size_t len = evbuffer_get_length(input);
    while(len >= sizeof(struct Message)) // While there are some messages
    {
        size_t wanted = message_get_size(
            (struct Message *) evbuffer_pullup(input, sizeof(struct Message)));

        if(wanted > len) // Not enough data
            break;

        process_control_message(
            buffevent,
            (struct Message *) evbuffer_pullup(input, wanted));

        evbuffer_drain(input, wanted);
        len -= wanted;
    }

    struct timeval five_seconds = { 5, 0 };
    event_del(context.keepalive);
    event_add(context.keepalive, &five_seconds);
}

static
void error_on_control_connection_bufferevent(   struct bufferevent *buffevent,
                                                short events,
                                                void *args)
{
    if(events & BEV_EVENT_ERROR)
        perror("bufferevent");

    if(events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
        debug("control connection: end of data");
        teardown_control_connection();
    }
}

static
void read_tcp_channel_connection(struct bufferevent *buffevent, void *channel)
{
    union Channel *current = (union Channel *) channel;
    current->base.alive = 2;
    assert(buffevent == current->tcp.channel_buffers);

    if(evbuffer_get_length(bufferevent_get_output(current->tcp.peer_buffers))
        < BUFFER_LIMIT)
    {
        struct evbuffer *input  = bufferevent_get_input(buffevent);
        bufferevent_write_buffer(current->tcp.peer_buffers, input);
    }
}

static
void write_tcp_channel_connection(struct bufferevent *buffevent, void *channel)
{
    union Channel *current = (union Channel *) channel;
    current->base.alive = 2;
    assert(buffevent == current->tcp.channel_buffers);

    if(evbuffer_get_length(bufferevent_get_output(buffevent)) < BUFFER_LIMIT)
    {
        struct evbuffer *input  =
            bufferevent_get_input(current->tcp.peer_buffers);

        bufferevent_write_buffer(buffevent, input);
    }
}

static
void error_on_tcp_channel_connection_bufferevent(
    struct bufferevent *buffevent,
    short events,
    void *channel)
{
    if(events & BEV_EVENT_ERROR)
        perror("bufferevent");

    if(events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
        debug("tcp channel connection: end of data");
        if(channel)
            teardown_channel((union Channel *) channel, 1);
    }
}

static
void read_tcp_peer_connection(struct bufferevent *buffevent, void *channel)
{
    union Channel *current = (union Channel *) channel;
    current->base.alive = 2;
    assert(buffevent == current->tcp.peer_buffers);

    if(evbuffer_get_length(bufferevent_get_output(current->tcp.channel_buffers))
        < BUFFER_LIMIT)
    {
        struct evbuffer *input  = bufferevent_get_input(buffevent);
        bufferevent_write_buffer(current->tcp.channel_buffers, input);
    }
}

static
void write_tcp_peer_connection(struct bufferevent *buffevent, void *channel)
{
    union Channel *current = (union Channel *) channel;
    current->base.alive = 2;
    assert(buffevent == current->tcp.peer_buffers);

    if(evbuffer_get_length(bufferevent_get_output(buffevent)) < BUFFER_LIMIT)
    {
        struct evbuffer *input  =
            bufferevent_get_input(current->tcp.channel_buffers);

        bufferevent_write_buffer(buffevent, input);
    }
}

static
void error_on_tcp_peer_connection_bufferevent(  struct bufferevent *buffevent,
                                                short events,
                                                void *channel)
{
    if(events & BEV_EVENT_ERROR)
        perror("bufferevent");

    if(events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
        debug("tcp peer connection: end of data");
        teardown_channel((union Channel *) channel, 1);
    }
}

inline
static
void allocate_channels(void)
{
    assert(!context.free_channels);
    int32_t count = 8192 / sizeof(union Channel);
    context.free_channels =
        (union Channel *) malloc(count * sizeof(union Channel));

    memset(context.free_channels, 0, count * sizeof(union Channel));
    union Channel *cur = context.free_channels;
    for(int c = 0; c < count; ++ c, ++ cur)
    {
        cur->base.next = &(cur + 1)->base;
        cur->base.prev = &(cur - 1)->base;
    }

    context.free_channels->base.prev = NULL;
    -- cur;
    cur->base.next = NULL;
    return;
}

inline
static
union Channel *find_channel(const struct AuthenticationHash *token)
{
    struct BaseChannel *cur = &context.channels->base;
    while(cur && !authentication_compare_hash(&cur->token, token))
        cur = cur->next;

    return (union Channel *) cur;
}

inline
static
struct UDPChannel *find_udp_channel_by_channel(const struct sockaddr_in *addr)
{
    union Channel *cur = context.channels;
    while(cur &&
        (
            cur->base.proto != IPPROTO_UDP
        ||  cur->udp.channel_addr.sin_port != addr->sin_port
        ||  memcmp( &cur->udp.channel_addr.sin_addr,
                    &addr->sin_addr,
                    sizeof(addr->sin_addr))
        ))
    {
        cur = (union Channel *) cur->base.next;
    }

    return &cur->udp;
}

inline
static
struct UDPChannel *find_udp_channel_by_peer(const struct sockaddr_in *addr)
{
    union Channel *cur = context.channels;
    while(cur &&
        (
            cur->base.proto != IPPROTO_UDP
        ||  cur->udp.peer_addr.sin_port != addr->sin_port
        ||  memcmp( &cur->udp.peer_addr.sin_addr,
                    &addr->sin_addr,
                    sizeof(addr->sin_addr))
        ))
    {
        cur = (union Channel *) cur->base.next;
    }

    return &cur->udp;
}

// EVENTS
static
void keepalive(evutil_socket_t fd, short events, void *args)
{
    assert(events & EV_TIMEOUT);
    if(!context.control_buffers)
    {
        debug("keepalive: no connection");
        return;
    }

    if(!context.alive)
    {
        debug("keepalive: connection down");
        teardown_control_connection();
        return;
    }

    debug("keepalive: sending alive");
    ++ context.msg_alive.seq;
    bufferevent_write(  context.control_buffers,
                        &context.msg_alive,
                        sizeof(context.msg_alive));

    struct timespec cur; clock_gettime(CLOCK_MONOTONIC, &cur);
    context.last_alive =
        cur.tv_sec * 1000LL + cur.tv_nsec / 1000000LL;

    context.alive = 0;
}

static
void display_stats(evutil_socket_t fd, short events, void *args)
{
    assert(events & EV_TIMEOUT);

    uint32_t    used_channels   = 0;
    uint32_t    alive_channels  = 0;
    uint32_t    free_channels   = 0;
    for(struct BaseChannel *cur = &context.channels->base; cur; cur = cur->next)
    {
        ++ used_channels;
        alive_channels += cur->alive > 0;
    }

    for(struct BaseChannel *cur = &context.free_channels->base;
        cur;
        cur = cur->next)
        ++ free_channels;

    debug("STATS: Channels used: %u, alive: %u, free: %u",
        used_channels, alive_channels, free_channels);
}

static
void cleanup_channels(evutil_socket_t fd, short events, void *args)
{
    assert(events & EV_TIMEOUT);
    debug("clean up: channels");

    for(struct BaseChannel *cur = &context.channels->base; cur;)
    {
        if(!cur->alive)
        {
            debug("clean uo: removing dead channel");
            struct BaseChannel *next = cur->next;
            teardown_channel((union Channel *) cur, 1);
            cur = next;
            continue;
        }

        -- cur->alive;
        cur = cur->next;
    }
}

#endif // __COMMON_H__
