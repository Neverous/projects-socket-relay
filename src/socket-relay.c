/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket-relay.
 * ----------
 *  Relay node.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

// libevent
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

// protocol
#include "protocol/message.h"
#include "protocol/authentication.h"
#include "protocol/channel.h"
#include "relaylistener.h"

#define BUFFER_LIMIT 262144

// Usage options and info
const char *VERSION = "0.1.0";
const char *HELP    = "Usage: socket-relay [options]\n\n\
    -h --help                                               Display this usage information.\n\
    -v --version                                            Display version.\n\
    -c --control-port   PORT[=10000]                        Control port.\n\
    -r --relay-ports    PORTS[=tcp:10080:80,tcp:10022:22]   Relay ports.\n\
    -p --password       PASSWORD[=1234]                     Password.";

const char *SHORT_OPTIONS           = "hvc:r:p:";
const struct option LONG_OPTIONS[] =
{
    {"help",            no_argument,        0, 'h'}, // display help and usage
    {"version",         no_argument,        0, 'v'}, // display version
    {"control-port",    required_argument,  0, 'c'}, // control port
    {"relay-ports",     required_argument,  0, 'r'}, // relay ports
    {"password",        required_argument,  0, 'p'}, // password
    {NULL, 0, 0, 0},
};

struct Options
{
    int16_t     control_port;
    const char  *relay_ports;
    const char  *password;
} options = {
    10000,
    "tcp:10080:80,tcp:10022:22",
    "1234",
};

struct Context
{
    struct event_base       *events;
    struct evconnlistener   *listener;
    struct bufferevent      *control_buffers;

    struct AuthenticationHash   challenge;
    uint8_t                     secret;
    struct MessageAlive         msg_alive;
    uint8_t                     alive;
    uint32_t                    ping;
    uint64_t                    last_alive;
    struct event                *keepalive;

    union Channel           *channels;
    union Channel           *free_channels;

    struct RelayListener    *relays;
    uint16_t                relays_count;
} context;

// SIMPLE LOGGING
inline
static
void debug(const char *fmt, ...);

// CONTROL CONNECTION
static
void accept_control_connection( struct evconnlistener *listener,
                                evutil_socket_t fd,
                                struct sockaddr *address,
                                int socklet,
                                void *args);

inline
static
void setup_control_connection(struct bufferevent *buffevent);

static
void error_on_control_connection_listener(  struct evconnlistener *listener,
                                            void *args);

static
void authenticate_control_connection(struct bufferevent *buffevent, void *args);

static
void read_control_connection(struct bufferevent *buffevent, void *args);

inline
static
void process_control_message(   struct bufferevent *buffevent,
                                struct Message *msg);

static
void error_on_control_connection_bufferevent(   struct bufferevent *buffevent,
                                                short events,
                                                void *args);

inline
static
void teardown_control_connection(void);

// CHANNEL CONNECTION
static
void accept_tcp_channel_connection( struct evconnlistener *listener,
                                    evutil_socket_t fd,
                                    struct sockaddr *address,
                                    int socklen,
                                    void *args);

static
void authenticate_tcp_channel_connection(   struct bufferevent *buffevent,
                                            void *args);

static
void read_tcp_channel_connection(struct bufferevent *buffevent, void *channel);

static
void write_tcp_channel_connection(struct bufferevent *buffevent, void *channel);

static
void error_on_tcp_channel_connection_bufferevent(
    struct bufferevent *buffevent,
    short events,
    void *channel);

/*static
void read_udp_channel_connection(evutil_socket_t fd, short events, void *arg);

static
void error_on_udp_channel_connection(   evutil_socket_t fd,
                                        short events,
                                        void *args);
*/

// RELAY CONNECTION
inline
static
void setup_relay_connections(void);

inline
static
void teardown_relay_connections(void);

static
void accept_tcp_peer_connection(struct evconnlistener *listener,
                                evutil_socket_t fd,
                                struct sockaddr *address,
                                int socklen,
                                void *relay_listener);

static
void error_on_tcp_peer_connection_listener( struct evconnlistener *listener,
                                            void *args);

static
void read_tcp_peer_connection(struct bufferevent *buffevent, void *channel);

static
void write_tcp_peer_connection(struct bufferevent *buffevent, void *channel);

static
void error_on_tcp_peer_connection_bufferevent(  struct bufferevent *buffevent,
                                                short events,
                                                void *channel);

/*static
void read_udp_peer_connection(  evutil_socket_t fd,
                                short events,
                                void *channel);

inline
static
void error_on_udp_peer_connection(  evutil_socket_t fd,
                                    short events,
                                    void *channel);
*/

// OTHER
/*static
void read_esp_connection(evutil_socket_t fd, short events, void *args);

inline
static
void error_on_esp_connection(evutil_socket_t fd, short events, void *args);
*/

// CHANNELS
inline
static
void allocate_channels(void);

inline
static
union Channel *request_channel(uint8_t proto, uint16_t port);

inline
static
void teardown_channel(union Channel *channel, uint8_t close_channel);

inline
static
union Channel *find_channel(const struct AuthenticationHash *token);

// EVENTS
static
void keepalive(evutil_socket_t fd, short events, void *arg);

static
void display_stats(evutil_socket_t fd, short events, void *arg);

static
void cleanup_channels(evutil_socket_t fd, short events, void *arg);

int32_t main(int32_t argc, char **argv)
{
    int32_t o;
    while((o = getopt_long(argc, argv, SHORT_OPTIONS, LONG_OPTIONS, 0)) != -1)
        switch(o)
        {
            case 'h': puts(HELP);
                return 0;

            case 'v': printf("socket-relay %s\n", VERSION);
                return 0;

            case 'c': options.control_port = atoi(optarg);
                break;

            case 'p': options.password = optarg;
                break;

            case 'r': options.relay_ports = optarg;
                break;

            case '?': fputs(HELP, stderr);
                return 1;
        }

    context.events = event_base_new();
    if(!context.events)
    {
        perror("event_base_new");
        return 2;
    }

    struct sockaddr_in  relay; memset(&relay, 0, sizeof(relay));
    relay.sin_family        = AF_INET;
    relay.sin_addr.s_addr   = INADDR_ANY;
    relay.sin_port          = htons(options.control_port);

    context.listener = evconnlistener_new_bind(
        context.events,
        accept_control_connection, NULL,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr *) &relay, sizeof(relay));

    if(!context.listener)
    {
        perror("evconnlistener_new_bind");
        return 3;
    }

    evconnlistener_set_error_cb(    context.listener,
                                    error_on_control_connection_listener);

    struct timeval five_seconds = { 5, 0 };
    context.msg_alive.type = ALIVE;
    context.alive = 1;
    context.keepalive = event_new(  context.events,
                                    -1,
                                    EV_TIMEOUT | EV_PERSIST,
                                    keepalive,
                                    NULL);

    event_add(context.keepalive, &five_seconds);

    struct timeval thirty_seconds = { 30, 0 };
    struct event *stats = event_new(context.events,
                                    -1,
                                    EV_TIMEOUT | EV_PERSIST,
                                    display_stats,
                                    NULL);

    event_add(stats, &thirty_seconds);

    struct timeval ten_seconds = { 10, 0 };
    struct event *cleanup = event_new(  context.events,
                                        -1,
                                        EV_TIMEOUT | EV_PERSIST,
                                        cleanup_channels,
                                        NULL);

    event_add(cleanup, &ten_seconds);

    debug("main: waiting for control connection");
    event_base_dispatch(context.events);

    debug("main: shutting down");
    event_del(stats);
    event_free(stats);
    stats = 0;

    event_del(cleanup);
    event_free(cleanup);
    cleanup = 0;

    event_del(context.keepalive);
    event_free(context.keepalive);
    context.keepalive = 0;
    return 0;
}

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

static
void accept_control_connection( struct evconnlistener *listener,
                                evutil_socket_t fd,
                                struct sockaddr *address,
                                int socklen,
                                void *args)
{
    assert(address->sa_family == AF_INET);
    struct sockaddr_in *ipv4 = (struct sockaddr_in *) address;
    char buffer[INET_ADDRSTRLEN];
    debug(  "control connection: from %s",
            inet_ntop(AF_INET, &(ipv4->sin_addr), buffer, INET_ADDRSTRLEN));

    int32_t one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    context.control_buffers = bufferevent_socket_new(
        context.events,
        fd,
        BEV_OPT_CLOSE_ON_FREE);

    if(!context.control_buffers)
    {
        perror("bufferevent_socket_new");
        event_base_loopexit(context.events, NULL);
        return;
    }

    bufferevent_setcb(  context.control_buffers,
                        authenticate_control_connection,
                        NULL,
                        error_on_control_connection_bufferevent,
                        NULL);

    bufferevent_setwatermark(   context.control_buffers,
                                EV_READ | EV_WRITE,
                                sizeof(struct Message), BUFFER_LIMIT);

    bufferevent_enable(context.control_buffers, EV_READ | EV_WRITE);

    // disable new connections while authenticating
    evconnlistener_set_cb(listener, NULL, NULL);
    setup_control_connection(context.control_buffers);
}

inline
static
void setup_control_connection(struct bufferevent *buffevent)
{
    struct MessageChallenge cha;
    cha.type = CHALLENGE;
    authentication_prepare_challenge(&cha.challenge);
    context.secret = authentication_get_secret_byte(&cha.challenge);
    authentication_prepare_response(    &context.challenge,
                                        &cha.challenge,
                                        options.password);
    bufferevent_write(  buffevent,
                        &cha,
                        sizeof(cha));
}

static
void error_on_control_connection_listener(  struct evconnlistener *listener,
                                            void *args)
{
    int error = EVUTIL_SOCKET_ERROR();
    debug(  "control connection: evconnlistener error %d %s",
            error, evutil_socket_error_to_string(error));

    event_base_loopexit(context.events, NULL);
    return;
}

static
void authenticate_control_connection(struct bufferevent *buffevent, void *args)
{
    debug("control connection: authentication reading data");
    context.alive = 1;
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    size_t len      = evbuffer_get_length(input);
    size_t wanted   = sizeof(struct MessageResponse);
    if(len < wanted)
        return;

    debug("control connection: authentication checking message");
    struct MessageResponse *res =
        (struct MessageResponse *) evbuffer_pullup(input, wanted);

    if(res->type != RESPONSE)
    {
        debug(  "control connection: invalid authentication message %s",
                message_get_type_string((struct Message *) res));

        teardown_control_connection();
        return;
    }

    if(!authentication_compare_hash(&context.challenge, &res->response))
    {
        debug("control connection: authentication failed");
        teardown_control_connection();
        return;
    }

    debug("control connection: authenticated");
    struct MessageResponse res2;
    res2.type = RESPONSE;
    authentication_prepare_response(
        &res2.response,
        &res->response,
        options.password);

    evbuffer_drain(input, wanted);
    bufferevent_write(  buffevent,
                        &res2,
                        sizeof(res2));

    bufferevent_setcb(  buffevent,
                        read_control_connection,
                        NULL,
                        error_on_control_connection_bufferevent,
                        NULL);

    setup_relay_connections();
    read_control_connection(buffevent, args);
}

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

inline
static
void process_control_message(struct bufferevent *buffevent, struct Message *msg)
{
    debug("control connection: processing message");
    switch(msg->type)
    {
        case NOOP:
            debug("control connection: message NOOP");
            break;

        case ALIVE:
            {
                struct MessageAlive *ali = (struct MessageAlive *) msg;
                debug("control connection: message ALIVE(%d)", ali->seq);
                if(context.msg_alive.seq != ali->seq)
                {
                    context.msg_alive.seq = ali->seq;
                    bufferevent_write(  buffevent,
                                        &context.msg_alive,
                                        sizeof(context.msg_alive));
                }

                else
                {
                    struct timespec cur; clock_gettime(CLOCK_MONOTONIC, &cur);
                    context.ping =
                        (
                                context.ping
                            -   context.last_alive
                            +   cur.tv_sec * 1000LL
                            +   (cur.tv_nsec + 999999LL) / 1000000LL
                        ) / 4;

                    debug("control connection: estimated ping %ums",
                        context.ping);
                }
            }
            break;

        case CLOSE_CHANNEL:
            {
                struct MessageCloseChannel *clo =
                    (struct MessageCloseChannel *) msg;

                debug("control connection: message CLOSE_CHANNEL");
                union Channel *channel =
                    find_channel(&clo->response);

                if(!channel)
                    debug("control connection: channel doesn't exist");

                else
                    teardown_channel(channel, 0);
            }
            break;

        case CHALLENGE:
        case RESPONSE:
            {
                debug(  "control connection: not yet implemented message (%s)",
                        message_get_type_string(msg));
            }
            break;

        case OPEN_CHANNEL:
        default:
            {
                debug(  "control connection: invalid message (%s)",
                        message_get_type_string(msg));
            }
            break;
    }
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

inline
static
void teardown_control_connection(void)
{
    // disconnect everything and close...
    teardown_relay_connections();

    bufferevent_free(context.control_buffers);
    context.control_buffers = 0;
    evconnlistener_free(context.listener);
    context.listener = 0;

    event_base_loopexit(context.events, NULL);
}

static
void accept_tcp_channel_connection( struct evconnlistener *listener,
                                    evutil_socket_t fd,
                                    struct sockaddr *address,
                                    int socklen,
                                    void *args)
{
    assert(address->sa_family == AF_INET);
    struct sockaddr_in *ipv4 = (struct sockaddr_in *) address;
    char buffer[INET_ADDRSTRLEN];
    debug(  "tcp channel connection: from %s",
            inet_ntop(AF_INET, &(ipv4->sin_addr), buffer, INET_ADDRSTRLEN));

    int32_t one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct bufferevent *buffevent = bufferevent_socket_new(
        context.events,
        fd,
        BEV_OPT_CLOSE_ON_FREE);

    if(!buffevent)
    {
        perror("bufferevent_socket_new");
        event_base_loopexit(context.events, NULL);
        return;
    }

    bufferevent_setwatermark(buffevent, EV_READ | EV_WRITE, 0, BUFFER_LIMIT);
    bufferevent_setcb(
        buffevent,
        authenticate_tcp_channel_connection,
        NULL,
        error_on_tcp_channel_connection_bufferevent,
        NULL);

    bufferevent_enable(buffevent, EV_READ | EV_WRITE);
}

static
void authenticate_tcp_channel_connection(   struct bufferevent *buffevent,
                                            void *args)
{
    debug("tcp channel connection: authentication reading data");
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    size_t len      = evbuffer_get_length(input);
    size_t wanted   = sizeof(struct MessageResponse);
    if(len < wanted)
        return;

    debug("tcp channel connection: authentication checking message");
    struct MessageResponse *res =
        (struct MessageResponse *) evbuffer_pullup(input, wanted);

    if(res->type != RESPONSE)
    {
        debug(  "tcp channel connection: invalid authentication message %s",
                message_get_type_string((struct Message *) res));

        bufferevent_free(buffevent);
        return;
    }

    union Channel *current = find_channel(&res->response);
    if(!current)
    {
        debug("tcp channel connection: authentication failed");
        bufferevent_free(buffevent);
        return;
    }

    debug("tcp channel connection: authenticated");
    assert(current->base.proto == IPPROTO_TCP);
    current->tcp.channel_buffers = buffevent;
    bufferevent_setcb(  current->tcp.peer_buffers,
                        read_tcp_peer_connection,
                        write_tcp_peer_connection,
                        error_on_tcp_peer_connection_bufferevent,
                        current);

    bufferevent_enable(current->tcp.peer_buffers, EV_READ | EV_WRITE);
    bufferevent_setcb(  buffevent,
                        read_tcp_channel_connection,
                        write_tcp_channel_connection,
                        error_on_tcp_channel_connection_bufferevent,
                        current);

    read_tcp_channel_connection(buffevent, current);
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

inline
static
void setup_relay_connections(void)
{
    const char *w = options.relay_ports;
    for(context.relays_count = 1;
        w[context.relays_count];
        w[context.relays_count] == ',' ? ++ context.relays_count : *w ++);

    if(!context.relays_count)
    {
        debug("relay connections: missing ports");
        event_base_loopexit(context.events, NULL);
        return;
    }

    debug("relay connections: setting up channel ports");
    evconnlistener_set_cb(context.listener, accept_tcp_channel_connection, NULL);

    debug("relay connections: setting up %d relay ports", context.relays_count);
    context.relays =
        (struct RelayListener *) malloc(
            context.relays_count * sizeof(struct RelayListener));

    w = options.relay_ports;
    struct RelayListener *cur = context.relays;
    for(int c = 0; c < context.relays_count; ++ c)
    {
        char        proto[4];
        uint16_t    port_from;
        int32_t     bytes;

        if(sscanf(w, "%[^:]:%hu:%hu,%n", proto, &port_from, &cur->port, &bytes)
            != 3)
        {
            debug("relay connections: invalid relay ports format");
            event_base_loopexit(context.events, NULL);
            return;
        }

        if(!strcmp(proto, "tcp"))
        {
            debug("setting up tcp relay %d -> %d", port_from, cur->port);
            cur->proto = IPPROTO_TCP;
            struct sockaddr_in  relay; memset(&relay, 0, sizeof(relay));
            relay.sin_family        = AF_INET;
            relay.sin_addr.s_addr   = INADDR_ANY;
            relay.sin_port          = htons(port_from);

            cur->tcp_listener = evconnlistener_new_bind(
                context.events,
                accept_tcp_peer_connection, cur,
                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                (struct sockaddr *) &relay, sizeof(relay));

            if(!cur->tcp_listener)
            {
                perror("evconnlistener_new_bind");
                return;
            }

            evconnlistener_set_error_cb(cur->tcp_listener,
                                        error_on_tcp_peer_connection_listener);

            ++ cur;
            w += bytes;
        }

        else
        {
            debug("relay connections: unsupported protocol %s", proto);
            event_base_loopexit(context.events, NULL);
            return;
        }
    }
}

inline
static
void teardown_relay_connections(void)
{
    debug("relay connections: teardown");
    struct RelayListener *cur = context.relays;
    for(int c = 0; c < context.relays_count; ++ c)
    {
        assert(cur->proto == 1);
        evconnlistener_free(cur->tcp_listener);
        cur->tcp_listener = 0;
        cur->proto = 0;
        ++ cur;
    }

    while(context.channels)
        teardown_channel(context.channels, 1);

    free(context.relays);
}

static
void accept_tcp_peer_connection(struct evconnlistener *listener,
                                evutil_socket_t fd,
                                struct sockaddr *address,
                                int socklen,
                                void *relay_listener)
{
    assert(address->sa_family == AF_INET);
    struct sockaddr_in *ipv4 = (struct sockaddr_in *) address;
    char buffer[INET_ADDRSTRLEN];
    debug(  "tcp peer connection: from %s",
            inet_ntop(AF_INET, &(ipv4->sin_addr), buffer, INET_ADDRSTRLEN));

    int32_t one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    struct bufferevent *buffevent = bufferevent_socket_new(
        context.events,
        fd,
        BEV_OPT_CLOSE_ON_FREE);

    if(!buffevent)
    {
        perror("bufferevent_socket_new");
        event_base_loopexit(context.events, NULL);
        return;
    }

    bufferevent_setwatermark(buffevent, EV_READ | EV_WRITE, 0, BUFFER_LIMIT);

    struct RelayListener *relay = (struct RelayListener *) relay_listener;
    union Channel *channel = request_channel(relay->proto, relay->port);
    channel->tcp.peer_buffers = buffevent;
    bufferevent_setcb(
        buffevent,
        NULL,
        NULL,
        error_on_tcp_peer_connection_bufferevent,
        channel);
}

static
void error_on_tcp_peer_connection_listener( struct evconnlistener *listener,
                                            void *args)
{
    int error = EVUTIL_SOCKET_ERROR();
    debug( "evconnlistener: %d %s\n",
            error, evutil_socket_error_to_string(error));

    event_base_loopexit(context.events, NULL);
    return;
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
union Channel *request_channel(uint8_t proto, uint16_t port)
{
    debug("channel: request %d %d", proto, port);
    if(!context.free_channels)
        allocate_channels();

    assert(context.free_channels);
    union Channel *channel = context.free_channels;
    context.free_channels = (union Channel *) context.free_channels->base.next;
    if(context.free_channels)
        context.free_channels->base.prev = NULL;

    memset(channel, 0, sizeof(union Channel));
    channel->base.next = &context.channels->base;
    if(context.channels)
        context.channels->base.prev = &channel->base;

    context.channels = channel;
    channel->base.proto = proto;
    authentication_prepare_challenge(&channel->base.token);

    struct MessageOpenChannel ope;
    ope.type    = OPEN_CHANNEL;

    memcpy(&ope.challenge, &channel->base.token, CHALLENGE_LENGTH);
    ope.port    = htons(port);
    ope.proto   = proto;

    bufferevent_write(  context.control_buffers,
                        &ope,
                        sizeof(ope));

    authentication_prepare_response(&channel->base.token,
                                    &channel->base.token,
                                    options.password);

    channel->base.alive = 2;
    return channel;
}

inline
static
void teardown_channel(union Channel *channel, uint8_t close_channel)
{
    assert(channel);
    debug("channel: teardown");
    if(context.channels == channel)
        context.channels = (union Channel *) channel->base.next;

    if(channel->base.prev)
        channel->base.prev->next = channel->base.next;

    if(channel->base.next)
        channel->base.next->prev = channel->base.prev;

    switch(channel->base.proto)
    {
        case IPPROTO_TCP:
            {
                if(channel->tcp.channel_buffers)
                {
                    bufferevent_free(channel->tcp.channel_buffers);
                    channel->tcp.channel_buffers = 0;
                }

                if(channel->tcp.peer_buffers)
                {
                    bufferevent_free(channel->tcp.peer_buffers);
                    channel->tcp.peer_buffers = 0;
                }
            }
            break;

        default:
            debug(  "channel: not yet implemented protocol %d",
                    channel->base.proto);
            break;
    }

    channel->base.prev = NULL;
    channel->base.next = &context.free_channels->base;
    if(context.free_channels)
    {
        assert(!context.free_channels->base.prev);
        context.free_channels->base.prev = &channel->base;
    }

    context.free_channels = channel;
    if(close_channel)
    {
        debug("channel: sending CLOSE_CHANNEL");
        struct MessageCloseChannel clo;
        clo.type = CLOSE_CHANNEL;
        memcpy(&clo.response, &channel->base.token, CHALLENGE_LENGTH);
        bufferevent_write(  context.control_buffers,
                            &clo,
                            sizeof(clo));
    }
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

static
void keepalive(evutil_socket_t fd, short events, void *arg)
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
void display_stats(evutil_socket_t fd, short events, void *arg)
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
void cleanup_channels(evutil_socket_t fd, short events, void *arg)
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
