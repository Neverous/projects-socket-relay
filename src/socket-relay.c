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

// libevent
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

// protocol
#include "protocol/message.h"
#include "protocol/authentication.h"
#include "protocol/channel.h"
#include "relaylistener.h"

#define BUFFER_LIMIT 8192

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
    struct event                *keepalive;

    struct Channel              *channels;
    struct Channel              *free_channels;

    struct RelayListener        *relays;
    uint16_t                    relays_count;
} context;

// SIMPLE LOGGING
inline
static
void debug(const char *fmt, ...)
{
    char buffer[32];
    time_t raw;
    struct tm *local;
    va_list args;

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

// DATA CONNECTION
static
void accept_data_connection(struct evconnlistener *listener,
                            evutil_socket_t fd,
                            struct sockaddr *address,
                            int socklen,
                            void *args);

static
void authenticate_data_connection(struct bufferevent *buffevent, void *args);

static
void read_data_connection(struct bufferevent *buffevent, void *data_channel);

static
void write_data_connection(struct bufferevent *buffevent, void *data_channel);

static
void error_on_data_connection_bufferevent(  struct bufferevent *buffevent,
                                            short events,
                                            void *data_channel);

// RELAY CONNECTION
inline
static
void setup_relay_connections(void);

inline
static
void teardown_relay_connections(void);

static
void accept_relay_connection(   struct evconnlistener *listener,
                                evutil_socket_t fd,
                                struct sockaddr *address,
                                int socklen,
                                void *relay_listener);

static
void error_on_relay_connection_listener(struct evconnlistener *listener,
                                        void *args);

static
void read_relay_connection(struct bufferevent *buffevent, void *data_channel);

static
void write_relay_connection(struct bufferevent *buffevent, void *data_channel);

static
void error_on_relay_connection_bufferevent( struct bufferevent *buffevent,
                                            short events,
                                            void *data_channel);

// CHANNELS
inline
static
void allocate_data_channels(void);

inline
static
struct Channel *request_data_channel(   struct bufferevent *buffevent,
                                        struct sockaddr *address,
                                        uint8_t server_proto,
                                        uint16_t server_port);

inline
static
void setup_data_channel(struct Channel *channel, struct bufferevent *buffevent);

inline
static
void teardown_data_channel(struct Channel *channel, uint8_t close_channel);

inline
static
struct Channel *find_data_channel(const struct AuthenticationHash *token);

// KEEPALIVE
static
void keepalive(evutil_socket_t fd, short event, void *arg);

static
void display_stats(evutil_socket_t fd, short event, void *arg);

static
void cleanup_channels(evutil_socket_t fd, short event, void *arg);

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

    debug("working...");
    event_base_dispatch(context.events);

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


static
void accept_control_connection( struct evconnlistener *listener,
                                evutil_socket_t fd,
                                struct sockaddr *address,
                                int socklen,
                                void *args)
{
    debug("got control connection");
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

    evconnlistener_set_cb(listener, accept_data_connection, NULL);
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
                                        options.password,
                                        context.secret);
    bufferevent_write(  buffevent,
                        &cha,
                        sizeof(cha));
}

static
void error_on_control_connection_listener(  struct evconnlistener *listener,
                                            void *args)
{
    int error = EVUTIL_SOCKET_ERROR();
    debug(  "evconnlistener: %d %s",
            error, evutil_socket_error_to_string(error));

    event_base_loopexit(context.events, NULL);
    return;
}

static
void authenticate_control_connection(struct bufferevent *buffevent, void *args)
{
    debug("authentication: reading data");
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    size_t len      = evbuffer_get_length(input);
    size_t wanted   = sizeof(struct MessageResponse);
    if(len < wanted)
        return;

    struct MessageResponse *res =
        (struct MessageResponse *) evbuffer_pullup(input, wanted);

    if(res->type != RESPONSE)
    {
        debug(  "authentication: invalid message type %s",
                message_get_type_string((struct Message *) res));

        teardown_control_connection();
        return;
    }

    if(!authentication_compare_hash(&context.challenge, &res->response))
    {
        debug("authentication: authentication failed");
        teardown_control_connection();
        return;
    }

    debug("control authenticated");
    struct MessageResponse res2;
    res2.type = RESPONSE;
    authentication_prepare_response(
        &res2.response,
        &res->response,
        options.password,
        context.secret);

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
    debug("control: reading data");
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

    context.alive = 1;
    struct timeval five_seconds = { 5, 0 };
    event_del(context.keepalive);
    event_add(context.keepalive, &five_seconds);
}

inline
static
void process_control_message(   struct bufferevent *buffevent,
                                struct Message *msg)
{
    debug("processing control message");
    switch(msg->type)
    {
        case NOOP:
            debug("NOOP");
            break;

        case ALIVE:
            {
                struct MessageAlive *ali = (struct MessageAlive *) msg;
                debug("ALIVE %d", ali->seq);
                if(context.msg_alive.seq != ali->seq)
                {
                    context.msg_alive.seq = ali->seq;
                    bufferevent_write(  buffevent,
                                        &context.msg_alive,
                                        sizeof(context.msg_alive));
                }
            }
            break;

        case CLOSE_CHANNEL:
            {
                struct MessageCloseChannel *clo =
                    (struct MessageCloseChannel *) msg;

                debug("CLOSE_CHANNEL");
                struct Channel *channel = find_data_channel(&clo->response);
                if(!channel)
                    debug("channel already closed?");

                else
                    teardown_data_channel(channel, 0);
            }
            break;

        case CHALLENGE:
        case RESPONSE:
            {
                debug(  "not yet implemented message received (%s)",
                        message_get_type_string(msg));
            }
            break;

        case OPEN_CHANNEL:
        default:
            {
                debug(  "invalid message received (%s)",
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
        debug("control end of data");
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
void accept_data_connection(struct evconnlistener *listener,
                            evutil_socket_t fd,
                            struct sockaddr *address,
                            int socklen,
                            void *args)
{
    debug("got data connection");
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
        authenticate_data_connection,
        NULL,
        error_on_data_connection_bufferevent,
        NULL);

    bufferevent_enable(buffevent, EV_READ | EV_WRITE);
}

static
void authenticate_data_connection(struct bufferevent *buffevent, void *args)
{
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    size_t len      = evbuffer_get_length(input);
    size_t wanted   = sizeof(struct MessageResponse);
    if(len < sizeof(struct MessageResponse))
        return;

    struct MessageResponse *res =
        (struct MessageResponse *) evbuffer_pullup(input, wanted);

    if(res->type != RESPONSE)
    {
        debug(  "authentication: invalid message type %s",
                message_get_type_string((struct Message *) res));

        bufferevent_free(buffevent);
        return;
    }

    struct Channel *current = find_data_channel(&res->response);
    if(!current)
    {
        debug("authentication: authentication failed");
        bufferevent_free(buffevent);
        return;
    }

    debug("data connection authenticated");
    setup_data_channel(current, buffevent);
    bufferevent_setcb(  buffevent,
                        read_data_connection,
                        write_data_connection,
                        error_on_data_connection_bufferevent,
                        current);

    read_data_connection(buffevent, current);
}

static
void read_data_connection(struct bufferevent *buffevent, void *data_channel)
{
    //debug("data: reading data");
    struct Channel *current = (struct Channel *) data_channel;
    if(evbuffer_get_length(bufferevent_get_output(current->peer_buffers)) < BUFFER_LIMIT)
    {
        struct evbuffer *input  = bufferevent_get_input(buffevent);

        bufferevent_write_buffer(current->peer_buffers, input);
    }
}

static
void write_data_connection(struct bufferevent *buffevent, void *data_channel)
{
    //debug("data: writing data");
    struct Channel *current = (struct Channel *) data_channel;
    if(evbuffer_get_length(bufferevent_get_output(buffevent)) < BUFFER_LIMIT)
    {
        struct evbuffer *input  =
            bufferevent_get_input(current->peer_buffers);

        bufferevent_write_buffer(buffevent, input);
    }
}

static
void error_on_data_connection_bufferevent(  struct bufferevent *buffevent,
                                            short events,
                                            void *data_channel)
{
    if(events & BEV_EVENT_ERROR)
        perror("bufferevent");

    if(events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
        debug("data connection end of data");
        if(data_channel)
            teardown_data_channel((struct Channel *) data_channel, 1);
    }
}

inline
static
void setup_relay_connections(void)
{
    const char *w = options.relay_ports;
    for(context.relays_count = 1;
        w[context.relays_count];
        w[context.relays_count] == ',' ? ++ context.relays_count : *w++);

    if(!context.relays_count)
    {
        debug("missing relay ports!");
        event_base_loopexit(context.events, NULL);
        return;
    }

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

        if(sscanf(w, "%[^:]:%hu:%hu,%n", proto, &port_from, &cur->port, &bytes) != 3)
        {
            debug("invalid relay ports format!");
            event_base_loopexit(context.events, NULL);
            return;
        }

        if(strcmp(proto, "tcp"))
        {
            debug("only tcp supported so far!");
            event_base_loopexit(context.events, NULL);
            return;
        }

        debug("setting up %s %d -> %d", proto, port_from, cur->port);

        cur->proto = 1;
        struct sockaddr_in  relay; memset(&relay, 0, sizeof(relay));
        relay.sin_family        = AF_INET;
        relay.sin_addr.s_addr   = INADDR_ANY;
        relay.sin_port          = htons(port_from);

        cur->tcp_listener = evconnlistener_new_bind(
            context.events,
            accept_relay_connection, cur,
            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
            (struct sockaddr *) &relay, sizeof(relay));

        if(!cur->tcp_listener)
        {
            perror("evconnlistener_new_bind");
            return;
        }

        evconnlistener_set_error_cb(    cur->tcp_listener,
                                        error_on_relay_connection_listener);

        ++ cur;
        w += bytes;
    }
}

inline
static
void teardown_relay_connections(void)
{
    debug("relays teardown");
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
        teardown_data_channel(context.channels, 1);

    free(context.relays);
}

static
void accept_relay_connection(   struct evconnlistener *listener,
                                evutil_socket_t fd,
                                struct sockaddr *address,
                                int socklen,
                                void *relay_listener)
{
    debug("got relay connection");
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
    struct Channel *channel = request_data_channel( buffevent,
                                                    address,
                                                    relay->proto,
                                                    relay->port);
    bufferevent_setcb(
        buffevent,
        NULL,
        NULL,
        error_on_relay_connection_bufferevent,
        channel);
}

static
void error_on_relay_connection_listener(    struct evconnlistener *listener,
                                            void *args)
{
    int error = EVUTIL_SOCKET_ERROR();
    debug( "evconnlistener: %d %s\n",
            error, evutil_socket_error_to_string(error));

    event_base_loopexit(context.events, NULL);
    return;
}

static
void read_relay_connection(struct bufferevent *buffevent, void *data_channel)
{
    //debug("relay: reading data");
    struct Channel *current = (struct Channel *) data_channel;
    if(evbuffer_get_length(bufferevent_get_output(current->channel_buffers)) < BUFFER_LIMIT)
    {
        struct evbuffer *input  = bufferevent_get_input(buffevent);
        bufferevent_write_buffer(current->channel_buffers, input);
    }
}

static
void write_relay_connection(struct bufferevent *buffevent, void *data_channel)
{
    //debug("relay: writing data");
    struct Channel *current = (struct Channel *) data_channel;
    assert(buffevent == current->peer_buffers);

    if(evbuffer_get_length(bufferevent_get_output(buffevent)) < BUFFER_LIMIT)
    {
        struct evbuffer *input  =
            bufferevent_get_input(current->channel_buffers);

        bufferevent_write_buffer(buffevent, input);
    }
}

static
void error_on_relay_connection_bufferevent( struct bufferevent *buffevent,
                                            short events,
                                            void *data_channel)
{
    if(events & BEV_EVENT_ERROR)
        perror("bufferevent");

    if(events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
        debug("relay connection end of data");
        teardown_data_channel((struct Channel *) data_channel, 1);
    }
}

inline
static
void allocate_data_channels(void)
{
    assert(!context.free_channels);
    int32_t count = 8192 / sizeof(struct Channel);
    context.free_channels =
        (struct Channel *) malloc(count * sizeof(struct Channel));
    memset(context.free_channels, 0, count * sizeof(struct Channel));
    struct Channel *cur = context.free_channels;
    for(int c = 0; c < count; ++ c, ++ cur)
    {
        cur->next = cur + 1;
        cur->prev = cur - 1;
    }

    context.free_channels->prev = NULL;
    -- cur;
    cur->next = NULL;
    return;
}

inline
static
struct Channel *request_data_channel(   struct bufferevent *buffevent,
                                        struct sockaddr *address,
                                        uint8_t server_proto,
                                        uint16_t server_port)
{
    if(!context.free_channels)
        allocate_data_channels();

    assert(context.free_channels);
    struct Channel *channel = context.free_channels;
    context.free_channels = context.free_channels->next;
    if(context.free_channels)
        context.free_channels->prev = NULL;

    memset(channel, 0, sizeof(struct Channel));
    channel->next = context.channels;
    if(context.channels)
        context.channels->prev = channel;

    context.channels = channel;
    authentication_prepare_challenge(&channel->token);

    struct MessageOpenChannel ope;
    ope.type    = OPEN_CHANNEL;

    memcpy(&ope.challenge, &channel->token, CHALLENGE_LENGTH);
    ope.port    = server_port;
    ope.proto   = server_proto;

    bufferevent_write(  context.control_buffers,
                        &ope,
                        sizeof(ope));

    channel->peer_buffers = buffevent;
    authentication_prepare_response(&channel->token,
                                    &channel->token,
                                    options.password,
                                    context.secret);

    return channel;
}

inline
static
void setup_data_channel(struct Channel *channel, struct bufferevent *buffevent)
{
    channel->channel_buffers = buffevent;
    bufferevent_setcb(  channel->peer_buffers,
                        read_relay_connection,
                        write_relay_connection,
                        error_on_relay_connection_bufferevent,
                        channel);

    bufferevent_enable(channel->peer_buffers, EV_READ | EV_WRITE);
}

inline
static
void teardown_data_channel(struct Channel *channel, uint8_t close_channel)
{
    assert(channel);
    debug("data channel teardown");
    if(context.channels == channel)
        context.channels = channel->next;

    if(channel->prev)
        channel->prev->next = channel->next;

    if(channel->next)
        channel->next->prev = channel->prev;

    if(channel->channel_buffers)
    {
        bufferevent_free(channel->channel_buffers);
        channel->channel_buffers = 0;
    }

    if(channel->peer_buffers)
    {
        bufferevent_free(channel->peer_buffers);
        channel->peer_buffers = 0;
    }

    channel->prev = NULL;
    channel->next = context.free_channels;
    if(context.free_channels)
    {
        assert(!context.free_channels->prev);
        context.free_channels->prev = channel;
    }

    context.free_channels = channel;

    if(close_channel)
    {
        struct MessageCloseChannel clo;
        clo.type = CLOSE_CHANNEL;
        memcpy(&clo.response, &channel->token, CHALLENGE_LENGTH);
        bufferevent_write(  context.control_buffers,
                            &clo,
                            sizeof(clo));
    }
}

inline
static
struct Channel *find_data_channel(const struct AuthenticationHash *token)
{
    struct Channel *cur = context.channels;
    while(cur && !authentication_compare_hash(&cur->token, token))
        cur = cur->next;

    return cur;
}

static
void keepalive(evutil_socket_t fd, short event, void *arg)
{
    assert(event & EV_TIMEOUT);
    if(!context.control_buffers)
    {
        debug("no connection");
        return;
    }

    if(!context.alive)
    {
        debug("connection down");
        teardown_control_connection();
        return;
    }

    debug("sending alive");
    ++ context.msg_alive.seq;
    bufferevent_write(  context.control_buffers,
                        &context.msg_alive,
                        sizeof(context.msg_alive));

    context.alive = 0;
}

static
void display_stats(evutil_socket_t fd, short event, void *arg)
{
    assert(event & EV_TIMEOUT);

    uint32_t    used_channels   = 0;
    uint32_t    marked_channels = 0;
    uint32_t    free_channels   = 0;
    for(struct Channel *cur = context.channels; cur; cur = cur->next)
    {
        ++ used_channels;
        if(cur->marked == 1)
            marked_channels += cur->marked;
    }

    for(struct Channel *cur = context.free_channels; cur; cur = cur->next)
        ++ free_channels;

    debug("STATS: Channels used/marked: %u/%u, free: %u", used_channels, marked_channels, free_channels);
}

static
void cleanup_channels(evutil_socket_t fd, short event, void *arg)
{
    assert(event & EV_TIMEOUT);
    debug("cleaning up channels");

    for(struct Channel *cur = context.channels; cur;)
    {
        if(cur->marked == 2)
            cur = cur->next;

        else if(cur->channel_buffers && cur->peer_buffers)
        {
            cur->marked = 2;
            cur = cur->next;
        }

        else if(cur->marked == 1)
        {
            debug("removing stalled channel");
            struct Channel *next = cur->next;
            teardown_data_channel(cur, 1);
            cur = next;
        }

        else
        {
            assert(cur->marked == 0);
            cur->marked = 1;
            cur = cur->next;
        }
    }
}
