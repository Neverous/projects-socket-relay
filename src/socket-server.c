/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket-relay.
 * ----------
 *  Server node.
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
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>

// protocol
#include "protocol/message.h"
#include "protocol/authentication.h"
#include "protocol/channel.h"

// Usage options and info
const char *VERSION = "0.1.0";
const char *HELP    = "Usage: socket-server [options]\n\n\
    -h --help                               Display this usage information.\n\
    -v --version                            Display program version.\n\
    -r --relay-host     HOST[=localhost]    Address of the relay.\n\
    -s --host           HOST[=localhost]    Destination address.\n\
    -c --control-port   PORT[=10000]        Control port of the relay.\n\
    -p --password       PASSWORD[=1234]     Password.";

const char *SHORT_OPTIONS           = "hvr:s:c:d:p:";
const struct option LONG_OPTIONS[] =
{
    {"help",            no_argument,        0,  'h'}, // display help and usage
    {"version",         no_argument,        0,  'v'}, // display version
    {"relay-host",      required_argument,  0,  'r'}, // relay address
    {"host",            required_argument,  0,  's'}, // destination address
    {"control-port",    required_argument,  0,  'c'}, // relay control port
    {"password",        required_argument,  0,  'p'}, // password
    {NULL, 0, 0, 0},
};

struct Options
{
    int16_t     control_port;
    const char  *relay_host;
    const char  *host;
    const char  *password;
} options = {
    10000,
    "localhost",
    "localhost",
    "1234",
};

struct Context
{
    struct event_base       *events;
    struct evdns_base       *dns;
    struct bufferevent      *control_buffers;

    struct AuthenticationHash   challenge;
    uint8_t                     secret;
    struct MessageAlive         msg_alive;
    uint8_t                     alive;
    struct event                *keepalive;

    struct Channel              *channels;
    struct Channel              *free_channels;
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
void authenticate_control_connection(struct bufferevent *buffevent, void *args);

static
void authenticate_relay_control_connection( struct bufferevent *buffevent,
                                            void *args);

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
void read_data_connection(struct bufferevent *buffevent, void *data_channel);

static
void error_on_data_connection_bufferevent(  struct bufferevent *buffevent,
                                            short events,
                                            void *data_channel);

// RELAY CONNECTION
inline
static
void teardown_relay_connections(void);

static
void read_relay_connection(struct bufferevent *buffevent, void *data_channel);

static
void error_on_relay_connection_bufferevent( struct bufferevent *buffevent,
                                            short events,
                                            void *data_channels);

// CHANNELS
inline
static
void allocate_data_channels(void);

inline
static
struct Channel *setup_data_channel(struct MessageOpenChannel *ope);

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

            case 'v': printf("socket-server %s\n", VERSION);
                return 0;

            case 'r': options.relay_host = optarg;
                break;

            case 's': options.host = optarg;
                break;

            case 'c': options.control_port = atoi(optarg);
                break;

            case 'p': options.password = optarg;
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

    context.dns = evdns_base_new(context.events, 1);

    context.control_buffers = bufferevent_socket_new(
        context.events,
        -1,
        BEV_OPT_CLOSE_ON_FREE);

    if(!context.control_buffers)
    {
        perror("bufferevent_socket_new");
        return 3;
    }

    bufferevent_setwatermark(   context.control_buffers,
                                EV_READ | EV_WRITE,
                                sizeof(struct Message),
                                8192);

    bufferevent_setcb(  context.control_buffers,
                        authenticate_control_connection,
                        NULL,
                        error_on_control_connection_bufferevent,
                        NULL);

    bufferevent_enable(context.control_buffers, EV_READ | EV_WRITE);
    bufferevent_socket_connect_hostname(
        context.control_buffers,
        context.dns,
        AF_UNSPEC,
        options.relay_host,
        options.control_port);

    struct timeval timeout = { 30, 0 };
    context.msg_alive.type = ALIVE;
    context.alive = 1;
    context.keepalive = event_new(  context.events,
                                    -1,
                                    EV_TIMEOUT | EV_PERSIST,
                                    keepalive,
                                    NULL);

    event_add(context.keepalive, &timeout);

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
void authenticate_control_connection(struct bufferevent *buffevent, void *args)
{
    debug("authentication: reading data");
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    size_t len      = evbuffer_get_length(input);
    size_t wanted   = sizeof(struct MessageChallenge);
    if(len < wanted)
        return;

    struct MessageChallenge *cha =
        (struct MessageChallenge *) evbuffer_pullup(input, wanted);

    if(cha->type != CHALLENGE)
    {
        debug(  "authentication: invalid message type %s",
                message_get_type_string((struct Message *) cha));

        teardown_control_connection();
        return;
    }

    context.secret = authentication_get_secret_byte(&cha->challenge);
    struct MessageResponse res;
    res.type = RESPONSE;
    authentication_prepare_response(
        &res.response,
        &cha->challenge,
        options.password,
        context.secret);

    evbuffer_drain(input, wanted);
    authentication_prepare_response(
        &context.challenge,
        &res.response,
        options.password,
        context.secret);

    bufferevent_write(  buffevent,
                        &res,
                        sizeof(res));

    bufferevent_setcb(  buffevent,
                        authenticate_relay_control_connection,
                        NULL,
                        error_on_control_connection_bufferevent,
                        NULL);

    authenticate_relay_control_connection(buffevent, args);
}

static
void authenticate_relay_control_connection( struct bufferevent *buffevent,
                                            void *args)
{
    debug("relay authentication: reading data");
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    size_t len      = evbuffer_get_length(input);
    size_t wanted   = sizeof(struct MessageResponse);
    if(len < wanted)
        return;

    struct MessageResponse *res =
        (struct MessageResponse *) evbuffer_pullup(input, wanted);

    if(res->type != RESPONSE)
    {
        debug(  "relay authentication: invalid message type %s",
                message_get_type_string((struct Message *) res));

        teardown_control_connection();
        return;
    }

    if(!authentication_compare_hash(&context.challenge, &res->response))
    {
        debug("relay authentication: authentication failed");
        teardown_control_connection();
        return;
    }

    evbuffer_drain(input, wanted);
    debug("control authenticated");

    bufferevent_setcb(  buffevent,
                        read_control_connection,
                        NULL,
                        error_on_control_connection_bufferevent,
                        NULL);

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

        case OPEN_CHANNEL:
            {
                struct Channel *channel = setup_data_channel((struct MessageOpenChannel *) msg);
                if(!channel)
                    debug("couldn't allocate channel");
            }
            break;

        case CHALLENGE:
        case RESPONSE:
            {
                debug(  "not yet implemented message received (%s)",
                        message_get_type_string(msg));
            }
            break;

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

    event_base_loopexit(context.events, NULL);
}

static
void read_data_connection(struct bufferevent *buffevent, void *data_channel)
{
    //debug("data: reading data");
    struct Channel *current = (struct Channel *) data_channel;
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    bufferevent_write_buffer(current->peer_buffers, input);
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
void teardown_relay_connections(void)
{
    debug("relays teardown");
    while(context.channels)
        teardown_data_channel(context.channels, 1);
}

static
void read_relay_connection(struct bufferevent *buffevent, void *data_channel)
{
    //debug("relay: reading data");
    struct Channel *current = (struct Channel *) data_channel;
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    bufferevent_write_buffer(current->channel_buffers, input);
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
}

inline
static
struct Channel *setup_data_channel(struct MessageOpenChannel *ope)
{
    debug("creating new data channel");
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
    authentication_prepare_response(&channel->token,
                                    &ope->challenge,
                                    options.password,
                                    context.secret);

    channel->peer_buffers = bufferevent_socket_new(
        context.events,
        -1,
        BEV_OPT_CLOSE_ON_FREE);

    if(!channel->peer_buffers)
    {
        perror("bufferevent_socket_new");
        teardown_data_channel(channel, 1);
        return 0;
    }

    bufferevent_setwatermark(   channel->peer_buffers,
                                EV_READ | EV_WRITE,
                                sizeof(struct Message),
                                8192);

    bufferevent_setcb(  channel->peer_buffers,
                        read_relay_connection,
                        NULL,
                        error_on_relay_connection_bufferevent,
                        channel);

    bufferevent_enable(channel->peer_buffers, EV_READ | EV_WRITE);
    bufferevent_socket_connect_hostname(channel->peer_buffers,
                                        context.dns,
                                        AF_UNSPEC,
                                        options.host,
                                        ope->port);

    channel->channel_buffers = bufferevent_socket_new(
        context.events,
        -1,
        BEV_OPT_CLOSE_ON_FREE);

    if(!channel->channel_buffers)
    {
        perror("bufferevent_socket_new");
        teardown_data_channel(channel, 1);
        return 0;
    }

    bufferevent_setwatermark(   channel->channel_buffers,
                                EV_READ | EV_WRITE,
                                sizeof(struct Message),
                                8192);

    bufferevent_setcb(  channel->channel_buffers,
                        read_data_connection,
                        NULL,
                        error_on_data_connection_bufferevent,
                        channel);

    bufferevent_enable(channel->channel_buffers, EV_READ | EV_WRITE);
    bufferevent_socket_connect_hostname(channel->channel_buffers,
                                        context.dns,
                                        AF_UNSPEC,
                                        options.relay_host,
                                        options.control_port);

    struct MessageResponse res;
    res.type = RESPONSE;
    memcpy(&res.response, &channel->token, CHALLENGE_LENGTH);
    bufferevent_write(  channel->channel_buffers,
                        &res,
                        sizeof(res));

    return channel;
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

    channel->prev = 0;
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
    if(!context.alive || !context.control_buffers)
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
