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

// CONTROLL CONNECTION

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

// KEEPALIVE
static
void keepalive(evutil_socket_t fd, short event, void *arg);

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

    struct evdns_base *dns;
    dns = evdns_base_new(context.events, 1);

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
                                EV_READ,
                                sizeof(struct Message),
                                4096);

    bufferevent_setcb(  context.control_buffers,
                        authenticate_control_connection,
                        NULL,
                        error_on_control_connection_bufferevent,
                        NULL);

    bufferevent_enable(context.control_buffers, EV_READ | EV_WRITE);
    bufferevent_socket_connect_hostname(
        context.control_buffers,
        dns,
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

    debug("working...");
    event_base_dispatch(context.events);

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

        case CHALLENGE:
        case RESPONSE:
        case OPEN_CHANNEL:
        case CLOSE_CHANNEL:
        default:
            {
                debug(  "Not yet implemented message received (%s)",
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
    //teardown_relay_connections();

    bufferevent_free(context.control_buffers);
    context.control_buffers = 0;

    event_base_loopexit(context.events, NULL);
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
