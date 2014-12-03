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
#include <unistd.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

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

#define BUFFER_LIMIT 262144

// Usage options and info
const char *VERSION = "0.1.0";
const char *HELP    = "Usage: socket-server [options]\n\n\
    -h --help                               Display this usage information.\n\
    -v --version                            Display program version.\n\
    -r --relay-host     HOST[=localhost]    Address of the relay.\n\
    -s --host           HOST[=localhost]    Destination address.\n\
    -c --control-port   PORT[=10000]        Control port of the relay.\n\
    -p --password       PASSWORD[=1234]     Password.";

const char *SHORT_OPTIONS           = "hvr:s:c:p:";
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
    uint32_t                    ping;
    uint64_t                    last_alive;
    struct event                *keepalive;

    union Channel   *channels;
    union Channel   *free_channels;
} context;

// SIMPLE LOGGING
inline
static
void debug(const char *fmt, ...);

// CONTROL CONNECTION
static
void authenticate_control_connection(struct bufferevent *buffevent, void *args);

static
void authenticate_mutual_control_connection(struct bufferevent *buffevent,
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

// CHANNEL CONNECTION
static
void read_tcp_channel_connection(   struct bufferevent *buffevent,
                                    void *channel);

static
void write_tcp_channel_connection(  struct bufferevent *buffevent,
                                    void *channel);

static
void error_on_tcp_channel_connection_bufferevent(
    struct bufferevent *buffevent,
    short events,
    void *channel);

static
void read_udp_channel_connection(   evutil_socket_t fd,
                                    short events,
                                    void *channel);

inline
static
void error_on_udp_channel_connection(   evutil_socket_t fd,
                                        short events,
                                        void *channel);

// RELAY CONNECTION
inline
static
void teardown_relay_connections(void);

static
void read_tcp_peer_connection(  struct bufferevent *buffevent,
                                void *channel);

static
void write_tcp_peer_connection( struct bufferevent *buffevent,
                                void *channel);

static
void error_on_tcp_peer_connection_bufferevent(  struct bufferevent *buffevent,
                                                short events,
                                                void *channels);

static
void read_udp_peer_connection(  evutil_socket_t fd,
                                short events,
                                void *channel);

inline
static
void error_on_udp_peer_connection(  evutil_socket_t fd,
                                    short events,
                                    void *channel);

// CHANNELS
inline
static
void allocate_channels(void);

inline
static
union Channel *setup_channel(struct MessageOpenChannel *ope);

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

    context.control_buffers = bufferevent_socket_new(   context.events,
                                                        -1,
                                                        BEV_OPT_CLOSE_ON_FREE);

    int32_t one = 1;
    setsockopt( bufferevent_getfd(context.control_buffers),
                IPPROTO_TCP,
                TCP_NODELAY,
                &one,
                sizeof(one));

    if(!context.control_buffers)
    {
        perror("bufferevent_socket_new");
        return 3;
    }

    bufferevent_setwatermark(   context.control_buffers,
                                EV_READ | EV_WRITE,
                                sizeof(struct Message),
                                BUFFER_LIMIT);

    bufferevent_setcb(  context.control_buffers,
                        authenticate_control_connection,
                        NULL,
                        error_on_control_connection_bufferevent,
                        NULL);

    bufferevent_enable(context.control_buffers, EV_READ | EV_WRITE);
    bufferevent_socket_connect_hostname(context.control_buffers,
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

    debug("main: connecting");
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
void authenticate_control_connection(struct bufferevent *buffevent, void *args)
{
    debug("control connection: authentication reading data");
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    size_t len      = evbuffer_get_length(input);
    size_t wanted   = sizeof(struct MessageChallenge);
    if(len < wanted)
        return;

    debug("control connection: authentication checking message");
    struct MessageChallenge *cha =
        (struct MessageChallenge *) evbuffer_pullup(input, wanted);

    if(cha->type != CHALLENGE)
    {
        debug(  "control connection: invalid authentication message %s",
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
        options.password);

    evbuffer_drain(input, wanted);
    authentication_prepare_response(
        &context.challenge,
        &res.response,
        options.password);

    bufferevent_write(  buffevent,
                        &res,
                        sizeof(res));

    bufferevent_setcb(  buffevent,
                        authenticate_mutual_control_connection,
                        NULL,
                        error_on_control_connection_bufferevent,
                        NULL);

    authenticate_mutual_control_connection(buffevent, args);
}

static
void authenticate_mutual_control_connection( struct bufferevent *buffevent,
                                            void *args)
{
    debug("control connection: mutual authentication reading data");
    struct evbuffer *input  = bufferevent_get_input(buffevent);

    size_t len      = evbuffer_get_length(input);
    size_t wanted   = sizeof(struct MessageResponse);
    if(len < wanted)
        return;

    debug("control connection: mutual authentication checking message");
    struct MessageResponse *res =
        (struct MessageResponse *) evbuffer_pullup(input, wanted);

    if(res->type != RESPONSE)
    {
        debug(  "control connection: invalid mutual authentication message %s",
                message_get_type_string((struct Message *) res));

        teardown_control_connection();
        return;
    }

    if(!authentication_compare_hash(&context.challenge, &res->response))
    {
        debug("control connection: mutual authentication failed");
        teardown_control_connection();
        return;
    }

    evbuffer_drain(input, wanted);
    debug("control connection: mutually authenticated");

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

        case OPEN_CHANNEL:
            {
                debug("control connection: message OPEN_CHANNEL");
                union Channel *channel =
                    setup_channel((struct MessageOpenChannel *) msg);

                if(!channel)
                    debug("control connection: couldn't allocate channel");
            }
            break;

        case CHALLENGE:
        case RESPONSE:
            {
                debug(  "control connection: not yet implemented message (%s)",
                        message_get_type_string(msg));
            }
            break;

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

    event_base_loopexit(context.events, NULL);
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
void read_udp_channel_connection(   evutil_socket_t fd,
                                    short events,
                                    void *channel)
{
    union Channel *chan = (union Channel *) channel;

    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(addr);
    uint8_t buffer[BUFFER_LIMIT];
    int32_t buff_size;
    if((buff_size = recvfrom(   fd,
                                &buffer,
                                BUFFER_LIMIT,
                                0,
                                (struct sockaddr *) &addr,
                                &addr_size)) == -1)
    {
        error_on_udp_channel_connection(fd, events, channel);
        return;
    }

    if(sendto(  chan->udp.peer_fd,
                buffer,
                buff_size,
                0,
                (struct sockaddr *) &chan->udp.peer_addr,
                addr_size) == -1)
    {
        error_on_udp_channel_connection(fd, events, channel);
        return;
    }

    chan->base.alive = 2;
}

inline
static
void error_on_udp_channel_connection(   evutil_socket_t fd,
                                        short events,
                                        void *channel)
{
    debug("udp channel connection: error");
    teardown_channel((union Channel *) channel, 1);
}

inline
static
void teardown_relay_connections(void)
{
    debug("relay connections: teardown");
    while(context.channels)
        teardown_channel(context.channels, 1);
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

static
void read_udp_peer_connection(  evutil_socket_t fd,
                                short events,
                                void *channel)
{
    union Channel *chan = (union Channel *) channel;

    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(addr);
    uint8_t buffer[BUFFER_LIMIT];
    int32_t buff_size;
    if((buff_size = recvfrom(   fd,
                                &buffer,
                                BUFFER_LIMIT,
                                0,
                                (struct sockaddr *) &addr,
                                &addr_size)) == -1)
    {
        error_on_udp_peer_connection(fd, events, channel);
        return;
    }

    if(sendto(  chan->udp.channel_fd,
                buffer,
                buff_size,
                0,
                (struct sockaddr *) &chan->udp.channel_addr,
                addr_size) == -1)
    {
        error_on_udp_peer_connection(fd, events, channel);
        return;
    }

    chan->base.alive = 2;
}

inline
static
void error_on_udp_peer_connection(  evutil_socket_t fd,
                                    short events,
                                    void *channel)
{
    debug("udp peer connection: error");
    teardown_channel((union Channel *) channel, 1);
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
union Channel *setup_channel(struct MessageOpenChannel *ope)
{
    debug("channel: setup %d %d", ope->proto, ntohs(ope->port));
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
    authentication_prepare_response(&channel->base.token,
                                    &ope->challenge,
                                    options.password);

    struct MessageResponse res;
    res.type = RESPONSE;
    memcpy(&res.response, &channel->base.token, CHALLENGE_LENGTH);
    channel->base.proto = ope->proto;

    switch(ope->proto)
    {
        case IPPROTO_TCP:
            {
                debug("channel: setting up tcp");
                channel->tcp.peer_buffers = bufferevent_socket_new(
                    context.events,
                    -1,
                    BEV_OPT_CLOSE_ON_FREE);

                if(!channel->tcp.peer_buffers)
                {
                    perror("bufferevent_socket_new");
                    teardown_channel(channel, 1);
                    return 0;
                }

                int32_t one = 1;
                setsockopt( bufferevent_getfd(channel->tcp.peer_buffers),
                        IPPROTO_TCP,
                        TCP_NODELAY,
                        &one,
                        sizeof(one));


                bufferevent_setwatermark(   channel->tcp.peer_buffers,
                                            EV_READ | EV_WRITE,
                                            sizeof(struct Message),
                                            BUFFER_LIMIT);

                bufferevent_setcb(  channel->tcp.peer_buffers,
                                    read_tcp_peer_connection,
                                    write_tcp_peer_connection,
                                    error_on_tcp_peer_connection_bufferevent,
                                    channel);

                bufferevent_enable( channel->tcp.peer_buffers,
                                    EV_READ | EV_WRITE);

                bufferevent_socket_connect_hostname(channel->tcp.peer_buffers,
                                                    context.dns,
                                                    AF_UNSPEC,
                                                    options.host,
                                                    ntohs(ope->port));

                channel->tcp.channel_buffers = bufferevent_socket_new(
                    context.events,
                    -1,
                    BEV_OPT_CLOSE_ON_FREE);

                if(!channel->tcp.channel_buffers)
                {
                    perror("bufferevent_socket_new");
                    teardown_channel(channel, 1);
                    return 0;
                }

                setsockopt( bufferevent_getfd(channel->tcp.channel_buffers),
                        IPPROTO_TCP,
                        TCP_NODELAY,
                        &one,
                        sizeof(one));

                bufferevent_setwatermark(   channel->tcp.channel_buffers,
                                            EV_READ | EV_WRITE,
                                            sizeof(struct Message),
                                            BUFFER_LIMIT);

                bufferevent_setcb(  channel->tcp.channel_buffers,
                                    read_tcp_channel_connection,
                                    write_tcp_channel_connection,
                                    error_on_tcp_channel_connection_bufferevent,
                                    channel);

                bufferevent_enable( channel->tcp.channel_buffers,
                                    EV_READ | EV_WRITE);

                bufferevent_socket_connect_hostname(
                    channel->tcp.channel_buffers,
                    context.dns,
                    AF_UNSPEC,
                    options.relay_host,
                    options.control_port);

                bufferevent_write(  channel->tcp.channel_buffers,
                                    &res,
                                    sizeof(res));
            }
            break;

        case IPPROTO_UDP:
            {
                debug("channel: setting up udp");
                char port_buf[6];
                struct evutil_addrinfo hints; memset(&hints, 0, sizeof(hints));
                struct evutil_addrinfo *answer = NULL;
                int err;

                // PEER
                evutil_snprintf(port_buf,
                                sizeof(port_buf),
                                "%d",
                                ntohs(ope->port));

                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;
                hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
                err = evutil_getaddrinfo(   options.host,
                                            port_buf,
                                            &hints,
                                            &answer);

                if(err != 0)
                {
                    debug(  "channel: getaddrinfo(%s): %s",
                            options.relay_host,
                            evutil_gai_strerror(err));

                    teardown_channel(channel, 1);
                    return 0;
                }

                channel->udp.peer_fd = socket(  answer->ai_family,
                                                answer->ai_socktype,
                                                answer->ai_protocol);
                //make nonblocking?
                memcpy( &channel->udp.peer_addr,
                        answer->ai_addr,
                        sizeof(struct sockaddr_in));

                channel->udp.peer_event = event_new(context.events,
                                                    channel->udp.peer_fd,
                                                    EV_READ | EV_PERSIST,
                                                    read_udp_peer_connection,
                                                    channel);

                event_add(channel->udp.peer_event, 0);

                // CHANNEL
                answer = 0;
                evutil_snprintf(port_buf,
                                sizeof(port_buf),
                                "%d",
                                options.control_port);

                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;
                hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
                err = evutil_getaddrinfo(   options.relay_host,
                                            port_buf,
                                            &hints,
                                            &answer);

                if(err != 0)
                {
                    debug(  "channel: getaddrinfo(%s): %s",
                            options.host,
                            evutil_gai_strerror(err));

                    teardown_channel(channel, 1);
                    return 0;
                }

                channel->udp.channel_fd = socket(   answer->ai_family,
                                                    answer->ai_socktype,
                                                    answer->ai_protocol);
                //make nonblocking?
                memcpy( &channel->udp.channel_addr,
                        answer->ai_addr,
                        sizeof(struct sockaddr_in));

                channel->udp.channel_event = event_new(
                    context.events,
                    channel->udp.channel_fd,
                    EV_READ | EV_PERSIST,
                    read_udp_channel_connection,
                    channel);

                event_add(channel->udp.channel_event, 0);

                if(sendto(  channel->udp.channel_fd,
                            &res,
                            sizeof(res),
                            0,
                            (struct sockaddr *) &channel->udp.channel_addr,
                            sizeof(struct sockaddr_in)) == -1)
                {
                    debug("channel: error on sendto");
                    teardown_channel(channel, 1);
                    return 0;
                }
            }
            break;

        default:
            debug("channel: not yet implemented protocol %d", ope->proto);
            break;
    }

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

        case IPPROTO_UDP:
            {
                if(channel->udp.channel_event)
                {
                    event_del(channel->udp.channel_event);
                    event_free(channel->udp.channel_event);
                    close(channel->udp.channel_fd);
                    channel->udp.channel_event = 0;
                    channel->udp.channel_fd = 0;
                }

                if(channel->udp.peer_event)
                {
                    event_del(channel->udp.peer_event);
                    event_free(channel->udp.peer_event);
                    close(channel->udp.peer_fd);
                    channel->udp.peer_event = 0;
                    channel->udp.peer_fd = 0;
                }
            }
            break;

        default:
            debug(  "channel: not yet implemented protocol %d",
                    channel->base.proto);
            break;
    }

    channel->base.prev = 0;
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
            debug("clean up: removing dead channel");
            struct BaseChannel *next = cur->next;
            teardown_channel((union Channel *) cur, 1);
            cur = next;
            continue;
        }

        -- cur->alive;
        cur = cur->next;
    }
}
