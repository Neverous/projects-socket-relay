/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket-relay.
 * ----------
 *  Server node.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// libevent
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/util.h>

// protocol
#include "protocol/authentication.h"
#include "protocol/channel.h"
#include "protocol/message.h"

// Usage options and info
const char *HELP    = "Usage: socket-server [options]\n\n\
    -h --help                                                                               Display this usage information.\n\
    -v --version                                                                            Display program version.\n\
    -i --input-interface    INTERFACE[=any]                                                 Input interface to bind to.\n\
    -a --input-address      ADDRESS[=any]                                                   Input address to bind to.\n\
    -o --output-interface   INTERFACE[=any]                                                 Output interface to bind to.\n\
    -b --output-address     ADDRESS[=any]                                                   Output address to bind to.\n\
    -r --relay-host         HOST[=localhost]                                                Address of the relay.\n\
    -s --destinations       DESTINATIONS[=tcp:10080:127.0.0.1:80,tcp:10022:127.0.0.1:22]    Relay ports.\n\
    -c --control-port       PORT[=10000]                                                    Control port of the relay.\n\
    -p --password           PASSWORD[=1234]                                                 Password.";

const char *SHORT_OPTIONS           = "hvi:a:o:b:r:s:c:p:";
const struct option LONG_OPTIONS[] =
{
    {"help",                no_argument,        NULL,   'h'}, // display help and usage
    {"version",             no_argument,        NULL,   'v'}, // display version
    {"input-interface",     required_argument,  NULL,   'i'}, // input interface to bind to
    {"input-address",       required_argument,  NULL,   'a'}, // input address to bind to
    {"output-interface",    required_argument,  NULL,   'o'}, // output interface to bind to
    {"output-address",      required_argument,  NULL,   'b'}, // output address to bind to
    {"relay-host",          required_argument,  NULL,   'r'}, // relay address
    {"destinations",        required_argument,  NULL,   's'}, // destinations
    {"control-port",        required_argument,  NULL,   'c'}, // relay control port
    {"password",            required_argument,  NULL,   'p'}, // password
    {NULL,                  0,                  NULL,   0},
};

struct Options
{
    int16_t     control_port;
    const char  *relay_host;
    const char  *destinations;
    const char  *password;
    const char  *input_interface;
    const char  *input_address;
    const char  *output_interface;
    const char  *output_address;
} options = {
    10000,
    "localhost",
    "tcp:10080:127.0.0.1:80,tcp:10022:127.0.0.1:22",
    "1234",
    NULL,
    NULL,
    NULL,
    NULL,
};

struct Destination
{
    uint8_t     proto;
    uint16_t    from_port;
    char        to_address[INET_ADDRSTRLEN];
    uint16_t    to_port;
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

    int32_t         allocated_channels;
    union Channel   *channels;
    union Channel   *free_channels;

    struct Destination  *destinations;
    int32_t             destinations_count;
} context;

inline
static
void parse_destinations(void);

inline
static
struct Destination *find_destination(uint8_t proto, uint16_t from_port);

// CONTROL CONNECTION
static
void authenticate_control(struct bufferevent *bev, void *_);

static
void authenticate_mutual_control(struct bufferevent *bev, void *_);

inline
static
void process_control_message(struct bufferevent *bev, struct Message *msg);

inline
static
void teardown_control(void);

// CHANNEL CONNECTION
static
void read_udp_channel(evutil_socket_t fd, short events, void *chan);

inline
static
void error_on_udp_channel(evutil_socket_t fd, short events, void *chan);

// PEER CONNECTION
static
void read_udp_peer(evutil_socket_t fd, short events, void *chan);

inline
static
void error_on_udp_peer(evutil_socket_t fd, short events, void *chan);

// RELAY CONNECTIONS
inline
static
void teardown_relays(void);

// CHANNELS
inline
static
union Channel *setup_channel(struct MessageOpenChannel *ope);

inline
static
void teardown_channel(union Channel *channel, uint8_t close_channel);

//############################################################################//
//
#include "common.h"

int32_t main(int32_t argc, char **argv)
{
    int32_t o;
    while(
        (o = getopt_long(argc, argv, SHORT_OPTIONS, LONG_OPTIONS, NULL)) != -1)
        switch(o)
        {
            case 'h': puts(HELP);
                return 0;

            case 'v': printf("socket-server %s\n", VERSION);
                return 0;

            case 'i': options.input_interface = optarg;
                break;

            case 'a': options.input_address = optarg;
                break;

            case 'o': options.output_interface = optarg;
                break;

            case 'b': options.output_address = optarg;
                break;

            case 'r': options.relay_host = optarg;
                break;

            case 's': options.destinations = optarg;
                break;

            case 'c': options.control_port = atoi(optarg);
                break;

            case 'p': options.password = optarg;
                break;

            case '?': fputs(HELP, stderr);
                return 1;
        }

    parse_destinations();

    context.events = event_base_new();
    if(!context.events)
    {
        perror("event_base_new");
        return 2;
    }

    context.dns = evdns_base_new(context.events, 1);
    if(!context.dns)
    {
        perror("evdns_base_new");
        return 3;
    }

    evutil_socket_t fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd != -1);
    evutil_make_socket_nonblocking(fd);
    evutil_make_listen_socket_reuseable(fd);
    if(options.input_address)
    {
        debug("main: binding fd:%d to address %s", fd, options.input_address);
        struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        inet_pton(AF_INET, options.input_address, &addr.sin_addr);
        if(bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1)
        {
            perror("bind");
            return 4;
        }
    }

    if(options.input_interface)
    {
        debug(  "main: binding fd:%d to interface %s",
                fd,
                options.input_interface);

        struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, options.input_interface, sizeof(ifr.ifr_name));
        if(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1)
        {
            perror("setsockopt");
            return 5;
        }
    }

    int32_t one = 1;
    setsockopt( fd,
                IPPROTO_TCP,
                TCP_NODELAY,
                &one,
                sizeof(one));


    context.control_buffers = bufferevent_socket_new(
        context.events,
        fd,
        BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

    if(!context.control_buffers)
    {
        perror("bufferevent_socket_new");
        return 3;
    }

    bufferevent_socket_connect_hostname(context.control_buffers,
                                        context.dns,
                                        AF_INET,
                                        options.relay_host,
                                        options.control_port);

    assert(fd == bufferevent_getfd(context.control_buffers));
    bufferevent_setwatermark(   context.control_buffers,
                                EV_READ,
                                sizeof(struct Message),
                                BUFFER_LIMIT);

    bufferevent_setcb(  context.control_buffers,
                        authenticate_control,
                        NULL,
                        error_on_control,
                        NULL);

    bufferevent_enable(context.control_buffers, EV_READ | EV_WRITE);
    context.msg_alive.type = ALIVE;
    context.alive = 1;
    context.keepalive = event_new(  context.events,
                                    -1,
                                    EV_TIMEOUT | EV_PERSIST,
                                    keepalive,
                                    NULL);

    struct timeval thirty_seconds = { 30, 0 };
    struct event *stats = event_new(context.events,
                                    -1,
                                    EV_TIMEOUT | EV_PERSIST,
                                    display_stats,
                                    NULL);

    event_add(stats, &thirty_seconds);

    struct event *cleanup = event_new(  context.events,
                                        -1,
                                        EV_TIMEOUT | EV_PERSIST,
                                        cleanup_channels,
                                        NULL);

    event_add(cleanup, &thirty_seconds);

    debug("main: connecting");
    event_base_dispatch(context.events);

    debug("main: shutting down");
    event_del(stats);
    event_free(stats);
    stats = NULL;

    event_del(cleanup);
    event_free(cleanup);
    cleanup = NULL;

    event_del(context.keepalive);
    event_free(context.keepalive);
    context.keepalive = NULL;
    return 0;
}

inline
static
void parse_destinations(void)
{
    if(!*options.destinations)
    {
        debug("main: missing destinations");
        teardown_control();
        return;
    }

    const char *w = options.destinations;
    for(context.destinations_count = 1; *w; ++ w)
        context.destinations_count += *w == ',';

    context.destinations =
        (struct Destination *) malloc(
            context.destinations_count * sizeof(struct Destination));

    w = options.destinations;
    struct Destination *cur = context.destinations;
    for(int c = 0; c < context.destinations_count; ++ c)
    {
        int32_t bytes;
        char    proto[4];

        if(sscanf(  w, "%[^:]:%hu:%[^:]:%hu,%n",
                    proto,
                    &cur->from_port,
                    cur->to_address,
                    &cur->to_port,
                    &bytes) != 4)
        {
            debug("main: invalid destination format");
            context.destinations_count = c;
            teardown_control();
            return;
        }

        if(!strcmp(proto, "tcp"))
            cur->proto = IPPROTO_TCP;

        else if(!strcmp(proto, "udp"))
            cur->proto = IPPROTO_UDP;

        else
        {
            debug("main: unsupported protocol %s", proto);
            context.destinations_count = c;
            teardown_control();
            return;
        }

        ++ cur;
        w += bytes;
    }

}

inline
static
struct Destination *find_destination(uint8_t proto, uint16_t from_port)
{
    struct Destination *cur = context.destinations;
    while(cur && (proto != cur->proto || from_port != cur->from_port))
        ++ cur;

    return cur;
}

static
void authenticate_control(struct bufferevent *bev, void *_)
{
    debug("control: authentication reading data");
    struct evbuffer *input  = bufferevent_get_input(bev);
    size_t len      = evbuffer_get_length(input);
    size_t wanted   = sizeof(struct MessageChallenge);
    if(len < wanted)
        return;

    debug("control: authentication checking message");
    struct MessageChallenge *cha =
        (struct MessageChallenge *) evbuffer_pullup(input, wanted);

    if(cha->type != CHALLENGE)
    {
        debug(  "control: invalid authentication message %s",
                message_get_type_string((struct Message *) cha));

        teardown_control();
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

    bufferevent_write(  bev,
                        &res,
                        sizeof(res));

    bufferevent_setcb(  bev,
                        authenticate_mutual_control,
                        NULL,
                        error_on_control,
                        NULL);

    authenticate_mutual_control(bev, _);
}

static
void authenticate_mutual_control(struct bufferevent *bev, void *_)
{
    debug("control: mutual authentication reading data");
    struct evbuffer *input  = bufferevent_get_input(bev);
    size_t len      = evbuffer_get_length(input);
    size_t wanted   = sizeof(struct MessageResponse);
    if(len < wanted)
        return;

    debug("control: mutual authentication checking message");
    struct MessageResponse *res =
        (struct MessageResponse *) evbuffer_pullup(input, wanted);

    if(res->type != RESPONSE)
    {
        debug(  "control: invalid mutual authentication message %s",
                message_get_type_string((struct Message *) res));

        teardown_control();
        return;
    }

    if(!authentication_compare_hash(&context.challenge, &res->response))
    {
        debug("control: mutual authentication failed");
        teardown_control();
        return;
    }

    evbuffer_drain(input, wanted);
    debug("control: mutually authenticated");

    bufferevent_setcb(  bev,
                        read_control,
                        NULL,
                        error_on_control,
                        NULL);

    read_control(bev, _);
}

inline
static
void process_control_message(struct bufferevent *bev, struct Message *msg)
{
    debug("control: processing message");
    switch(msg->type)
    {
        case NOOP:
            debug("control: message NOOP");
            break;

        case ALIVE:
            {
                struct MessageAlive *ali = (struct MessageAlive *) msg;
                debug("control: message ALIVE(%d)", ali->seq);
                if(context.msg_alive.seq != ali->seq)
                {
                    context.msg_alive.seq = ali->seq;
                    bufferevent_write(  bev,
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

                    debug("control: estimated ping %ums", context.ping);
                }
            }
            break;

        case CLOSE_CHANNEL:
            {
                struct MessageCloseChannel *clo =
                    (struct MessageCloseChannel *) msg;

                debug("control: message CLOSE_CHANNEL");
                union Channel *channel =
                    find_channel(&clo->response);

                if(!channel)
                    debug("control: channel doesn't exist");

                else
                    teardown_channel(channel, 0);
            }
            break;

        case OPEN_CHANNEL:
            {
                debug("control: message OPEN_CHANNEL");
                union Channel *channel =
                    setup_channel((struct MessageOpenChannel *) msg);

                if(!channel)
                    debug("control: couldn't allocate channel");
            }
            break;

        case CHALLENGE:
        case RESPONSE:
            {
                debug(  "control: not yet implemented message (%s)",
                        message_get_type_string(msg));
            }
            break;

        default:
            {
                debug(  "control: invalid message (%s)",
                        message_get_type_string(msg));
            }
            break;
    }
}

inline
static
void teardown_control(void)
{
    // disconnect everything and close...
    teardown_relays();

    bufferevent_free(context.control_buffers);
    context.control_buffers = NULL;

    event_base_loopexit(context.events, NULL);
}

static
void read_udp_channel(evutil_socket_t fd, short events, void *chan)
{
    struct UDPChannel *channel = &((union Channel *) chan)->udp;

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
        error_on_udp_channel(fd, events, chan);
        return;
    }

    if(sendto(  channel->peer_fd,
                buffer,
                buff_size,
                0,
                (struct sockaddr *) &channel->peer_addr,
                addr_size) == -1)
    {
        error_on_udp_peer(fd, events, chan);
        return;
    }

    channel->base.alive = 2;
}

inline
static
void error_on_udp_channel(evutil_socket_t fd, short events, void *chan)
{
    debug("udp channel: error");
    teardown_channel((union Channel *) chan, 1);
}

static
void read_udp_peer(evutil_socket_t fd, short events, void *chan)
{
    struct UDPChannel *channel = &((union Channel *) chan)->udp;

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
        error_on_udp_peer(fd, events, chan);
        return;
    }

    if(sendto(  channel->channel_fd,
                buffer,
                buff_size,
                0,
                (struct sockaddr *) &channel->channel_addr,
                addr_size) == -1)
    {
        error_on_udp_channel(fd, events, chan);
        return;
    }

    channel->base.alive = 2;
}

inline
static
void error_on_udp_peer(evutil_socket_t fd, short events, void *chan)
{
    debug("udp peer: error");
    teardown_channel((union Channel *) chan, 1);
}

inline
static
void teardown_relays(void)
{
    debug("relay connections: teardown");
    while(context.channels)
        teardown_channel(context.channels, 1);
}

inline
static
union Channel *setup_channel(struct MessageOpenChannel *ope)
{
    debug("channel: setup %d %d", ope->proto, ntohs(ope->port));
    struct Destination *destination =
        find_destination(ope->proto, ntohs(ope->port));

    if(!destination)
    {
        debug("channel: invalid destination received");
        return NULL;
    }

    if(!context.free_channels)
        allocate_channels();

    if(!context.free_channels)
        return NULL;

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
                debug(  "channel: setting up tcp(%hu -> %s:%hu)",
                        destination->from_port,
                        destination->to_address,
                        destination->to_port);

                evutil_socket_t pfd = socket(AF_INET, SOCK_STREAM, 0);
                assert(pfd != -1);
                evutil_make_socket_nonblocking(pfd);
                if(options.output_address)
                {
                    debug(  "channel: binding fd:%d to address %s",
                            pfd,
                            options.output_address);

                    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
                    addr.sin_family = AF_INET;
                    addr.sin_port = 0;
                    inet_pton(AF_INET, options.output_address, &addr.sin_addr);
                    if(bind(pfd, (struct sockaddr *) &addr, sizeof(addr)) == -1)
                    {
                        perror("bind");
                        teardown_channel(channel, 1);
                        return NULL;
                    }
                }

                if(options.output_interface)
                {
                    debug(  "channel: binding fd:%d to interface %s",
                            pfd,
                            options.output_interface);

                    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
                    strncpy(ifr.ifr_name,
                            options.output_interface,
                            sizeof(ifr.ifr_name));

                    if(setsockopt(  pfd,
                                    SOL_SOCKET,
                                    SO_BINDTODEVICE,
                                    &ifr,
                                    sizeof(ifr)) == -1)
                    {
                        perror("setsockopt");
                        teardown_channel(channel, 1);
                        return NULL;
                    }
                }

                int32_t one = 1;
                setsockopt( pfd,
                            IPPROTO_TCP,
                            TCP_NODELAY,
                            &one,
                            sizeof(one));

                channel->tcp.peer_buffers = bufferevent_socket_new(
                    context.events,
                    pfd,
                    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

                if(!channel->tcp.peer_buffers)
                {
                    perror("bufferevent_socket_new");
                    teardown_channel(channel, 1);
                    return NULL;
                }

                bufferevent_socket_connect_hostname(channel->tcp.peer_buffers,
                                                    context.dns,
                                                    AF_INET,
                                                    destination->to_address,
                                                    destination->to_port);

                assert(pfd == bufferevent_getfd(channel->tcp.peer_buffers));
                bufferevent_setwatermark(   channel->tcp.peer_buffers,
                                            EV_READ,
                                            sizeof(struct Message),
                                            BUFFER_LIMIT);

                bufferevent_setcb(  channel->tcp.peer_buffers,
                                    read_tcp_peer,
                                    NULL,
                                    error_on_tcp_peer,
                                    channel);

                bufferevent_enable( channel->tcp.peer_buffers,
                                    EV_READ | EV_WRITE);

                evutil_socket_t cfd = socket(AF_INET, SOCK_STREAM, 0);
                assert(cfd != -1);
                evutil_make_socket_nonblocking(cfd);
                if(options.input_address)
                {
                    debug(  "channel: binding fd:%d to address %s",
                            cfd,
                            options.input_address);

                    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
                    addr.sin_family = AF_INET;
                    addr.sin_port = 0;
                    inet_pton(AF_INET, options.output_address, &addr.sin_addr);
                    if(bind(cfd, (struct sockaddr *) &addr, sizeof(addr)) == -1)
                    {
                        perror("bind");
                        teardown_channel(channel, 1);
                        return NULL;
                    }
                }

                if(options.input_interface)
                {
                    debug(  "channel: binding fd:%d to interface %s",
                            cfd,
                            options.input_interface);

                    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
                    strncpy(ifr.ifr_name,
                            options.input_interface,
                            sizeof(ifr.ifr_name));

                    if(setsockopt(  cfd,
                                    SOL_SOCKET,
                                    SO_BINDTODEVICE,
                                    &ifr,
                                    sizeof(ifr)) == -1)
                    {
                        perror("setsockopt");
                        teardown_channel(channel, 1);
                        return NULL;
                    }
                }

                setsockopt( cfd,
                            IPPROTO_TCP,
                            TCP_NODELAY,
                            &one,
                            sizeof(one));

                channel->tcp.channel_buffers = bufferevent_socket_new(
                    context.events,
                    cfd,
                    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

                if(!channel->tcp.channel_buffers)
                {
                    perror("bufferevent_socket_new");
                    teardown_channel(channel, 1);
                    return NULL;
                }

                bufferevent_socket_connect_hostname(
                    channel->tcp.channel_buffers,
                    context.dns,
                    AF_INET,
                    options.relay_host,
                    options.control_port);

                assert(cfd == bufferevent_getfd(channel->tcp.channel_buffers));
                bufferevent_setwatermark(   channel->tcp.channel_buffers,
                                            EV_READ,
                                            sizeof(struct Message),
                                            BUFFER_LIMIT);

                bufferevent_setcb(  channel->tcp.channel_buffers,
                                    read_tcp_channel,
                                    NULL,
                                    error_on_tcp_channel,
                                    channel);

                bufferevent_enable( channel->tcp.channel_buffers,
                                    EV_READ | EV_WRITE);

                bufferevent_write(  channel->tcp.channel_buffers,
                                    &res,
                                    sizeof(res));
            }
            break;

        case IPPROTO_UDP:
            {
                debug(  "channel: setting up udp(%hu -> %s:%hu)",
                        destination->from_port,
                        destination->to_address,
                        destination->to_port);

                char port_buf[6];
                struct evutil_addrinfo hints; memset(&hints, 0, sizeof(hints));
                struct evutil_addrinfo *answer = NULL;
                int err;

                // PEER
                evutil_snprintf(port_buf,
                                sizeof(port_buf),
                                "%d",
                                destination->to_port);

                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;
                hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
                err = evutil_getaddrinfo(   destination->to_address,
                                            port_buf,
                                            &hints,
                                            &answer);

                if(err != 0)
                {
                    debug(  "channel: getaddrinfo(%s): %s",
                            destination->to_address,
                            evutil_gai_strerror(err));

                    teardown_channel(channel, 1);
                    return NULL;
                }

                debug("channel: got address info");
                channel->udp.peer_fd = socket(  answer->ai_family,
                                                answer->ai_socktype,
                                                answer->ai_protocol);

                assert(channel->udp.peer_fd != -1);
                //make nonblocking?
                if(options.output_address)
                {
                    debug(  "channel: binding fd:%d to address %s",
                            channel->udp.peer_fd,
                            options.output_address);

                    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
                    addr.sin_family = AF_INET;
                    addr.sin_port = 0;
                    inet_pton(AF_INET, options.output_address, &addr.sin_addr);
                    if(bind(channel->udp.peer_fd,
                            (struct sockaddr *) &addr,
                            sizeof(addr)) == -1)
                    {
                        perror("bind");
                        teardown_channel(channel, 1);
                        return NULL;
                    }
                }

                if(options.output_interface)
                {
                    debug(  "channel: binding fd:%d to interface %s",
                            channel->udp.peer_fd,
                            options.output_interface);

                    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
                    strncpy(ifr.ifr_name,
                            options.output_interface,
                            sizeof(ifr.ifr_name));

                    if(setsockopt(  channel->udp.peer_fd,
                                    SOL_SOCKET,
                                    SO_BINDTODEVICE,
                                    &ifr,
                                    sizeof(ifr)) == -1)
                    {
                        perror("setsockopt");
                        teardown_channel(channel, 1);
                        return NULL;
                    }
                }

                memcpy( &channel->udp.peer_addr,
                        answer->ai_addr,
                        sizeof(struct sockaddr_in));

                channel->udp.peer_event = event_new(context.events,
                                                    channel->udp.peer_fd,
                                                    EV_READ | EV_PERSIST,
                                                    read_udp_peer,
                                                    channel);

                event_add(channel->udp.peer_event, NULL);

                // CHANNEL
                answer = NULL;
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
                            options.relay_host,
                            evutil_gai_strerror(err));

                    teardown_channel(channel, 1);
                    return NULL;
                }

                debug("channel: got address info");
                channel->udp.channel_fd = socket(   answer->ai_family,
                                                    answer->ai_socktype,
                                                    answer->ai_protocol);

                assert(channel->udp.channel_fd != -1);
                //make nonblocking?
                if(options.input_address)
                {
                    debug(  "channel: binding fd:%d to address %s",
                            channel->udp.channel_fd,
                            options.input_address);

                    struct sockaddr_in addr; memset(&addr, 0, sizeof(addr));
                    addr.sin_family = AF_INET;
                    addr.sin_port = 0;
                    inet_pton(AF_INET, options.input_address, &addr.sin_addr);
                    if(bind(channel->udp.channel_fd,
                            (struct sockaddr *) &addr,
                            sizeof(addr)) == -1)
                    {
                        perror("bind");
                        teardown_channel(channel, 1);
                        return NULL;
                    }
                }

                if(options.input_interface)
                {
                    debug(  "channel: binding fd:%d to interface %s",
                            channel->udp.channel_fd,
                            options.input_interface);

                    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
                    strncpy(ifr.ifr_name,
                            options.input_interface,
                            sizeof(ifr.ifr_name));

                    if(setsockopt(  channel->udp.channel_fd,
                                    SOL_SOCKET,
                                    SO_BINDTODEVICE,
                                    &ifr,
                                    sizeof(ifr)) == -1)
                    {
                        perror("setsockopt");
                        teardown_channel(channel, 1);
                        return NULL;
                    }
                }

                memcpy( &channel->udp.channel_addr,
                        answer->ai_addr,
                        sizeof(struct sockaddr_in));

                channel->udp.channel_event = event_new(
                    context.events,
                    channel->udp.channel_fd,
                    EV_READ | EV_PERSIST,
                    read_udp_channel,
                    channel);

                event_add(channel->udp.channel_event, NULL);

                if(sendto(  channel->udp.channel_fd,
                            &res,
                            sizeof(res),
                            0,
                            (struct sockaddr *) &channel->udp.channel_addr,
                            sizeof(struct sockaddr_in)) == -1)
                {
                    debug("channel: error on sendto");
                    teardown_channel(channel, 1);
                    return NULL;
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
                    channel->tcp.channel_buffers = NULL;
                }

                if(channel->tcp.peer_buffers)
                {
                    bufferevent_free(channel->tcp.peer_buffers);
                    channel->tcp.peer_buffers = NULL;
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
                    channel->udp.channel_event = NULL;
                    channel->udp.channel_fd = 0;
                }

                if(channel->udp.peer_event)
                {
                    event_del(channel->udp.peer_event);
                    event_free(channel->udp.peer_event);
                    close(channel->udp.peer_fd);
                    channel->udp.peer_event = NULL;
                    channel->udp.peer_fd = 0;
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
