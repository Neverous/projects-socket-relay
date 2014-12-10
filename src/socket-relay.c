/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket-relay.
 * ----------
 *  Relay node.
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
#include <event2/listener.h>

// protocol
#include "protocol/authentication.h"
#include "protocol/channel.h"
#include "protocol/message.h"

// relay
#include "relaylistener.h"

// Usage options and info
const char *HELP    = "Usage: socket-relay [options]\n\n\
    -h --help                                               Display this usage information.\n\
    -v --version                                            Display version.\n\
    -i --interface      INTERFACE                           Network interface to use.\n\
    -c --control-port   PORT[=10000]                        Control port.\n\
    -r --relay-ports    PORTS[=tcp:10080:80,tcp:10022:22]   Relay ports.\n\
    -p --password       PASSWORD[=1234]                     Password.";

const char *SHORT_OPTIONS           = "hvi:c:r:p:";
const struct option LONG_OPTIONS[] =
{
    {"help",            no_argument,        NULL,   'h'}, // display help and usage
    {"version",         no_argument,        NULL,   'v'}, // display version
    {"interface",       required_argument,  NULL,   'i'}, // interface
    {"control-port",    required_argument,  NULL,   'c'}, // control port
    {"relay-ports",     required_argument,  NULL,   'r'}, // relay ports
    {"password",        required_argument,  NULL,   'p'}, // password
    {NULL,              0,                  NULL,   0},
};

struct Options
{
    int16_t     control_port;
    const char  *relay_ports;
    const char  *password;
    const char  *interface;
} options = {
    10000,
    "tcp:10080:80,tcp:10022:22",
    "1234",
    NULL,
};

struct Context
{
    struct event_base       *events;
    struct _Listener
    {
        struct evconnlistener   *tcp;
        struct event            *udp;
    } listener;

    struct sockaddr_in      control_address;
    struct bufferevent      *control_buffers;

    struct AuthenticationHash   challenge;
    uint8_t                     secret;
    struct MessageAlive         msg_alive;
    uint8_t                     alive;
    uint32_t                    ping;
    uint64_t                    last_alive;
    struct event                *keepalive;

    int32_t                 allocated_channels;
    union Channel           *channels;
    union Channel           *free_channels;

    struct RelayListener    *relays;
    uint16_t                relays_count;
} context;

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

inline
static
void process_control_message(   struct bufferevent *buffevent,
                                struct Message *msg);

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
void read_udp_channel_connection(evutil_socket_t fd, short events, void *args);

inline
static
void error_on_udp_channel_connection(   evutil_socket_t fd,
                                        short events,
                                        void *args);

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
void read_udp_peer_connection(  evutil_socket_t fd,
                                short events,
                                void *relay);

inline
static
void error_on_udp_peer_connection(  evutil_socket_t fd,
                                    short events,
                                    void *relay);

// CHANNELS
inline
static
union Channel *request_channel(uint8_t proto, uint16_t port);

inline
static
void teardown_channel(union Channel *channel, uint8_t close_channel);

#include "common.h"

int32_t main(int32_t argc, char **argv)
{
    int32_t o;
    while((o = getopt_long(argc, argv, SHORT_OPTIONS, LONG_OPTIONS, NULL)) != -1)
        switch(o)
        {
            case 'h': puts(HELP);
                return 0;

            case 'v': printf("socket-relay %s\n", VERSION);
                return 0;

            case 'i': options.interface = optarg;
                break;

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

    context.listener.tcp = evconnlistener_new_bind(
        context.events,
        accept_control_connection, NULL,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr *) &relay, sizeof(relay));

    if(options.interface)
    {
        evutil_socket_t fd = evconnlistener_get_fd(context.listener.tcp);
        debug("binding fd:%d to interface %s", fd, options.interface);
        struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, options.interface, sizeof(ifr.ifr_name));
        if(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) == -1)
        {
            perror("setsockopt");
            return 3;
        }
    }

    if(!context.listener.tcp)
    {
        perror("evconnlistener_new_bind");
        return 4;
    }

    evconnlistener_set_error_cb(    context.listener.tcp,
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
    stats = NULL;

    event_del(cleanup);
    event_free(cleanup);
    cleanup = NULL;

    event_del(context.keepalive);
    event_free(context.keepalive);
    context.keepalive = NULL;
    return 0;
}

static
void accept_control_connection( struct evconnlistener *listener,
                                evutil_socket_t fd,
                                struct sockaddr *address,
                                int socklen,
                                void *args)
{
    assert(address->sa_family == AF_INET);
    memcpy(&context.control_address, address, sizeof(context.control_address));
    char buffer[INET_ADDRSTRLEN];
    debug(  "control connection: from %s",
        inet_ntop(  AF_INET,
                    &context.control_address.sin_addr,
                    buffer,
                    INET_ADDRSTRLEN));

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

inline
static
void teardown_control_connection(void)
{
    // disconnect everything and close...
    teardown_relay_connections();

    bufferevent_free(context.control_buffers);
    context.control_buffers = NULL;
    evconnlistener_free(context.listener.tcp);
    context.listener.tcp = NULL;

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

    if( ipv4->sin_family != context.control_address.sin_family
    ||  memcmp( &ipv4->sin_addr,
                &context.control_address.sin_addr,
                sizeof(ipv4->sin_addr)))
    {
        debug("tcp channel connection: invalid source address!");
        close(fd);
        return;
    }

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

    evbuffer_drain(input, wanted);
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
void read_udp_channel_connection(evutil_socket_t fd, short events, void *args)
{
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(addr);
    uint8_t buffer[BUFFER_LIMIT];
    int32_t buff_size;
    if((buff_size = recvfrom(   fd,
                                buffer,
                                BUFFER_LIMIT,
                                0,
                                (struct sockaddr *) &addr,
                                &addr_size)) == -1)
    {
        error_on_udp_channel_connection(fd, events, args);
        return;
    }

    struct UDPChannel *channel = find_udp_channel_by_channel(&addr);
    if(!channel)
    {
        if(buff_size != sizeof(struct MessageResponse))
        {
            debug("udp channel connection: doesn't exist");
            return;
        }

        struct MessageResponse *res = (struct MessageResponse *) buffer;
        union Channel *chan = find_channel(&res->response);

        if(!chan)
        {
            debug("udp channel connection: doesn't exist");
            return;
        }

        debug("udp channel connection: authenticated");
        chan->udp.channel_fd = fd;
        memcpy(&chan->udp.channel_addr, &addr, sizeof(struct sockaddr_in));
        return;
    }

    assert(channel->peer_fd);
    if(sendto(  channel->peer_fd,
                buffer,
                buff_size,
                0,
                (struct sockaddr *) &channel->peer_addr,
                addr_size) == -1)
    {
        error_on_udp_peer_connection(fd, events, args);
        return;
    }

    channel->base.alive = 2;
}

static
void error_on_udp_channel_connection(   evutil_socket_t fd,
                                        short events,
                                        void *args)
{
    debug("udp peer connection: I don't really know what to do here.");
    teardown_control_connection();
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
        teardown_control_connection();
        return;
    }

    debug("relay connections: setting up tcp channels port");
    evconnlistener_set_cb(  context.listener.tcp,
                            accept_tcp_channel_connection,
                            NULL);

    debug("relay connections: setting up %d relay ports", context.relays_count);
    context.relays =
        (struct RelayListener *) malloc(
            context.relays_count * sizeof(struct RelayListener));

    w = options.relay_ports;
    struct RelayListener *cur = context.relays;
    uint8_t udp = 0;
    for(int c = 0; c < context.relays_count; ++ c)
    {
        char        proto[4];
        uint16_t    port_from;
        int32_t     bytes;

        if(sscanf(w, "%[^:]:%hu:%hu,%n", proto, &port_from, &cur->port, &bytes)
            != 3)
        {
            debug("relay connections: invalid relay ports format");
            teardown_control_connection();
            return;
        }

        if(!strcmp(proto, "tcp"))
        {
            debug(  "relay connections: setting up tcp relay %d -> %d",
                    port_from, cur->port);

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

            if(options.interface)
            {
                evutil_socket_t fd =
                    evconnlistener_get_fd(cur->tcp_listener);

                debug(  "relay connections: binding fd:%d to interface %s",
                        fd,
                        options.interface);

                struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, options.interface, sizeof(ifr.ifr_name));
                if(setsockopt(  fd,
                                SOL_SOCKET,
                                SO_BINDTODEVICE,
                                &ifr,
                                sizeof(ifr)) == -1)
                {
                    perror("setsockopt");
                    teardown_control_connection();
                    return;
                }
            }

            if(!cur->tcp_listener)
            {
                perror("evconnlistener_new_bind");
                teardown_control_connection();
                return;
            }

            evconnlistener_set_error_cb(cur->tcp_listener,
                                        error_on_tcp_peer_connection_listener);

            ++ cur;
            w += bytes;
        }

        else if(!strcmp(proto, "udp"))
        {
            udp = 1;
            debug("relay connections: setting up udp relay %d -> %d",
                port_from, cur->port);

            cur->proto = IPPROTO_UDP;
            struct sockaddr_in  relay; memset(&relay, 0, sizeof(relay));
            relay.sin_family        = AF_INET;
            relay.sin_addr.s_addr   = INADDR_ANY;
            relay.sin_port          = htons(port_from);

            evutil_socket_t ufd = socket(AF_INET, SOCK_DGRAM, 0);
            //evutil_make_socket_nonblocking(ufd); maybe?
            if(options.interface)
            {
                debug(  "relay connections: binding fd:%d to interface %s",
                        ufd,
                        options.interface);

                struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, options.interface, sizeof(ifr.ifr_name));
                if(setsockopt(  ufd,
                                SOL_SOCKET,
                                SO_BINDTODEVICE,
                                &ifr,
                                sizeof(ifr)) == -1)
                {
                    perror("setsockopt");
                    teardown_control_connection();
                    return;
                }
            }

            if(bind(ufd, (struct sockaddr *) &relay, sizeof(relay)) == -1)
            {
                perror("bind");
                teardown_control_connection();
                return;
            }

            cur->udp_listener = event_new(  context.events,
                                            ufd,
                                            EV_READ | EV_PERSIST,
                                            read_udp_peer_connection,
                                            cur);

            event_add(cur->udp_listener, NULL);

            ++ cur;
            w += bytes;
        }

        else
        {
            debug("relay connections: unsupported protocol %s", proto);
            teardown_control_connection();
            return;
        }
    }

    if(udp)
    {
        debug("relay connections: setting up udp channels port");
        struct sockaddr_in  relay; memset(&relay, 0, sizeof(relay));

        relay.sin_family        = AF_INET;
        relay.sin_addr.s_addr   = INADDR_ANY;
        relay.sin_port          = htons(options.control_port);

        int32_t ufd = socket(AF_INET, SOCK_DGRAM, 0);
        //evutil_make_socket_nonblocking(ufd); maybe?
        if(options.interface)
        {
            debug(  "relay connections: binding fd:%d to interface %s",
                    ufd,
                    options.interface);

            struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, options.interface, sizeof(ifr.ifr_name));
            if(setsockopt(  ufd,
                            SOL_SOCKET,
                            SO_BINDTODEVICE,
                            &ifr,
                            sizeof(ifr)) == -1)
            {
                perror("setsockopt");
                teardown_control_connection();
                return;
            }
        }

        if(bind(ufd, (struct sockaddr *) &relay, sizeof(relay)) == -1)
        {
            perror("bind");
            teardown_control_connection();
            return;
        }

        context.listener.udp = event_new(   context.events,
                                            ufd,
                                            EV_READ | EV_PERSIST,
                                            read_udp_channel_connection,
                                            NULL);

        event_add(context.listener.udp, NULL);
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
        switch(cur->proto)
        {
            case IPPROTO_TCP:
                {
                    evconnlistener_free(cur->tcp_listener);
                    cur->tcp_listener = NULL;
                }
                break;

            case IPPROTO_UDP:
                {
                    event_free(cur->udp_listener);
                    cur->udp_listener = NULL;
                }
                break;

            default:
                debug("Not yet implemented");
                break;
        }

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
    if(!channel)
    {
        debug("tcp peer connection: no channels left!");
        bufferevent_free(buffevent);
        return;
    }

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
void read_udp_peer_connection(  evutil_socket_t fd,
                                short events,
                                void *relay)
{
    struct RelayListener *listener = (struct RelayListener *) relay;

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
        error_on_udp_peer_connection(fd, events, relay);
        return;
    }

    struct UDPChannel *channel = find_udp_channel_by_peer(&addr);
    if(!channel)
    {
        union Channel *chan = request_channel(listener->proto, listener->port);
        if(!chan)
        {
            debug("udp peer connection: no channels left!");
            return;
        }

        chan->udp.peer_fd = fd;
        memcpy(&chan->udp.peer_addr, &addr, addr_size);
        return;
    }

    if(!channel->channel_fd)
        return;

    if(sendto(  channel->channel_fd,
                buffer,
                buff_size,
                0,
                (struct sockaddr *) &channel->channel_addr,
                addr_size) == -1)
    {
        error_on_udp_peer_connection(fd, events, relay);
        return;
    }

    channel->base.alive = 2;
}

static
void error_on_udp_peer_connection(  evutil_socket_t fd,
                                    short events,
                                    void *relay)
{
    debug("udp peer connection: I don't really know what to do here.");
    teardown_control_connection();
}

inline
static
union Channel *request_channel(uint8_t proto, uint16_t port)
{
    debug("channel: request %d %d", proto, port);
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
