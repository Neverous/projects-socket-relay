/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket relay.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>

#include "relay.h"
#include "log/log.h"
#include "protocol/auth.h"
#include "protocol/message.h"

uint8_t rOpenTCPPort(SocketRelay *relay, uint16_t source, uint16_t destination);
uint8_t rOpenUDPPort(SocketRelay *relay, uint16_t source, uint16_t destination);

Msg     *rReadMsg(BufferedSocket *socket);
uint8_t rAuthenticate(SocketRelay *relay);

uint8_t rEpollRegister(SocketRelay *relay, int32_t socket, uint32_t flags);
uint8_t rEpollRegister(SocketRelay *relay, int32_t socket, uint32_t flags);
uint8_t rEpollModify(SocketRelay *relay, int32_t socket, uint32_t flags);
int8_t  rEpollWait( SocketRelay *relay,
                    struct epoll_event *events,
                    uint8_t maxEvents);

uint8_t rConnect(SocketRelay *relay)
{
    struct sockaddr_in  relay_addr;
    struct hostent      *relay_host;
    struct sockaddr_in  server_addr;
    memset((char *) &relay_addr, 0, sizeof(relay_addr));
    memset((char *) &server_addr, 0, sizeof(server_addr));

    struct timeval timeout;
    memset((char *) &timeout, 0, sizeof(timeout));

    int32_t opt = 1;
    BufferedSocket *control = &relay->connection.control;

    NOTICE(&relay->log, "Starting listening for control connection.");
    int32_t consock = socket(AF_INET, SOCK_STREAM, 0);
    if(consock < 0)
    {
        ERROR(&relay->log, "Error opening socket: %s!", strerror(errno));
        return 0;
    }

    DEBUG(&relay->log, "Socket opened.");

    if(setsockopt(  consock,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    (char *) &opt,
                    sizeof(opt)) < 0)
        WARNING(&relay->log,
                "Cannot set SO_REUSEADDR: %s!",
                strerror(errno));

    DEBUG(&relay->log, "SO_REUSEADDR set.");

    relay_addr.sin_family = AF_INET;
    if(relay->control.host)
    {
        NOTICE(&relay->log, "Looking up %s address.", relay->control.host);
        relay_host = gethostbyname(relay->control.host);
        if(!relay)
        {
            ERROR(&relay->log, "Cannot get host address: %s!", strerror(errno));
            bSocketClose(control, 0);
            return 0;
        }

        memcpy(&relay_addr.sin_addr.s_addr, relay_host->h_addr_list[0], relay_host->h_length);
    }

    else
        relay_addr.sin_addr.s_addr  = INADDR_ANY;

    relay_addr.sin_port = htons(relay->control.port);
    NOTICE(&relay->log, "Binding socket to %s:%u.", relay->control.host?relay->control.host:"0.0.0.0", relay->control.port);
    if(bind(consock, (struct sockaddr *) &relay_addr, sizeof(relay_addr)) < 0)
    {
        ERROR(&relay->log, "Error binding socket: %s!", strerror(errno));
        close(consock);
        return 0;
    }

    INFO(&relay->log, "Socket binded to %s:%u.", relay->control.host?relay->control.host:"0.0.0.0", relay->control.port);
    NOTICE(&relay->log, "Setting up listening.");
    if(listen(consock, 1) < 0)
    {
        ERROR(&relay->log, "Error on listen: %s!", strerror(errno));
        close(consock);
        return 0;
    }

    while(!control->socket)
    {
        socklen_t server_size = sizeof(server_addr);
        NOTICE(&relay->log, "Waiting for connection.");
        if(bSocketAccept(   control,
                            consock,
                            (struct sockaddr *) &server_addr,
                            &server_size) < 0)
        {
            ERROR(&relay->log, "Error on accept: %s!", strerror(errno));
            close(consock);
            bSocketClose(control, 0);
            return 0;
        }

        char host[NI_MAXHOST];
        char port[NI_MAXSERV];
        if(getnameinfo( (struct sockaddr *) &server_addr,
                        server_size,
                        host,
                        sizeof(host),
                        port,
                        sizeof(port),
                        NI_NUMERICHOST | NI_NUMERICSERV) == 0)
            INFO(&relay->log, "Control connected with %s:%s.", host, port);

        else
            INFO(&relay->log, "Control connected.");

        if(setsockopt(  control->socket,
                        IPPROTO_TCP,
                        TCP_NODELAY,
                        (char *) &opt,
                        sizeof(opt)) < 0)
            WARNING(&relay->log,
                    "Cannot set TCP_NODELAY: %s!",
                    strerror(errno));

        DEBUG(&relay->log, "TCP_NODELAY set.");
        timeout.tv_usec = 1000;
        if(setsockopt(  control->socket,
                        SOL_SOCKET,
                        SO_RCVTIMEO,
                        (char *) &timeout,
                        sizeof(timeout)) < 0)
        {
            ERROR(  &relay->log,
                    "Cannot set read timeout: %s!",
                    strerror(errno));

            close(consock);
            bSocketClose(control, 0);
            return 0;
        }

        DEBUG(&relay->log, "Read timeout set.");
        rAuthenticate(relay);
    }

    assert(control->socket > 0);
    close(consock);
    NOTICE(&relay->log, "Creating epoll.");
    if((relay->connection.epoll = epoll_create1(0)) < 0)
    {
        ERROR(&relay->log, "Cannot create epoll: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    return 1;
}

void rDisconnect(SocketRelay *relay, const char *reason)
{
    NOTICE(&relay->log, "Disconnecting control.");
    bSocketClose(&relay->connection.control, 1);
    INFO(&relay->log, "Control disconnected, reason %s.", reason);
    return;
}

uint8_t rOpenPorts(SocketRelay *relay)
{
    NOTICE(&relay->log, "Opening ports.");
    const char *port = relay->control.ports;
    uint32_t move = 0;
    int32_t count = 0;
    while(*port)
    {
        uint16_t source = 0;
        uint16_t destination = 0;
        char protocol[4] = {};
        count = sscanf(port, "%3s:%hu:%hu%n", protocol, &source, &destination, &move);
        assert(count == 3);
        assert(move >= 7);
        assert(source > 0);
        assert(destination > 0);
        assert(protocol[2] == 'p');
        switch(*protocol)
        {
            case 't':
                assert(protocol[1] = 'c');
                if(!rOpenTCPPort(relay, source, destination))
                    return 0;

                break;

            case 'u':
                assert(protocol[1] = 'd');
                if(!rOpenUDPPort(relay, source, destination))
                    return 0;

                break;

            default:
                ERROR(&relay->log, "Invalid port definition %s", port);
                return 0;
                break;
        }

        port += move;
        assert(!*port || *port == ',');
        if(*port == ',')
            ++ port;
    }

    return 1;
}

inline
uint8_t rOpenTCPPort(SocketRelay *relay, uint16_t source, uint16_t destination)
{
    struct hostent      *relay_host;
    struct sockaddr_in  relay_addr;
    memset((char *) &relay_addr, 0, sizeof(relay_addr));

    int32_t opt = 1;
    RelayPort *port = &relay->connection.port[relay->connection.ports ++];

    NOTICE(&relay->log, "Opening TCP port %hu -> %hu", source, destination);
    port->port      = destination;
    port->socket    = socket(AF_INET, SOCK_STREAM, 0);
    if(port->socket < 0)
    {
        ERROR(&relay->log, "Error opening socket: %s!", strerror(errno));
        return 0;
    }

    DEBUG(&relay->log, "Socket opened.");

    if(setsockopt(  port->socket,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    (char *) &opt,
                    sizeof(opt)) < 0)
        WARNING(&relay->log,
                "Cannot set SO_REUSEADDR: %s!",
                strerror(errno));

    DEBUG(&relay->log, "SO_REUSEADDR set.");

    relay_addr.sin_family = AF_INET;
    if(relay->control.host)
    {
        NOTICE(&relay->log, "Looking up %s address.", relay->control.host);
        relay_host = gethostbyname(relay->control.host);
        if(!relay)
        {
            ERROR(&relay->log, "Cannot get host address: %s!", strerror(errno));
            bSocketClose(&relay->connection.control, 0);
            return 0;
        }

        memcpy(&relay_addr.sin_addr.s_addr, relay_host->h_addr_list[0], relay_host->h_length);
    }

    else
        relay_addr.sin_addr.s_addr  = INADDR_ANY;

    relay_addr.sin_port = htons(source);
    NOTICE(&relay->log, "Binding socket to %s:%u.", relay->control.host?relay->control.host:"0.0.0.0", source);
    if(bind(port->socket, (struct sockaddr *) &relay_addr, sizeof(relay_addr)) < 0)
    {
        ERROR(&relay->log, "Error binding socket: %s!", strerror(errno));
        close(port->socket);
        return 0;
    }

    INFO(&relay->log, "Socket binded to %s:%u.", relay->control.host?relay->control.host:"0.0.0.0", source);
    NOTICE(&relay->log, "Setting up listening.");
    if(listen(port->socket, 5) < 0)
    {
        ERROR(&relay->log, "Error on listen: %s!", strerror(errno));
        close(port->socket);
        return 0;
    }

    return rEpollRegister(relay, port->socket, EPOLLIN | EPOLLPRI);
}

inline
uint8_t rOpenUDPPort(SocketRelay *relay, uint16_t source, uint16_t destination)
{
    NOTICE(&relay->log, "Opening UDP port %hu -> %hu", source, destination);
    CRITICAL(&relay->log, "Not yet implemented.");
    return 0;
}

void rListen(SocketRelay *relay)
{
    CRITICAL(&relay->log, "Not yet implemented!");
    return;
}

inline
Msg *rReadMsg(BufferedSocket *socket)
{
    while(bInBufferGetSize(socket) < sizeof(Msg))
    {
        int16_t bytes = bSocketRead(socket);
        if(bytes <= 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            return 0;
    }

    Msg *temp = (Msg *) bInBufferGet(socket, sizeof(Msg), 0);
    uint16_t full = 0;
    switch(temp->type)
    {
        case NOP:           full = sizeof(MsgNop);
            break;
        case PING:          full = sizeof(MsgPing);
            break;
        case PONG:          full = sizeof(MsgPong);
            break;
        case CHALLENGE:     full = sizeof(MsgChallenge);
            break;
        case RESPONSE:      full = sizeof(MsgResponse);
            break;
        case OPEN_CHANNEL:  full = sizeof(MsgOpenChannel);
            break;
        case CLOSE_CHANNEL: full = sizeof(MsgCloseChannel);
            break;
    }

    while(bInBufferGetSize(socket) < full)
    {
        int16_t bytes = bSocketRead(socket);
        if(bytes <= 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            return 0;
    }

    return (Msg *) bInBufferGet(socket, full, 1);
}

inline
uint8_t rAuthenticate(SocketRelay *relay)
{
    BufferedSocket *control = &relay->connection.control;

    NOTICE(&relay->log, "Authenticating...");
    DEBUG(&relay->log, "Sending challenge...");
    MsgChallenge cha;
    cha.type = CHALLENGE;
    aPrepareChallenge(&cha.challenge);
    relay->connection.secret = aGetSecretByte(&cha.challenge);
    if(!bOutBufferPut(control, (uint8_t *) &cha, sizeof(cha)) || bSocketWrite(control) != sizeof(cha))
    {
        ERROR(&relay->log, "Cannot write auth challenge: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&relay->log, "Wrote auth challenge.");
    MsgResponse *res = (MsgResponse *) rReadMsg(control);
    if(!res || res->type != RESPONSE)
    {
        ERROR(&relay->log, "Cannot read auth response: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&relay->log, "Read auth response.");
    AuthHash wanted;
    aPrepareResponse(   &wanted,
                        &cha.challenge,
                        relay->control.password,
                        relay->connection.secret);

    if(!aCompareHash(&wanted, &res->response))
    {
        ERROR(&relay->log, "Authentication failure! Disconnecting.");
        bSocketClose(control, 0);
        return 0;
    }

    NOTICE(&relay->log, "Control connection authenticated.");
    if(fcntl(   control->socket,
                F_SETFL,
                O_NONBLOCK | fcntl( control->socket,
                                    F_GETFL,
                                    0)) == -1)
        WARNING(&relay->log,
                "Cannot set socket non-blocking: %s!",
                strerror(errno));

    else
        DEBUG(&relay->log, "Set socket non-blocking.");

    return 1;
}

inline
uint8_t rEpollRegister(SocketRelay *relay, int32_t socket, uint32_t flags)
{
    if(!socket)
    {
        DEBUG(&relay->log, "Invalid socket number.");
        return 0;
    }

    struct epoll_event event;
    event.data.fd   = socket;
    event.events    = flags | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    if(epoll_ctl(relay->connection.epoll, EPOLL_CTL_ADD, socket, &event) < 0)
    {
        ERROR(  &relay->log,
                "Error adding socket to epoll: %s!",
                strerror(errno));

        return 0;
    }

    DEBUG(&relay->log, "Added %ld socket to epoll.", socket);
    return 1;
}

inline
uint8_t rEpollModify(SocketRelay *relay, int32_t socket, uint32_t flags)
{
    if(!socket)
    {
        DEBUG(&relay->log, "Invalid socket number.");
        return 0;
    }

    struct epoll_event event;
    event.data.fd   = socket;
    event.events    = flags | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    if(epoll_ctl(relay->connection.epoll, EPOLL_CTL_MOD, socket, &event) < 0)
    {
        ERROR(  &relay->log,
                "Error modifying socket in epoll: %s!",
                strerror(errno));

        return 0;
    }

    DEBUG(&relay->log, "Modified %ld socket flags.", socket);
    return 1;
}

inline
int8_t rEpollWait(  SocketRelay *relay,
                    struct epoll_event *events,
                    uint8_t maxEvents)
{
    DEBUG(&relay->log, "Waiting for events.");
    int8_t count = epoll_wait(relay->connection.epoll, events, maxEvents, 5000);
    DEBUG(&relay->log, "Epoll returned %d events.", count);
    int8_t e = 0;
    for(int8_t c = 0; c < count; ++ c)
    {
        if( (events[c].events & EPOLLERR)
        ||  (events[c].events & EPOLLHUP)
        ||  (events[c].events & EPOLLRDHUP))
        {
            DEBUG(&relay->log, "Peer connection broke.");
            if(events[c].data.fd == relay->connection.control.socket)
            {
                rDisconnect(relay, "server closed connection");
                return 0;
            }

            // check for ports
            // else
            // rCloseChannelFD(relay, events[c].data.fd);

            continue;
        }

        if(c != e)
            memmove(&events[e], &events[c], sizeof(struct epoll_event));

        ++ e;
    }

    return e;
}
