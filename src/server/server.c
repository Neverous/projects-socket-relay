/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket server.
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

#include "server.h"
#include "log/log.h"
#include "protocol/auth.h"
#include "protocol/message.h"

uint8_t sOpenTCPPort(SocketServer *server, uint16_t source, uint16_t destination);
uint8_t sOpenUDPPort(SocketServer *server, uint16_t source, uint16_t destination);

Msg     *sReadMsg(BufferedSocket *socket);
uint8_t sAuthenticate(SocketServer *server);

uint8_t sEpollRegister(SocketServer *server, int32_t socket, uint32_t flags);
uint8_t sEpollRegister(SocketServer *server, int32_t socket, uint32_t flags);
uint8_t sEpollModify(SocketServer *server, int32_t socket, uint32_t flags);
int8_t  sEpollWait( SocketServer *server,
                    struct epoll_event *events,
                    uint8_t maxEvents);

uint8_t sConnect(SocketServer *server)
{
    struct sockaddr_in  server_addr;
    struct hostent      *server_host;
    struct sockaddr_in  relay_addr;
    memset((char *) &server_addr, 0, sizeof(server_addr));
    memset((char *) &relay_addr, 0, sizeof(relay_addr));

    struct timeval timeout;
    memset((char *) &timeout, 0, sizeof(timeout));

    int32_t opt = 1;
    BufferedSocket *control = &server->connection.control;

    NOTICE(&server->log, "Starting listening for control connection.");
    int32_t consock = socket(AF_INET, SOCK_STREAM, 0);
    if(consock < 0)
    {
        ERROR(&server->log, "Error opening socket: %s!", strerror(errno));
        return 0;
    }

    DEBUG(&server->log, "Socket opened.");

    if(setsockopt(  consock,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    (char *) &opt,
                    sizeof(opt)) < 0)
        WARNING(&server->log,
                "Cannot set SO_REUSEADDR: %s!",
                strerror(errno));

    DEBUG(&server->log, "SO_REUSEADDR set.");

    server_addr.sin_family = AF_INET;
    if(server->control.host)
    {
        NOTICE(&server->log, "Looking up %s address.", server->control.host);
        server_host = gethostbyname(server->control.host);
        if(!server)
        {
            ERROR(&server->log, "Cannot get host address: %s!", strerror(errno));
            bSocketClose(control, 0);
            return 0;
        }

        memcpy(&server_addr.sin_addr.s_addr, server_host->h_addr_list[0], server_host->h_length);
    }

    else
        server_addr.sin_addr.s_addr  = INADDR_ANY;

    server_addr.sin_port = htons(server->control.port);
    NOTICE(&server->log, "Binding socket to %s:%u.", server->control.host?server->control.host:"0.0.0.0", server->control.port);
    if(bind(consock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
    {
        ERROR(&server->log, "Error binding socket: %s!", strerror(errno));
        close(consock);
        return 0;
    }

    INFO(&server->log, "Socket binded to %s:%u.", server->control.host?server->control.host:"0.0.0.0", server->control.port);
    NOTICE(&server->log, "Setting up listening.");
    if(listen(consock, 1) < 0)
    {
        ERROR(&server->log, "Error on listen: %s!", strerror(errno));
        close(consock);
        return 0;
    }

    while(!control->socket)
    {
        socklen_t relay_size = sizeof(relay_addr);
        NOTICE(&server->log, "Waiting for connection.");
        if(bSocketAccept(   control,
                            consock,
                            (struct sockaddr *) &relay_addr,
                            &relay_size) < 0)
        {
            ERROR(&server->log, "Error on accept: %s!", strerror(errno));
            close(consock);
            bSocketClose(control, 0);
            return 0;
        }

        char host[NI_MAXHOST];
        char port[NI_MAXSERV];
        if(getnameinfo( (struct sockaddr *) &relay_addr,
                        relay_size,
                        host,
                        sizeof(host),
                        port,
                        sizeof(port),
                        NI_NUMERICHOST | NI_NUMERICSERV) == 0)
            INFO(&server->log, "Control connected with %s:%s.", host, port);

        else
            INFO(&server->log, "Control connected.");

        if(setsockopt(  control->socket,
                        IPPROTO_TCP,
                        TCP_NODELAY,
                        (char *) &opt,
                        sizeof(opt)) < 0)
            WARNING(&server->log,
                    "Cannot set TCP_NODELAY: %s!",
                    strerror(errno));

        DEBUG(&server->log, "TCP_NODELAY set.");
        timeout.tv_usec = 1000;
        if(setsockopt(  control->socket,
                        SOL_SOCKET,
                        SO_RCVTIMEO,
                        (char *) &timeout,
                        sizeof(timeout)) < 0)
        {
            ERROR(  &server->log,
                    "Cannot set read timeout: %s!",
                    strerror(errno));

            close(consock);
            bSocketClose(control, 0);
            return 0;
        }

        DEBUG(&server->log, "Read timeout set.");
        sAuthenticate(server);
    }

    assert(control->socket > 0);
    close(consock);
    NOTICE(&server->log, "Creating epoll.");
    if((server->connection.epoll = epoll_create1(0)) < 0)
    {
        ERROR(&server->log, "Cannot create epoll: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    return 1;
}

void sDisconnect(SocketServer *server, const char *reason)
{
    NOTICE(&server->log, "Disconnecting control.");
    bSocketClose(&server->connection.control, 1);
    INFO(&server->log, "Control disconnected, reason %s.", reason);
    return;
}

uint8_t sOpenPorts(SocketServer *server)
{
    NOTICE(&server->log, "Opening ports.");
    const char *port = server->control.ports;
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
                if(!sOpenTCPPort(server, source, destination))
                    return 0;

                break;

            case 'u':
                assert(protocol[1] = 'd');
                if(!sOpenUDPPort(server, source, destination))
                    return 0;

                break;

            default:
                ERROR(&server->log, "Invalid port definition %s", port);
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
uint8_t sOpenTCPPort(SocketServer *server, uint16_t source, uint16_t destination)
{
    struct hostent      *server_host;
    struct sockaddr_in  server_addr;
    memset((char *) &server_addr, 0, sizeof(server_addr));

    int32_t opt = 1;
    ServerPort *port = &server->connection.port[server->connection.ports ++];

    NOTICE(&server->log, "Opening TCP port %hu -> %hu", source, destination);
    port->port      = destination;
    port->socket    = socket(AF_INET, SOCK_STREAM, 0);
    if(port->socket < 0)
    {
        ERROR(&server->log, "Error opening socket: %s!", strerror(errno));
        return 0;
    }

    DEBUG(&server->log, "Socket opened.");

    if(setsockopt(  port->socket,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    (char *) &opt,
                    sizeof(opt)) < 0)
        WARNING(&server->log,
                "Cannot set SO_REUSEADDR: %s!",
                strerror(errno));

    DEBUG(&server->log, "SO_REUSEADDR set.");

    server_addr.sin_family = AF_INET;
    if(server->control.host)
    {
        NOTICE(&server->log, "Looking up %s address.", server->control.host);
        server_host = gethostbyname(server->control.host);
        if(!server)
        {
            ERROR(&server->log, "Cannot get host address: %s!", strerror(errno));
            bSocketClose(&server->connection.control, 0);
            return 0;
        }

        memcpy(&server_addr.sin_addr.s_addr, server_host->h_addr_list[0], server_host->h_length);
    }

    else
        server_addr.sin_addr.s_addr  = INADDR_ANY;

    server_addr.sin_port = htons(source);
    NOTICE(&server->log, "Binding socket to %s:%u.", server->control.host?server->control.host:"0.0.0.0", source);
    if(bind(port->socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
    {
        ERROR(&server->log, "Error binding socket: %s!", strerror(errno));
        close(port->socket);
        return 0;
    }

    INFO(&server->log, "Socket binded to %s:%u.", server->control.host?server->control.host:"0.0.0.0", source);
    NOTICE(&server->log, "Setting up listening.");
    if(listen(port->socket, 5) < 0)
    {
        ERROR(&server->log, "Error on listen: %s!", strerror(errno));
        close(port->socket);
        return 0;
    }

    return sEpollRegister(server, port->socket, EPOLLIN | EPOLLPRI);
}

inline
uint8_t sOpenUDPPort(SocketServer *server, uint16_t source, uint16_t destination)
{
    NOTICE(&server->log, "Opening UDP port %hu -> %hu", source, destination);
    CRITICAL(&server->log, "Not yet implemented.");
    return 0;
}

void sListen(SocketServer *server)
{
    CRITICAL(&server->log, "Not yet implemented!");
    return;
}

inline
Msg *sReadMsg(BufferedSocket *socket)
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
uint8_t sAuthenticate(SocketServer *server)
{
    BufferedSocket *control = &server->connection.control;

    NOTICE(&server->log, "Authenticating...");
    DEBUG(&server->log, "Sending challenge...");
    MsgChallenge cha;
    cha.type = CHALLENGE;
    aPrepareChallenge(&cha.challenge);
    server->connection.secret = aGetSecretByte(&cha.challenge);
    if(!bOutBufferPut(control, (uint8_t *) &cha, sizeof(cha)) || bSocketWrite(control) != sizeof(cha))
    {
        ERROR(&server->log, "Cannot write auth challenge: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&server->log, "Wrote auth challenge.");
    MsgResponse *res = (MsgResponse *) sReadMsg(control);
    if(!res || res->type != RESPONSE)
    {
        ERROR(&server->log, "Cannot read auth response: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&server->log, "Read auth response.");
    AuthHash wanted;
    aPrepareResponse(   &wanted,
                        &cha.challenge,
                        server->control.password,
                        server->connection.secret);

    if(!aCompareHash(&wanted, &res->response))
    {
        ERROR(&server->log, "Authentication failure! Disconnecting.");
        bSocketClose(control, 0);
        return 0;
    }

    NOTICE(&server->log, "Control connection authenticated.");
    if(fcntl(   control->socket,
                F_SETFL,
                O_NONBLOCK | fcntl( control->socket,
                                    F_GETFL,
                                    0)) == -1)
        WARNING(&server->log,
                "Cannot set socket non-blocking: %s!",
                strerror(errno));

    else
        DEBUG(&server->log, "Set socket non-blocking.");

    return 1;
}

inline
uint8_t sEpollRegister(SocketServer *server, int32_t socket, uint32_t flags)
{
    if(!socket)
    {
        DEBUG(&server->log, "Invalid socket number.");
        return 0;
    }

    struct epoll_event event;
    event.data.fd   = socket;
    event.events    = flags | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    if(epoll_ctl(server->connection.epoll, EPOLL_CTL_ADD, socket, &event) < 0)
    {
        ERROR(  &server->log,
                "Error adding socket to epoll: %s!",
                strerror(errno));

        return 0;
    }

    DEBUG(&server->log, "Added %ld socket to epoll.", socket);
    return 1;
}

inline
uint8_t sEpollModify(SocketServer *server, int32_t socket, uint32_t flags)
{
    if(!socket)
    {
        DEBUG(&server->log, "Invalid socket number.");
        return 0;
    }

    struct epoll_event event;
    event.data.fd   = socket;
    event.events    = flags | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

    if(epoll_ctl(server->connection.epoll, EPOLL_CTL_MOD, socket, &event) < 0)
    {
        ERROR(  &server->log,
                "Error modifying socket in epoll: %s!",
                strerror(errno));

        return 0;
    }

    DEBUG(&server->log, "Modified %ld socket flags.", socket);
    return 1;
}

inline
int8_t sEpollWait(  SocketServer *server,
                    struct epoll_event *events,
                    uint8_t maxEvents)
{
    DEBUG(&server->log, "Waiting for events.");
    int8_t count = epoll_wait(server->connection.epoll, events, maxEvents, 5000);
    DEBUG(&server->log, "Epoll returned %d events.", count);
    int8_t e = 0;
    for(int8_t c = 0; c < count; ++ c)
    {
        if( (events[c].events & EPOLLERR)
        ||  (events[c].events & EPOLLHUP)
        ||  (events[c].events & EPOLLRDHUP))
        {
            DEBUG(&server->log, "Peer connection broke.");
            if(events[c].data.fd == server->connection.control.socket)
            {
                sDisconnect(server, "server closed connection");
                return 0;
            }

            // check for ports
            // else
            // sCloseChannelFD(server, events[c].data.fd);

            continue;
        }

        if(c != e)
            memmove(&events[e], &events[c], sizeof(struct epoll_event));

        ++ e;
    }

    return e;
}
