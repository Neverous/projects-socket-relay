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

#include "server.h"
#include "log/log.h"
#include "protocol/auth.h"
#include "protocol/message.h"

#define MAX_EVENTS 64

Msg     *sReadMsg(BufferedSocket *socket);
uint8_t sAuthenticate(SocketServer *server);
uint8_t sEpollRegister(SocketServer *server, int32_t socket, uint32_t flags);
uint8_t sEpollModify(SocketServer *server, int32_t socket, uint32_t flags);
int8_t  sEpollWait( SocketServer *server,
                    struct epoll_event *events,
                    uint8_t maxEvents);

uint8_t sProcessMessages(SocketServer *server);
uint8_t sProcessChannel(SocketServer *server, int32_t fd, uint32_t flags);
SocketChannel *sGetChannelFD(SocketServer *server, int32_t fd);
uint8_t sOpenChannel(SocketServer *server, MsgOpenChannel *cha);
uint8_t sOpenChannelTCP(SocketServer *server, SocketChannel *channel, MsgOpenChannel *cha);
uint8_t sOpenChannelUDP(SocketServer *server, SocketChannel *channel, MsgOpenChannel *cha);
void    sCloseChannelMsg(SocketServer *server, MsgCloseChannel *clo);
void    sCloseChannelFD(SocketServer *server, int32_t fd);
void    sCloseChannel(  SocketServer *server,
                        SocketChannel *channel,
                        uint8_t msg);

void            sFreeChannel(SocketChannel *channel);
SocketChannel   *sAllocChannel(void);

uint8_t sConnect(SocketServer *server)
{
    struct hostent      *relay;
    struct sockaddr_in  relay_addr;
    memset((char *) &relay_addr, 0, sizeof(relay_addr));

    struct timeval timeout;
    memset((char *) &timeout, 0, sizeof(timeout));

    int32_t opt = 1;
    BufferedSocket *control = &server->connection.control;

    NOTICE( &server->log,
            "Connecting to %s:%u.",
            server->control.host,
            server->control.port);
    if(bSocket(control, AF_INET, SOCK_STREAM, 0) < 0)
    {
        ERROR(&server->log, "Error opening socket: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&server->log, "Socket opened.");
    if(setsockopt(  control->socket,
                    IPPROTO_TCP,
                    TCP_NODELAY,
                    (char *) &opt,
                    sizeof(opt)) < 0)
        WARNING(&server->log, "Cannot set TCP_NODELAY: %s!", strerror(errno));

    DEBUG(&server->log, "TCP_NODELAY set.");
    timeout.tv_usec = 1000;
    if(setsockopt(  control->socket,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    (char *) &timeout,
                    sizeof(timeout)) < 0)
    {
        ERROR(&server->log, "Cannot set read timeout: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&server->log, "Read timeout set.");
    NOTICE(&server->log, "Looking up %s address.", server->control.host);
    relay = gethostbyname(server->control.host);
    if(!relay)
    {
        ERROR(&server->log, "Cannot get host address: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    relay_addr.sin_family = AF_INET;
    memcpy(&relay_addr.sin_addr.s_addr, relay->h_addr_list[0], relay->h_length);
    relay_addr.sin_port = htons(server->control.port);
    NOTICE(&server->log, "Connecting...");
    if(bSocketConnect(  control,
                        (struct sockaddr *) &relay_addr,
                        sizeof(relay_addr)) < 0)
    {
        ERROR(&server->log, "Cannot connect: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    INFO(   &server->log,
            "Connected to %s:%u.",
            server->control.host,
            server->control.port);

    return sAuthenticate(server);
}

void sDisconnect(SocketServer *server, const char *reason)
{
    NOTICE( &server->log,
            "Disconnecting from %s:%u.",
            server->control.host,
            server->control.port);

    bSocketClose(&server->connection.control, 1);
    INFO(   &server->log,
            "Disconnected from %s:%u, reason %s.",
            server->control.host,
            server->control.port,
            reason);

    return;
}

void sProcess(SocketServer *server)
{
    BufferedSocket *control = &server->connection.control;
    assert(control->socket > 0);
    if((server->connection.epoll = epoll_create1(0)) < 0)
    {
        ERROR(&server->log, "Cannot create epoll: %s!", strerror(errno));
        bSocketClose(control, 0);
        return;
    }

    if(!sEpollRegister( server,
                        control->socket,
                        EPOLLIN | EPOLLPRI))
    {
        bSocketClose(control, 0);
        return;
    }

    NOTICE(&server->log, "Processing.");
    struct epoll_event events[MAX_EVENTS];
    int8_t count = 0;
    while((count = sEpollWait(server, events, MAX_EVENTS)) >= 0)
    {
        if(!server->connection.control.socket)
        {
            ERROR(&server->log, "Control connection unavailable.");
            /*if(sConnect(server) && !sEpollRegister( server,
                                                    control->socket,
                                                    EPOLLIN | EPOLLPRI))
            {
                bSocketClose(control, 0);
                return;
            }*/
            return;
        }

        DEBUG(&server->log, "Got %d events to process.", count);
        for(int8_t e = 0; e < count; ++ e)
        {
            if(events[e].data.fd == control->socket)
            {
                if(events[e].events & EPOLLOUT)
                {
                    DEBUG(&server->log, "Control socket ready for write.");
                    bSocketWrite(control);
                }

                if(events[e].events & EPOLLIN)
                {
                    DEBUG(&server->log, "Control socket ready for read.");
                    if(!sProcessMessages(server))
                        break;
                }
            }

            else
                sProcessChannel(server, events[e].data.fd, events[e].events);
        }
    }

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
    MsgChallenge *cha = (MsgChallenge *) sReadMsg(control);
    if(!cha || cha->type != CHALLENGE)
    {
        ERROR(&server->log, "Cannot read auth challenge: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&server->log, "Read auth challenge.");
    server->connection.secret = aGetSecretByte(&cha->challenge);

    MsgResponse res;
    res.type = RESPONSE;

    aPrepareResponse(   &res.response,
                        &cha->challenge,
                        server->control.password,
                        server->connection.secret);

    if(!bOutBufferPut(control, (uint8_t *) &res, sizeof(res)) || bSocketWrite(control) != sizeof(res))
    {
        ERROR(&server->log, "Cannot write auth response: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&server->log, "Wrote auth response.");
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

    INFO(   &server->log,
            "Authenticated with %s:%u.",
            server->control.host,
            server->control.port);

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
                sDisconnect(server, "relay closed connection");
                return 0;
            }

            else
                sCloseChannelFD(server, events[c].data.fd);

            continue;
        }

        if(c != e)
            memmove(&events[e], &events[c], sizeof(struct epoll_event));

        ++ e;
    }

    return e;
}

inline
uint8_t sProcessMessages(SocketServer *server)
{
    BufferedSocket *control = &server->connection.control;
    uint8_t done = 0;
    while(!done)
    {
        int32_t bytes = bSocketRead(control);
        if(bytes == -1)
        {
            if(errno != EAGAIN && errno != EWOULDBLOCK)
            {
                ERROR(  &server->log,
                        "Error while reading from control: %s!",
                        strerror(errno));

                sDisconnect(server, "read error");
                return 0;
            }

            done = 1;
        }

        DEBUG(&server->log, "Read %ld bytes from socket.", bytes);

        Msg *msg = NULL;
        uint8_t processed = 0;
        while(  !processed
            &&  (msg = (Msg *) bInBufferGet(control, sizeof(Msg), 0)))
        {
            DEBUG(&server->log, "Processing message from server.");
            switch(msg->type)
            {
                case OPEN_CHANNEL:
                    {
                        MsgOpenChannel *ope = (MsgOpenChannel *)
                            bInBufferGet(control, sizeof(MsgOpenChannel), 0);

                        if(!ope)
                            processed = 1;

                        else
                        {
                            bInBufferPop(control, sizeof(MsgOpenChannel));
                            sOpenChannel(server, ope);
                        }
                    }
                    break;

                case CLOSE_CHANNEL:
                    {
                        MsgCloseChannel *clo = (MsgCloseChannel *)
                            bInBufferGet(control, sizeof(MsgCloseChannel), 0);

                        if(!clo)
                            processed = 1;

                        else
                        {
                            bInBufferPop(control, sizeof(MsgCloseChannel));
                            sCloseChannelMsg(server, clo);
                        }
                    }
                    break;

                default:
                    {
                        ERROR(  &server->log,
                                "Invalid message from server: %s!",
                                mGetTypeStr(msg->type));

                        sDisconnect(server, "invalid message");
                        return 0;
                    }
                    break;
            }
        }
    }

    return 1;
}

inline
uint8_t sProcessChannel(SocketServer *server, int32_t fd, uint32_t flags)
{
    SocketChannel *channel = sGetChannelFD(server, fd);
    if(!channel)
    {
        ERROR(  &server->log,
                "Cannot find channel responsible for fd: %ld!",
                fd);

        close(fd);
        return 0;
    }

    if(flags & EPOLLIN)
    {
        if(fd == channel->cha.socket)
        {
            bSocketReadInto(&channel->cha, &channel->end.out);
            sEpollModify(server, channel->cha.socket, EPOLLOUT);
        }

        else if(fd == channel->end.socket)
        {
            bSocketReadInto(&channel->end, &channel->cha.out);
            sEpollModify(server, channel->end.socket, EPOLLOUT);
        }
    }

    if(flags & EPOLLOUT)
    {
        if(fd == channel->cha.socket)
            bSocketWrite(&channel->cha);

        else if(fd == channel->end.socket)
            bSocketWrite(&channel->end);
    }

    return 1;
}

inline
SocketChannel *sGetChannelFD(SocketServer *server, int32_t fd)
{
    SocketChannel *cur = server->channels;
    while(cur &&  fd != cur->end.socket && fd != cur->cha.socket)
        cur = cur->next;

    return cur;
}

inline
uint8_t sOpenChannel(SocketServer *server, MsgOpenChannel *cha)
{
    NOTICE(&server->log, "Opening new channel.");
    SocketChannel *channel = sAllocChannel();
    if(!channel)
    {
        WARNING(&server->log, "All channels used!");
        return 0;
    }

    // CONNECT
    aPrepareResponse(   &channel->token,
                        &cha->challenge,
                        server->control.password,
                        server->connection.secret);

    switch(cha->proto)
    {
        case SOCK_STREAM:
            if(!sOpenChannelTCP(server, channel, cha))
                return 0;

            break;

        case SOCK_DGRAM:
            // TODO

        default:
            ERROR(&server->log, "Invalid channel protocol: %d!", cha->proto);
            return 0;
            break;
    }

    if(server->channels)
        server->channels->prev = channel;

    channel->next = server->channels;
    server->channels = channel;
    return 1;
}

inline
uint8_t sOpenChannelTCP(SocketServer *server, SocketChannel *channel, MsgOpenChannel *cha)
{
    struct hostent      *end;
    struct sockaddr_in  end_addr;
    memset((char *) &end_addr, 0, sizeof(end_addr));

    int32_t opt = 0;
    if(bSocket(&channel->end, AF_INET, SOCK_STREAM, 0) < 0)
    {
        ERROR(  &server->log,
                "Error opening socket: %s!",
                strerror(errno));

        bSocketClose(&channel->end, 0);
        return 0;
    }

    if(setsockopt(  channel->end.socket,
                    IPPROTO_TCP,
                    TCP_NODELAY,
                    (char *) &opt,
                    sizeof(opt)) < 0)
        WARNING(&server->log,
                "Cannot set TCP_NODELAY: %s!",
                strerror(errno));

    NOTICE( &server->log,
            "Looking up %s address.",
            server->destination);

    end = gethostbyname(server->destination);
    if(!end)
    {
        ERROR(  &server->log,
                "Cannot get host address: %s!",
                strerror(errno));

        bSocketClose(&channel->end, 0);
        return 0;
    }

    end_addr.sin_family = AF_INET;
    memcpy( &end_addr.sin_addr.s_addr,
            end->h_addr_list[0],
            end->h_length);

    end_addr.sin_port = cha->port;
    NOTICE(&server->log, "Channel connecting...");
    if(bSocketConnect(  &channel->end,
                        (struct sockaddr *) &end_addr,
                        sizeof(end_addr)) < 0)
    {
        ERROR(&server->log, "Cannot connect: %s!", strerror(errno));
        bSocketClose(&channel->end, 0);
        return 0;
    }

    if(fcntl(   channel->end.socket,
                F_SETFL,
                O_NONBLOCK | fcntl( channel->end.socket,
                                    F_GETFL,
                                    0)) == -1)
        WARNING(&server->log,
                "Cannot set socket non-blocking: %s!",
                strerror(errno));

    INFO(&server->log, "Connected with endpoint.");
    return 1;
}

inline
uint8_t sOpenChannelUDP(SocketServer *server, SocketChannel *channel, MsgOpenChannel *cha)
{
    return 0;
}

inline
void sCloseChannelMsg(SocketServer *server, MsgCloseChannel *clo)
{
    SocketChannel *cur = server->channels;
    while(cur)
    {
        if(aCompareHash(&clo->response, &cur->token))
        {
            sCloseChannel(server, cur, 0);
            return;
        }

        cur = cur->next;
    }

    WARNING(&server->log, "Channel not found.");
    return;
}

inline
void sCloseChannelFD(SocketServer *server, int32_t fd)
{
    SocketChannel *cur = sGetChannelFD(server, fd);
    if(!cur)
    {
        WARNING(&server->log, "Channel not found.");
        return;
    }

    if(fd == cur->end.socket)
        sCloseChannel(server, cur, 1);

    else if(fd == cur->cha.socket)
        sCloseChannel(server, cur, 0);

    return;
}

inline
void sCloseChannel(SocketServer *server, SocketChannel *channel, uint8_t msg)
{
    BufferedSocket *control = &server->connection.control;
    if(msg)
    {
        MsgCloseChannel clo;
        clo.type = CLOSE_CHANNEL;
        memcpy(&clo.response, &channel->token, sizeof(AuthHash));
        bOutBufferPut(control, (uint8_t *) &clo, sizeof(MsgCloseChannel));
        sEpollModify(server, control->socket, EPOLLOUT | EPOLLIN | EPOLLPRI);
    }

    bSocketClose(&channel->end, 1);
    bSocketClose(&channel->cha, 1);
    sFreeChannel(channel);
}

static SocketChannel *freeChannels;

inline
void sFreeChannel(SocketChannel *channel)
{
    if(channel->prev)
        channel->prev->next = channel->next;

    if(channel->next)
        channel->next->prev = channel->prev;

    channel->prev = NULL;
    channel->next = freeChannels;
    if(freeChannels)
        freeChannels->prev = channel;

    freeChannels = channel;
}

inline
SocketChannel *sAllocChannel(void)
{
    if(!freeChannels)
    {
        int32_t count = 8192 / sizeof(SocketChannel);
        SocketChannel *cur = (SocketChannel *)
            malloc(count * sizeof(SocketChannel));

        memset(cur, 0, count * sizeof(SocketChannel));
        freeChannels = cur++;
        for(int c = 1; c < count; ++ c)
        {
            freeChannels->prev = cur;
            cur->next = freeChannels;
            freeChannels = cur ++;
        }
    }

    SocketChannel *channel = freeChannels;
    freeChannels = freeChannels->next;
    freeChannels->prev = NULL;

    channel->next = NULL;
    return channel;
}
