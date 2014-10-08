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

#include "relay.h"
#include "log/log.h"
#include "protocol/auth.h"
#include "protocol/message.h"

#define MAX_EVENTS 64

Msg     *rReadMsg(BufferedSocket *socket);
uint8_t rAuthenticate(SocketRelay *relay);
uint8_t rEpollRegister(SocketRelay *relay, int32_t socket, uint32_t flags);
uint8_t rEpollModify(SocketRelay *relay, int32_t socket, uint32_t flags);
int8_t  rEpollWait( SocketRelay *relay,
                    struct epoll_event *events,
                    uint8_t maxEvents);

uint8_t rProcessMessages(SocketRelay *relay);
uint8_t rProcessChannel(SocketRelay *relay, int32_t fd, uint32_t flags);
SocketChannel *rGetChannelFD(SocketRelay *relay, int32_t fd);
uint8_t rOpenChannel(SocketRelay *relay, MsgOpenChannel *cha);
uint8_t rOpenChannelTCP(SocketRelay *relay, SocketChannel *channel, MsgOpenChannel *cha);
uint8_t rOpenChannelUDP(SocketRelay *relay, SocketChannel *channel, MsgOpenChannel *cha);
void    rCloseChannelMsg(SocketRelay *relay, MsgCloseChannel *clo);
void    rCloseChannelFD(SocketRelay *relay, int32_t fd);
void    rCloseChannel(  SocketRelay *relay,
                        SocketChannel *channel,
                        uint8_t msg);

void            rFreeChannel(SocketChannel *channel);
SocketChannel   *rAllocChannel(void);

uint8_t rConnect(SocketRelay *relay)
{
    struct hostent      *relay_host;
    struct sockaddr_in  relay_addr;
    memset((char *) &relay_addr, 0, sizeof(relay_addr));

    struct timeval timeout;
    memset((char *) &timeout, 0, sizeof(timeout));

    int32_t opt = 1;
    BufferedSocket *control = &relay->connection.control;

    NOTICE( &relay->log,
            "Connecting to %s:%u.",
            relay->control.host,
            relay->control.port);
    if(bSocket(control, AF_INET, SOCK_STREAM, 0) < 0)
    {
        ERROR(&relay->log, "Error opening socket: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&relay->log, "Socket opened.");
    if(setsockopt(  control->socket,
                    IPPROTO_TCP,
                    TCP_NODELAY,
                    (char *) &opt,
                    sizeof(opt)) < 0)
        WARNING(&relay->log, "Cannot set TCP_NODELAY: %s!", strerror(errno));

    DEBUG(&relay->log, "TCP_NODELAY set.");
    timeout.tv_usec = 1000;
    if(setsockopt(  control->socket,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    (char *) &timeout,
                    sizeof(timeout)) < 0)
    {
        ERROR(&relay->log, "Cannot set read timeout: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&relay->log, "Read timeout set.");
    NOTICE(&relay->log, "Looking up %s address.", relay->control.host);
    relay_host = gethostbyname(relay->control.host);
    if(!relay_host)
    {
        ERROR(&relay->log, "Cannot get host address: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    relay_addr.sin_family = AF_INET;
    memcpy(&relay_addr.sin_addr.s_addr, relay_host->h_addr_list[0], relay_host->h_length);
    relay_addr.sin_port = htons(relay->control.port);
    NOTICE(&relay->log, "Connecting...");
    if(bSocketConnect(  control,
                        (struct sockaddr *) &relay_addr,
                        sizeof(relay_addr)) < 0)
    {
        ERROR(&relay->log, "Cannot connect: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    INFO(   &relay->log,
            "Connected to %s:%u.",
            relay->control.host,
            relay->control.port);

    return rAuthenticate(relay);
}

void rDisconnect(SocketRelay *relay, const char *reason)
{
    NOTICE( &relay->log,
            "Disconnecting from %s:%u.",
            relay->control.host,
            relay->control.port);

    bSocketClose(&relay->connection.control, 1);
    INFO(   &relay->log,
            "Disconnected from %s:%u, reason %s.",
            relay->control.host,
            relay->control.port,
            reason);

    return;
}

void rProcess(SocketRelay *relay)
{
    BufferedSocket *control = &relay->connection.control;
    assert(control->socket > 0);
    if((relay->connection.epoll = epoll_create1(0)) < 0)
    {
        ERROR(&relay->log, "Cannot create epoll: %s!", strerror(errno));
        bSocketClose(control, 0);
        return;
    }

    if(!rEpollRegister( relay,
                        control->socket,
                        EPOLLIN | EPOLLPRI))
    {
        bSocketClose(control, 0);
        return;
    }

    NOTICE(&relay->log, "Processing.");
    struct epoll_event events[MAX_EVENTS];
    int8_t count = 0;
    while((count = rEpollWait(relay, events, MAX_EVENTS)) >= 0)
    {
        if(!relay->connection.control.socket)
        {
            ERROR(&relay->log, "Control connection unavailable.");
            /*if(sConnect(relay) && !sEpollRegister( relay,
                                                    control->socket,
                                                    EPOLLIN | EPOLLPRI))
            {
                bSocketClose(control, 0);
                return;
            }*/
            return;
        }

        DEBUG(&relay->log, "Got %d events to process.", count);
        for(int8_t e = 0; e < count; ++ e)
        {
            if(events[e].data.fd == control->socket)
            {
                if(events[e].events & EPOLLOUT)
                {
                    DEBUG(&relay->log, "Control socket ready for write.");
                    bSocketWrite(control);
                }

                if(events[e].events & EPOLLIN)
                {
                    DEBUG(&relay->log, "Control socket ready for read.");
                    if(!rProcessMessages(relay))
                        break;
                }
            }

            else
                rProcessChannel(relay, events[e].data.fd, events[e].events);
        }
    }

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
    MsgChallenge *cha = (MsgChallenge *) rReadMsg(control);
    if(!cha || cha->type != CHALLENGE)
    {
        ERROR(&relay->log, "Cannot read auth challenge: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&relay->log, "Read auth challenge.");
    relay->connection.secret = aGetSecretByte(&cha->challenge);

    MsgResponse res;
    res.type = RESPONSE;

    aPrepareResponse(   &res.response,
                        &cha->challenge,
                        relay->control.password,
                        relay->connection.secret);

    if(!bOutBufferPut(control, (uint8_t *) &res, sizeof(res)) || bSocketWrite(control) != sizeof(res))
    {
        ERROR(&relay->log, "Cannot write auth response: %s!", strerror(errno));
        bSocketClose(control, 0);
        return 0;
    }

    DEBUG(&relay->log, "Wrote auth response.");
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

    INFO(   &relay->log,
            "Authenticated with %s:%u.",
            relay->control.host,
            relay->control.port);

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
                rDisconnect(relay, "relay closed connection");
                return 0;
            }

            else
                rCloseChannelFD(relay, events[c].data.fd);

            continue;
        }

        if(c != e)
            memmove(&events[e], &events[c], sizeof(struct epoll_event));

        ++ e;
    }

    return e;
}

inline
uint8_t rProcessMessages(SocketRelay *relay)
{
    BufferedSocket *control = &relay->connection.control;
    uint8_t done = 0;
    while(!done)
    {
        int32_t bytes = bSocketRead(control);
        if(bytes == -1)
        {
            if(errno != EAGAIN && errno != EWOULDBLOCK)
            {
                ERROR(  &relay->log,
                        "Error while reading from control: %s!",
                        strerror(errno));

                rDisconnect(relay, "read error");
                return 0;
            }

            done = 1;
        }

        DEBUG(&relay->log, "Read %ld bytes from socket.", bytes);

        Msg *msg = NULL;
        uint8_t processed = 0;
        while(  !processed
            &&  (msg = (Msg *) bInBufferGet(control, sizeof(Msg), 0)))
        {
            DEBUG(&relay->log, "Processing message from relay.");
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
                            rOpenChannel(relay, ope);
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
                            rCloseChannelMsg(relay, clo);
                        }
                    }
                    break;

                default:
                    {
                        ERROR(  &relay->log,
                                "Invalid message from relay: %s!",
                                mGetTypeStr(msg->type));

                        rDisconnect(relay, "invalid message");
                        return 0;
                    }
                    break;
            }
        }
    }

    return 1;
}

inline
uint8_t rProcessChannel(SocketRelay *relay, int32_t fd, uint32_t flags)
{
    SocketChannel *channel = rGetChannelFD(relay, fd);
    if(!channel)
    {
        ERROR(  &relay->log,
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
            rEpollModify(relay, channel->cha.socket, EPOLLOUT);
        }

        else if(fd == channel->end.socket)
        {
            bSocketReadInto(&channel->end, &channel->cha.out);
            rEpollModify(relay, channel->end.socket, EPOLLOUT);
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
SocketChannel *rGetChannelFD(SocketRelay *relay, int32_t fd)
{
    SocketChannel *cur = relay->channels;
    while(cur &&  fd != cur->end.socket && fd != cur->cha.socket)
        cur = cur->next;

    return cur;
}

inline
uint8_t rOpenChannel(SocketRelay *relay, MsgOpenChannel *cha)
{
    NOTICE(&relay->log, "Opening new channel.");
    SocketChannel *channel = rAllocChannel();
    if(!channel)
    {
        WARNING(&relay->log, "All channels used!");
        return 0;
    }

    // CONNECT
    aPrepareResponse(   &channel->token,
                        &cha->challenge,
                        relay->control.password,
                        relay->connection.secret);

    switch(cha->proto)
    {
        case SOCK_STREAM:
            if(!rOpenChannelTCP(relay, channel, cha))
                return 0;

            break;

        case SOCK_DGRAM:
            // TODO

        default:
            ERROR(&relay->log, "Invalid channel protocol: %d!", cha->proto);
            return 0;
            break;
    }

    if(relay->channels)
        relay->channels->prev = channel;

    channel->next = relay->channels;
    relay->channels = channel;
    return 1;
}

inline
uint8_t rOpenChannelTCP(SocketRelay *relay, SocketChannel *channel, MsgOpenChannel *cha)
{
    struct hostent      *end;
    struct sockaddr_in  end_addr;
    memset((char *) &end_addr, 0, sizeof(end_addr));

    int32_t opt = 0;
    if(bSocket(&channel->end, AF_INET, SOCK_STREAM, 0) < 0)
    {
        ERROR(  &relay->log,
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
        WARNING(&relay->log,
                "Cannot set TCP_NODELAY: %s!",
                strerror(errno));

    NOTICE( &relay->log,
            "Looking up %s address.",
            relay->destination);

    end = gethostbyname(relay->destination);
    if(!end)
    {
        ERROR(  &relay->log,
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
    NOTICE(&relay->log, "Channel connecting...");
    if(bSocketConnect(  &channel->end,
                        (struct sockaddr *) &end_addr,
                        sizeof(end_addr)) < 0)
    {
        ERROR(&relay->log, "Cannot connect: %s!", strerror(errno));
        bSocketClose(&channel->end, 0);
        return 0;
    }

    if(fcntl(   channel->end.socket,
                F_SETFL,
                O_NONBLOCK | fcntl( channel->end.socket,
                                    F_GETFL,
                                    0)) == -1)
        WARNING(&relay->log,
                "Cannot set socket non-blocking: %s!",
                strerror(errno));

    INFO(&relay->log, "Connected with endpoint.");
    return 1;
}

inline
uint8_t rOpenChannelUDP(SocketRelay *relay, SocketChannel *channel, MsgOpenChannel *cha)
{
    return 0;
}

inline
void rCloseChannelMsg(SocketRelay *relay, MsgCloseChannel *clo)
{
    SocketChannel *cur = relay->channels;
    while(cur)
    {
        if(aCompareHash(&clo->response, &cur->token))
        {
            rCloseChannel(relay, cur, 0);
            return;
        }

        cur = cur->next;
    }

    WARNING(&relay->log, "Channel not found.");
    return;
}

inline
void rCloseChannelFD(SocketRelay *relay, int32_t fd)
{
    SocketChannel *cur = rGetChannelFD(relay, fd);
    if(!cur)
    {
        WARNING(&relay->log, "Channel not found.");
        return;
    }

    if(fd == cur->end.socket)
        rCloseChannel(relay, cur, 1);

    else if(fd == cur->cha.socket)
        rCloseChannel(relay, cur, 0);

    return;
}

inline
void rCloseChannel(SocketRelay *relay, SocketChannel *channel, uint8_t msg)
{
    BufferedSocket *control = &relay->connection.control;
    if(msg)
    {
        MsgCloseChannel clo;
        clo.type = CLOSE_CHANNEL;
        memcpy(&clo.response, &channel->token, sizeof(AuthHash));
        bOutBufferPut(control, (uint8_t *) &clo, sizeof(MsgCloseChannel));
        rEpollModify(relay, control->socket, EPOLLOUT | EPOLLIN | EPOLLPRI);
    }

    bSocketClose(&channel->end, 1);
    bSocketClose(&channel->cha, 1);
    rFreeChannel(channel);
}

static SocketChannel *freeChannels;

inline
void rFreeChannel(SocketChannel *channel)
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
SocketChannel *rAllocChannel(void)
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
