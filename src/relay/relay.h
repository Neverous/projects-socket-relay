/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket relay.
 */
#ifndef RELAY_H
#define RELAY_H

#include <stdint.h>
#include "protocol/auth.h"
#include "log/log.h"
#include "misc/bufferedSocket.h"
#include "misc/socketChannel.h"

#define MAX_PORTS 65536

typedef struct _port
{
    uint16_t    port;
    int32_t     socket;
} RelayPort;

typedef struct _relay
{
    struct _control
    {
        const char  *host;
        uint16_t    port;
        uint16_t    connectionPort;
        const char  *password;
        const char  *ports;
    } control;

    struct _connection
    {
        BufferedSocket  control;
        int32_t         epoll;
        int8_t          secret;
        uint16_t        ports;
        RelayPort       port[MAX_PORTS];
    } connection;

    SocketChannel   *channels;
    Logger      log;
} SocketRelay;

uint8_t rConnect(SocketRelay *relay);
void    rDisconnect(SocketRelay *relay, const char *reason);
uint8_t rOpenPorts(SocketRelay *relay);
void    rListen(SocketRelay *relay);

#endif // RELAY_H
