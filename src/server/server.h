/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket server.
 */
#ifndef server_H
#define server_H

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
} ServerPort;

typedef struct _server
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
        ServerPort       port[MAX_PORTS];
    } connection;

    SocketChannel   *channels;
    Logger      log;
} SocketServer;

uint8_t sConnect(SocketServer *server);
void    sDisconnect(SocketServer *server, const char *reason);
uint8_t sOpenPorts(SocketServer *server);
void    sListen(SocketServer *server);

#endif // server_H
