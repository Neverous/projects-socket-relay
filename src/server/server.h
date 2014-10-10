/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket relay.
 */
#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include "protocol/auth.h"
#include "log/log.h"
#include "misc/bufferedSocket.h"
#include "misc/socketChannel.h"

typedef struct _server
{
    struct _control
    {
        const char  *host;
        uint16_t    port;
        uint16_t    connectionPort;
        const char  *password;
    } control;

    const char      *destination;
    struct _connection
    {
        BufferedSocket  control;
        int32_t         epoll;
        int8_t          secret;
    } connection;

    SocketChannel   *channels;
    Logger          log;
} SocketServer;

uint8_t sConnect(SocketServer *server);
void    sDisconnect(SocketServer *server, const char *reason);
void    sProcess(SocketServer *server);

#endif // SERVER_H
