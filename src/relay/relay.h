/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket relay.
 */
#ifndef relay_H
#define relay_H

#include <stdint.h>
#include "protocol/auth.h"
#include "log/log.h"
#include "misc/bufferedSocket.h"
#include "misc/socketChannel.h"

typedef struct _relay
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
} SocketRelay;

uint8_t rConnect(SocketRelay *relay);
void    rDisconnect(SocketRelay *relay, const char *reason);
void    rProcess(SocketRelay *relay);

#endif // relay_H
