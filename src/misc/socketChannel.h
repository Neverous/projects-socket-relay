/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket relay.
 */
#ifndef __SOCKET_CHANNEL_H__
#define __SOCKET_CHANNEL_H__

#include "protocol/auth.h"
#include "bufferedSocket.h"

typedef struct _socket_channel
{
    // List handles
    struct _socket_channel  *prev;
    struct _socket_channel  *next;

    // Authentication token
    AuthHash                token;

    // Endpoints
    BufferedSocket          cha;
    BufferedSocket          end;
} SocketChannel;

#endif // __SOCKET_CHANNEL_H__
