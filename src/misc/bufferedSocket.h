/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket relay.
 */
#ifndef __BUFFERED_SOCKET_H__
#define __BUFFERED_SOCKET_H__

#include <stdint.h>
#include <sys/socket.h>
#include "cyclicBuffer.h"

typedef struct _buffered_socket
{
    int32_t         socket;
    CyclicBuffer    in;
    CyclicBuffer    out;
} BufferedSocket;

int8_t      bSocket(BufferedSocket *handle,
                    int32_t domain,
                    int32_t type,
                    int32_t protocol);

int8_t      bSocketClose(BufferedSocket *handle, uint8_t shutdown);
int8_t      bSocketAccept(  BufferedSocket *handle,
                            int32_t consock,
                            struct sockaddr *client_addr,
                            socklen_t *client_size);

int8_t      bSocketConnect( BufferedSocket *handle,
                            struct sockaddr *address,
                            socklen_t address_size);

int16_t     bSocketRead(BufferedSocket *handle);
int16_t     bSocketReadInto(BufferedSocket *handle, CyclicBuffer *buffer);
int16_t     bSocketWrite(BufferedSocket *handle);

uint16_t    bInBufferGetSize(BufferedSocket *handle);
uint8_t     *bInBufferGet(BufferedSocket *handle, uint16_t size, uint8_t pop);
uint16_t    bInBufferPut(BufferedSocket *handle, uint8_t *data, uint16_t size);
uint8_t     bInBufferPop(BufferedSocket *handle, uint16_t size);

uint16_t    bOutBufferGetSize(BufferedSocket *handle);
uint8_t     *bOutBufferGet(BufferedSocket *handle, uint16_t size, uint8_t pop);
uint16_t    bOutBufferPut(BufferedSocket *handle, uint8_t *data, uint16_t size);
uint8_t     bOutBufferPop(BufferedSocket *handle, uint16_t size);

#endif // __SOCKET_CHANNEL_H__
