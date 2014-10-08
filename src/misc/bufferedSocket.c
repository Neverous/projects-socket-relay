/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info?
 *
 * Socket relay.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "bufferedSocket.h"

int8_t bSocket( BufferedSocket *handle,
                int32_t domain,
                int32_t type,
                int32_t protocol)
{
    assert(handle->socket <= 0);
    handle->socket = socket(domain, type, protocol);
    cClear(&handle->in);
    cClear(&handle->out);
    return handle->socket;
}

int8_t bSocketClose(BufferedSocket *handle, uint8_t shut)
{
    if(handle->socket > 0)
    {
        if(shut)
            shutdown(handle->socket, SHUT_RDWR);

        close(handle->socket);
        handle->socket = 0;
    }

    cClear(&handle->in);
    cClear(&handle->out);
    return 1;
}

int8_t bSocketAccept(   BufferedSocket *handle,
                        int32_t consock,
                        struct sockaddr *client_addr,
                        socklen_t *client_size)
{
    assert(handle->socket <= 0);
    cClear(&handle->in);
    cClear(&handle->out);
    return handle->socket = accept(consock, client_addr, client_size);
}

int8_t bSocketConnect(  BufferedSocket *handle,
                        struct sockaddr *address,
                        socklen_t address_size)
{
    assert(handle->socket > 0);
    return connect(handle->socket, address, address_size);
}

int16_t bSocketRead(BufferedSocket *handle)
{
    return bSocketReadInto(handle, &handle->in);
}

int16_t bSocketReadInto(BufferedSocket *handle, CyclicBuffer *buffer)
{
    assert(handle->socket > 0);
    uint16_t readBytes = 0;
    int16_t count;
    if(!cGetFreeSize(buffer))
        return -2;

    while(cGetFreeSize(buffer) && (count = read(handle->socket, buffer->end, cGetFreeSize(buffer))) > 0)
    {
        assert(handle->socket > 0);
        buffer->end += count;
        readBytes += count;
    }

    if(count == 0)
        errno = ECANCELED;

    if(count == -1)
        return -1;

    if(!cGetFreeSize(buffer))
        return -2;

    return readBytes;
}

int16_t bSocketWrite(BufferedSocket *handle)
{
    assert(handle->socket > 0);
    uint16_t left = cGetSize(&handle->out);
    uint16_t bytesWrote = 0;
    int16_t count;
    while(left > 0 && (count = write(handle->socket, cGet(&handle->out, left, 0), left)) > 0)
    {
        assert(handle->socket > 0);
        if(count == -1)
        {
            if(errno == EAGAIN || errno == EWOULDBLOCK)
                return bytesWrote;

            return -1;
        }

        cPop(&handle->out, count);
        bytesWrote += count;
        left -= count;
    }

    return bytesWrote;
}

uint16_t bInBufferGetSize(BufferedSocket *handle)
{
    return cGetSize(&handle->in);
}

uint8_t *bInBufferGet(BufferedSocket *handle, uint16_t size, uint8_t pop)
{
    return cGet(&handle->in, size, pop);
}

uint16_t bInBufferPut(BufferedSocket *handle, uint8_t *data, uint16_t size)
{
    uint16_t bytes = cPut(&handle->in, data, size);
    assert(bytes = size);
    assert(cGetSize(&handle->in) >= bytes);
    return bytes;
}

uint8_t bInBufferPop(BufferedSocket *handle, uint16_t size)
{
    return cPop(&handle->in, size);
}

uint16_t bOutBufferGetSize(BufferedSocket *handle)
{
    return cGetSize(&handle->out);
}

uint8_t *bOutBufferGet(BufferedSocket *handle, uint16_t size, uint8_t pop)
{
    return cGet(&handle->out, size, pop);
}

uint16_t bOutBufferPut(BufferedSocket *handle, uint8_t *data, uint16_t size)
{
    uint16_t bytes = cPut(&handle->out, data, size);
    assert(bytes == size);
    assert(cGetSize(&handle->out) >= bytes);
    return bytes;
}

uint8_t bOutBufferPop(BufferedSocket *handle, uint16_t size)
{
    return cPop(&handle->out, size);
}
