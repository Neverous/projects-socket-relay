/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info?
 *
 * Socket relay.
 */

#include <string.h>
#include "cyclicBuffer.h"

void cClear(CyclicBuffer *buff)
{
    buff->begin = buff->end = buff->buffer;
}

int16_t cGetSize(CyclicBuffer *buff)
{
    return buff->end - buff->begin;
}

int16_t cGetFreeSize(CyclicBuffer *buff)
{
    int16_t used = cGetSize(buff);
    if(buff->begin != buff->buffer && buff->end == buff->buffer + BUFFER_SIZE)
    {
        memmove(buff->buffer, buff->begin, used);
        buff->begin = buff->buffer;
        buff->end = buff->begin + used;
    }

    return buff->buffer + BUFFER_SIZE - buff->end;
}

uint8_t *cGet(CyclicBuffer *buff, uint16_t size, uint8_t pop)
{
    if(cGetSize(buff) < size)
        return NULL;

    uint8_t *result = buff->begin;
    if(pop)
        cPop(buff, size);

    return result;
}

uint16_t cPut(CyclicBuffer *buff, uint8_t *data, uint16_t size)
{
    if(cGetFreeSize(buff) < size)
        return 0;

    memcpy(buff->end, data, size);
    buff->end += size;
    return size;
}

uint8_t cPop(CyclicBuffer *buff, uint16_t size)
{
    assert(cGetSize(buff) >= size);
    buff->begin += size;
    return 1;
}
