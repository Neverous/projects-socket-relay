/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket relay.
 */
#ifndef __CYCLIC_BUFFER_H__
#define __CYCLIC_BUFFER_H__

#include <stdint.h>
#include <assert.h>

#define BUFFER_SIZE 1024

#pragma pack (push, 1)

typedef struct _cyclic_buffer
{
    uint8_t buffer[BUFFER_SIZE];
    uint8_t *begin;
    uint8_t *end;
} CyclicBuffer;

static_assert(sizeof(CyclicBuffer) == 16 + BUFFER_SIZE, "Invalid CyclicBuffer structure size!");

#pragma pack (pop)

void    cClear(CyclicBuffer *buff);
int16_t cGetSize(CyclicBuffer *buff);
int16_t cGetFreeSize(CyclicBuffer *buff);

uint8_t     *cGet(CyclicBuffer *buff, uint16_t size, uint8_t pop);
uint16_t    cPut(CyclicBuffer *buff, uint8_t *data, uint16_t size);
uint8_t     cPop(CyclicBuffer *buff, uint16_t size);

#endif // __CYCLIC_BUFFER_H__
