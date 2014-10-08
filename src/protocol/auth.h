/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket relay.
 */
#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdint.h>
#include <assert.h>

#define CHALLENGE_LENGTH    32
#define SECRET_BYTE         17

#pragma pack(push, 1)

typedef struct _auth_hash
{
    uint8_t hash[CHALLENGE_LENGTH];
} AuthHash;

static_assert(  sizeof(AuthHash) == CHALLENGE_LENGTH,
                "Invalid AuthHash structure size");

#pragma pack(pop)

uint8_t aGetSecretByte(AuthHash *token);
uint8_t aPrepareResponse(   AuthHash *response,
                            AuthHash *challenge,
                            const char *password,
                            uint8_t secret);

uint8_t aPrepareChallenge(AuthHash *challenge);
uint8_t *aEncodeBuffer(uint8_t *buffer, uint32_t size, uint8_t secret);
uint8_t *aDecodeBuffer(uint8_t *buffer, uint32_t size, uint8_t secret);
uint8_t aCompareHash(AuthHash *first, AuthHash *second);

#endif // __AUTH_H__
