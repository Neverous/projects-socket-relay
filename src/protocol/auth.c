/* 2014
 * Maciej Szeptuch (Neverous) <neverous@neverous.info>
 *
 * Socket relay.
 */


#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "auth.h"
#include "misc/sha2.h"

uint8_t aGetSecretByte(AuthHash *token)
{
    return token->hash[SECRET_BYTE];
}

uint8_t aPrepareResponse(   AuthHash *response,
                            AuthHash *challenge,
                            const char *password,
                            uint8_t secret)
{
    int32_t passlen = strlen(password);
    assert(passlen < 256);
    assert(CHALLENGE_LENGTH <= SHA256_DIGEST_SIZE);

    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t message[CHALLENGE_LENGTH + 256];
    memcpy(message, password, passlen);
    memcpy(message + passlen, challenge->hash, CHALLENGE_LENGTH);
    sha256(message, CHALLENGE_LENGTH + passlen, digest);
    memcpy(response->hash, digest, CHALLENGE_LENGTH);
    aEncodeBuffer(response->hash, CHALLENGE_LENGTH, aGetSecretByte(challenge));
    return 1;
}

uint8_t aPrepareChallenge(AuthHash *challenge)
{
    for(uint16_t c = 0; c < CHALLENGE_LENGTH; ++ c)
        challenge->hash[c] = rand();

    return 1;
}

uint8_t *aEncodeBuffer(uint8_t *buffer, uint32_t size, uint8_t secret)
{
    // FIXME
    uint8_t *cur = buffer;
    for(uint32_t b = 0; b < size; ++ b, ++ cur)
        *cur ^= secret;

    return buffer;
}

uint8_t *aDecodeBuffer(uint8_t *buffer, uint32_t size, uint8_t secret)
{
    // FIXME
    uint8_t *cur = buffer;
    for(uint32_t b = 0; b < size; ++ b, ++ cur)
        *cur ^= secret;

    return buffer;
}

uint8_t aCompareHash(AuthHash *first, AuthHash *second)
{
    return memcmp(first->hash, second->hash, CHALLENGE_LENGTH) == 0;
}
