/* 2014
 * Maciej Szeptuch (neverous) <neverous@neverous.info>
 */
#ifndef __AUTHENTICATION_H__
#define __AUTHENTICATION_H__

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <event2/util.h>
#include "sha2.h"

#define CHALLENGE_LENGTH    32
#define SECRET_BYTE         17

#pragma pack(push, 1)

struct AuthenticationHash
{
    uint8_t hash[CHALLENGE_LENGTH];
}; // struct AthenticationHash

static_assert(  sizeof(struct AuthenticationHash) == CHALLENGE_LENGTH,
                "Invalid AuthenticationHash structure size!");

#pragma pack(pop)

inline
static
uint8_t authentication_get_secret_byte(const struct AuthenticationHash *token)
{
    return token->hash[SECRET_BYTE];
}

inline
static
uint8_t authentication_compare_hash(const struct AuthenticationHash *first,
                                    const struct AuthenticationHash *second)
{
    return memcmp(first->hash, second->hash, CHALLENGE_LENGTH) == 0;
}

inline
static
uint8_t authentication_prepare_response(
        struct AuthenticationHash *response,
        const struct AuthenticationHash *challenge,
        const char *password)
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
    return 1;
}

inline
static
uint8_t authentication_prepare_challenge(struct AuthenticationHash *challenge)
{
    evutil_secure_rng_get_bytes(challenge->hash, CHALLENGE_LENGTH);
    return 1;
}

#endif // __AUTHENTICATION_H__
