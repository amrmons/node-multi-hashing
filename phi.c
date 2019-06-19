#include "phi.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_skein.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_gost.h"
#include "sha3/sph_echo.h"

void phi1612_hash(const char* input, char* output, uint32_t len)
{
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_cubehash512_context  ctx_cubehash;
    sph_fugue512_context     ctx_fugue;
    sph_gost512_context      ctx_gost;
    sph_echo512_context      ctx_echo;
    
    uint8_t hash[64 * 6];

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, input, len);
    sph_skein512_close(&ctx_skein, hash);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hash, 64);
    sph_jh512_close(&ctx_jh, hash + 1*64);

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, hash + 1*64, 64);
    sph_cubehash512_close(&ctx_cubehash, hash + 2*64);

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hash + 2*64, 64);
    sph_fugue512_close(&ctx_fugue, hash + 3*64);

    sph_gost512_init(&ctx_gost);
    sph_gost512 (&ctx_gost, hash + 3*64, 64);
    sph_gost512_close(&ctx_gost, hash + 4*64);

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, hash + 4*64, 64);
    sph_echo512_close(&ctx_echo, hash + 5*64);

    memcpy(output, hash + 5*64, 32);
}

void phi2_hash(const char* input, char* output, uint32_t len)
{
    unsigned char hash[128] = { 0 };
    unsigned char hashA[64] = { 0 };
    unsigned char hashB[64] = { 0 };

    sph_cubehash512_context ctx_cubehash;
    sph_jh512_context ctx_jh;
    sph_gost512_context ctx_gost;
    sph_echo512_context ctx_echo;
    sph_skein512_context ctx_skein;

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, input, len);
    sph_cubehash512_close(&ctx_cubehash, (void*)hashB);

    LYRA2(&hashA[ 0], 32, &hashB[ 0], 32, &hashB[ 0], 32, 1, 8, 8);
    LYRA2(&hashA[32], 32, &hashB[32], 32, &hashB[32], 32, 1, 8, 8);

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, static_cast<const void*>(hashA), 64);
    sph_jh512_close(&ctx_jh, static_cast<void*>(hash));

    if (hash[0] & 1) {
        sph_gost512_init(&ctx_gost);
        sph_gost512(&ctx_gost, static_cast<const void*>(hash), 64);
        sph_gost512_close(&ctx_gost, static_cast<void*>(hash));
    } else {
        sph_echo512_init(&ctx_echo);
        sph_echo512(&ctx_echo, static_cast<const void*>(hash), 64);
        sph_echo512_close(&ctx_echo, static_cast<void*>(hash));

        sph_echo512_init(&ctx_echo);
        sph_echo512(&ctx_echo, static_cast<const void*>(hash), 64);
        sph_echo512_close(&ctx_echo, static_cast<void*>(hash));
    }
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, static_cast<const void*>(hash), 64);
    sph_skein512_close(&ctx_skein, static_cast<void*>(hash));

    for (int i=0; i<32; i++)
        hash[i] ^= hash[i+32];

    memcpy(output, hash, 32);
}
