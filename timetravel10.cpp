#include "timetravel10.h"
#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"

#include <algorithm>

#define HASH_FUNC_BASE_TIMESTAMP 1492973331  // BitCore: Genesis Timestamp
#define HASH_FUNC_COUNT 10                   // BitCore: HASH_FUNC_COUNT of 11
#define HASH_FUNC_COUNT_PERMUTATIONS 40320   // BitCore: HASH_FUNC_COUNT!

void timetravel10_hash(const char* input, char* output)
{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;

    uint8_t hash[HASH_FUNC_COUNT * 64];
    uint32_t timestamp;
    
    std::memcpy(&timestamp, input + 68, 4);

    // We want to permute algorithms. To get started we
    // initialize an array with a sorted sequence of unique
    // integers where every integer represents its own algorithm.
    uint32_t permutation[HASH_FUNC_COUNT];
    for (uint32_t i=0; i < HASH_FUNC_COUNT; i++) {
        permutation[i]=i;
    }

    // Compute the next permuation
    uint32_t steps = (timestamp - HASH_FUNC_BASE_TIMESTAMP)%HASH_FUNC_COUNT_PERMUTATIONS;
    for (uint32_t i=0; i < steps; i++) {
        std::next_permutation(permutation, permutation + HASH_FUNC_COUNT);
    }

    for (uint32_t i=0; i < HASH_FUNC_COUNT; i++) {
	    switch(permutation[i]) {
            case 0:
                sph_blake512_init(&ctx_blake);
                if (i == 0)
                    sph_blake512 (&ctx_blake, input, 80);
                else
                    sph_blake512 (&ctx_blake, hash + (i*64)-64, 64);                
                sph_blake512_close(&ctx_blake, hash + (i*64));
            break;
            case 1:
                sph_bmw512_init(&ctx_bmw);
                if (i == 0)
                    sph_bmw512 (&ctx_bmw, input, 80);
                else
                    sph_bmw512 (&ctx_bmw, hash + (i*64)-64, 64);
                sph_bmw512_close(&ctx_bmw, hash + (i*64));
            break;
            case 2:
                sph_groestl512_init(&ctx_groestl);
                if (i == 0)
                    sph_groestl512 (&ctx_groestl, input, 80);
                else
                    sph_groestl512 (&ctx_groestl, hash + (i*64)-64, 64);
                sph_groestl512_close(&ctx_groestl, hash + (i*64));
            break;
            case 3:
                sph_skein512_init(&ctx_skein);
                if (i == 0)
                    sph_skein512 (&ctx_skein, input, 80);
                else
                    sph_skein512 (&ctx_skein, hash + (i*64)-64, 64);
                sph_skein512_close(&ctx_skein, hash + (i*64));
            break;
            case 4:
                sph_jh512_init(&ctx_jh);
                if (i == 0)
                    sph_jh512 (&ctx_jh, input, 80);
                else
                    sph_jh512 (&ctx_jh, hash + (i*64)-64, 64);
                sph_jh512_close(&ctx_jh, hash + (i*64));
            break;
            case 5:
                sph_keccak512_init(&ctx_keccak);
                if (i == 0)
                    sph_keccak512 (&ctx_keccak, input, 80);
                else
                    sph_keccak512 (&ctx_keccak, hash + (i*64)-64, 64);
                sph_keccak512_close(&ctx_keccak, hash + (i*64));
            break;
            case 6:
                sph_luffa512_init(&ctx_luffa);
                if (i == 0)
                    sph_luffa512 (&ctx_luffa, input, 80);
                else
                    sph_luffa512 (&ctx_luffa, static_cast<void*>(&hash[i-1]), 64);
                sph_luffa512_close(&ctx_luffa, hash + (i*64));
            break;
            case 7:
                sph_cubehash512_init(&ctx_cubehash);
                if (i == 0)
                    sph_cubehash512 (&ctx_cubehash, input, 80);
                else
                    sph_cubehash512 (&ctx_cubehash, hash + (i*64)-64, 64);
                sph_cubehash512_close(&ctx_cubehash, hash + (i*64));
            break;
            case 8:
                sph_shavite512_init(&ctx_shavite);
                if (i == 0)
                    sph_shavite512 (&ctx_shavite, input, 80);
                else
                    sph_shavite512(&ctx_shavite, hash + (i*64)-64, 64);
                sph_shavite512_close(&ctx_shavite, hash + (i*64));
            break;
            case 9:
                sph_simd512_init(&ctx_simd);
                if (i == 0)
                    sph_simd512 (&ctx_simd, input, 80);
                else
                    sph_simd512 (&ctx_simd, hash + (i*64)-64, 64);
                sph_simd512_close(&ctx_simd, hash + (i*64));
            break;
            case 10:
                sph_echo512_init(&ctx_echo);
                if (i == 0)
                    sph_echo512 (&ctx_echo, input, 80);
                else
                    sph_echo512 (&ctx_echo, hash + (i*64)-64, 64);
                sph_echo512_close(&ctx_echo, hash + (i*64));
            break;
	    }
    }

    std::memcpy(output, hash + HASH_FUNC_COUNT-64, 32);
}