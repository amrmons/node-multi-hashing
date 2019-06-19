#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "argon2/hashargon.h"


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
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_haval.h"
#include "sha3/sph_streebog.h"
#include "sha3/sph_sha2.h"
#include "lyra2.h"

#define START_OF_LAST_23_NIBBLES_OF_HASH 41

int GetNibble(unsigned char *pBlockBegin, int index) const 
{
    index = 63 - index;
    if (index % 2 == 1)
        return(*pBlockBegin[index / 2] >> 4);
    return(*pBlockBegin[index / 2] & 0x0F); 
} 

void cpu23r_hash(const char* input, char* output)
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
    sph_hamsi512_context     ctx_hamsi;
    sph_fugue512_context     ctx_fugue;
    sph_shabal512_context    ctx_shabal;
    sph_whirlpool_context    ctx_whirlpool;
    sph_sha512_context       ctx_sha512;

    sph_haval256_5_context   ctx_haval;
    sph_blake256_context     ctx_blake256;
    sph_gost512_context      ctx_gost;
    sph_sha256_context       ctx_sha256;

    unsigned int t_costs = 2;
    unsigned int m_costs = 16;
    unsigned char prevBlockBytes[32];
    uint8_t hash[64*23];
    size_t index = 0;
    int hashSelection;
    
    memcpy(prevBlockBytes, input + 4, 32);

    for (int i=0;i<23;i++) 
    {
        const void *toHash;
        int lenToHash;
        if (i == 0) {
            toHash = input;
            lenToHash = 80;
        } else {
            index = (64*i)-64;
            toHash = hash[index];
            lenToHash = 64;
        }

        hashSelection = getCurrentHash(prevBlockBytes, START_OF_LAST_23_NIBBLES_OF_HASH + i);

        switch(hashSelection) {
            case 0:
                sph_blake512_init(&ctx_blake);
                sph_blake512 (&ctx_blake, toHash, lenToHash);
                sph_blake512_close(&ctx_blake, hash);
                break;
            case 1:
                sph_bmw512_init(&ctx_bmw);
                sph_bmw512 (&ctx_bmw, toHash, lenToHash);
                sph_bmw512_close(&ctx_bmw, hash);
                break;
            case 2:
                sph_groestl512_init(&ctx_groestl);
                sph_groestl512 (&ctx_groestl, toHash, lenToHash);
                sph_groestl512_close(&ctx_groestl, hash);
                break;
            case 3:
                sph_jh512_init(&ctx_jh);
                sph_jh512 (&ctx_jh, toHash, lenToHash);
                sph_jh512_close(&ctx_jh, hash);
                break;
            case 4:
                sph_keccak512_init(&ctx_keccak);
                sph_keccak512 (&ctx_keccak, toHash, lenToHash);
                sph_keccak512_close(&ctx_keccak, hash);
                break;
            case 5:
                sph_skein512_init(&ctx_skein);
                sph_skein512 (&ctx_skein, toHash, lenToHash);
                sph_skein512_close(&ctx_skein, hash);
                break;
            case 6:
                sph_luffa512_init(&ctx_luffa);
                sph_luffa512 (&ctx_luffa, toHash, lenToHash);
                sph_luffa512_close(&ctx_luffa, hash);
                break;
            case 7:
                sph_cubehash512_init(&ctx_cubehash);
                sph_cubehash512 (&ctx_cubehash, toHash, lenToHash);
                sph_cubehash512_close(&ctx_cubehash, hash);
                break;
            case 8:
                sph_shavite512_init(&ctx_shavite);
                sph_shavite512(&ctx_shavite, toHash, lenToHash);
                sph_shavite512_close(&ctx_shavite, hash);
                break;
            case 9:
                sph_simd512_init(&ctx_simd);
                sph_simd512 (&ctx_simd, toHash, lenToHash);
                sph_simd512_close(&ctx_simd, hash);
                break;
            case 10:
                sph_echo512_init(&ctx_echo);
                sph_echo512 (&ctx_echo, toHash, lenToHash);
                sph_echo512_close(&ctx_echo, hash);
                break;
            case 11:
                sph_hamsi512_init(&ctx_hamsi);
                sph_hamsi512 (&ctx_hamsi, toHash, lenToHash);
                sph_hamsi512_close(&ctx_hamsi, hash);
                break;
            case 12:
                sph_fugue512_init(&ctx_fugue);
                sph_fugue512 (&ctx_fugue, toHash, lenToHash);
                sph_fugue512_close(&ctx_fugue, hash);
                break;
            case 13:
                sph_shabal512_init(&ctx_shabal);
                sph_shabal512 (&ctx_shabal, toHash, lenToHash);
                sph_shabal512_close(&ctx_shabal, hash);
                break;
            case 14:
                sph_whirlpool_init(&ctx_whirlpool);
                sph_whirlpool(&ctx_whirlpool, toHash, lenToHash);
                sph_whirlpool_close(&ctx_whirlpool, hash);
                break;
            case 15:
                sph_sha512_init(&ctx_sha512);
                sph_sha512 (&ctx_sha512, toHash, lenToHash);
                sph_sha512_close(&ctx_sha512, hash);
                break;
            case 16:
                sph_haval256_5_init(&ctx_haval);
                sph_haval256_5 (&ctx_haval, toHash, lenToHash);
                sph_haval256_5_close(&ctx_haval, hash);
                break;
            case 17:
                sph_blake256_init(&ctx_blake256);
                sph_blake256 (&ctx_blake256, toHash, lenToHash);
                sph_blake256_close(&ctx_blake256, hash);
                break;
            case 18:
                LYRA2(hash, lenToHash, toHash, lenToHash, toHash, lenToHash, 1, 4, 4);
                break;
            case 19:
                sph_gost512_init(&ctx_gost);
                sph_gost512 (&ctx_gost, toHash, lenToHash);
                sph_gost512_close(&ctx_gost, hash);
                break;
            case 20:
                sph_sha256_init(&ctx_sha256);
                sph_sha256 (&ctx_sha256, toHash, lenToHash);
                sph_sha256_close(&ctx_sha256, hash);
                break;
            case 21:
                cpu23R_hash_argon2d(hash, lenToHash, toHash, lenToHash, toHash, lenToHash, t_costs, m_costs);
                break;
            case 22:
                cpu23R_hash_argon2i(hash, lenToHash, toHash, lenToHash, toHash, lenToHash, t_costs, m_costs);
                break;
        }
    }
    
    memcpy(output, hash + 22*64, 32);
}
