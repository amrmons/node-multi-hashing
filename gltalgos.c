#include "gltalgos.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake/blake2.h"
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
#include "sha3/sph_sha2.h"
#include "sha3/sph_haval.h"
#include "sha3/sph_gost.h"


void pawelhash(const char* input, char* output, uint32_t len)
{
    sph_fugue512_context     ctx_fugue;
    sph_sha512_context       ctx_sha2;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_luffa512_context     ctx_luffa;
    sph_whirlpool_context    ctx_whirlpool;
    sph_shabal512_context    ctx_shabal;
    sph_echo512_context      ctx_echo;
    sph_groestl512_context   ctx_groestl;
    sph_haval256_5_context   ctx_haval;
    sph_bmw512_context       ctx_bmw;
    sph_gost512_context      ctx_gost;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];	

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512(&ctx_fugue, input, len);
    sph_fugue512_close(&ctx_fugue, hashA);

    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashA, 64);
    sph_sha512_close(&ctx_sha2, hashB);
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashB, 64);
    sph_skein512_close(&ctx_skein, hashA);

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashA, 64);
    sph_jh512_close(&ctx_jh, hashB);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hashB, 64);
    sph_keccak512_close(&ctx_keccak, hashA);
    
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hashA, 64);
    sph_luffa512_close(&ctx_luffa, hashB);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashB, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashA);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashA, 64);
    sph_shabal512_close(&ctx_shabal, hashB);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashB, 64);
    sph_echo512_close(&ctx_echo, hashA);
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hashA, 64);
    sph_groestl512_close(&ctx_groestl, hashB);
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hashB, 64);
    sph_haval256_5_close(&ctx_haval, hashA);
    
    memset(&hashA[8], 0, 32);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashB, 64);
    sph_echo512_close(&ctx_echo, hashA);
    
    sph_fugue512_init(&ctx_fugue);
    sph_fugue512(&ctx_fugue, hashA, 64);
    sph_fugue512_close(&ctx_fugue, hashB);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);

    sph_gost512_init(&ctx_gost);
    sph_gost512(&ctx_gost, hashA, 64);
    sph_gost512_close(&ctx_gost, hashB);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashB, 64);
    sph_shabal512_close(&ctx_shabal, hashA);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashA, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashB);
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashB, 64);
    sph_groestl512_close(&ctx_groestl, hashA);

    memcpy(output, hashA, 32);
}

void jeonghash(const char* input, char* output, uint32_t len)
{
    sph_simd512_context      ctx_simd;
    sph_hamsi512_context     ctx_hamsi;
    sph_shabal512_context    ctx_shabal;
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_sha512_context       ctx_sha2;
    sph_whirlpool_context    ctx_whirlpool;
    sph_skein512_context     ctx_skein;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];

    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, input, len);
    sph_simd512_close(&ctx_simd, hashA);

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashA, 64);
    sph_hamsi512_close(&ctx_hamsi, hashB);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashB, 64);
    sph_shabal512_close(&ctx_shabal, hashA);
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hashA, 64);
    sph_blake512_close(&ctx_blake, hashB);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashA, 64);
    sph_sha512_close(&ctx_sha2, hashB);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashB, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashA);
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hashB);
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashB, 64);
    sph_skein512_close(&ctx_skein, hashA);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashA, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashB);
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashB, 64);
    sph_sha512_close(&ctx_sha2, hashA);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hashB, 64);
    sph_blake512_close(&ctx_blake, hashA);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashA, 64);
    sph_shabal512_close(&ctx_shabal, hashB);
    
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashB, 64);
    sph_hamsi512_close(&ctx_hamsi, hashA);
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hashA, 64);
    sph_simd512_close(&ctx_simd, hashB);
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hashB, 64);
    sph_simd512_close(&ctx_simd, hashA);

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashA, 64);
    sph_hamsi512_close(&ctx_hamsi, hashB);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashB, 64);
    sph_shabal512_close(&ctx_shabal, hashA);
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hashA, 64);
    sph_blake512_close(&ctx_blake, hashB);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashA, 64);
    sph_sha512_close(&ctx_sha2, hashB);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashB, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashA);
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hashB);

    memcpy(output, hashB, 32);
}

void astralhash(const char* input, char* output, uint32_t len)
{
    sph_luffa512_context     ctx_luffa;
    sph_skein512_context     ctx_skein;
    sph_echo512_context      ctx_echo;
    sph_whirlpool_context    ctx_whirlpool;
    sph_bmw512_context       ctx_bmw; 
    sph_blake512_context     ctx_blake;
    sph_shavite512_context   ctx_shavite;
    sph_fugue512_context     ctx_fugue;
    sph_hamsi512_context     ctx_hamsi;
    sph_haval256_5_context   ctx_haval;
    sph_sha512_context       ctx_sha2;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];	

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, input, len);
    sph_luffa512_close(&ctx_luffa, hashA);

    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hashB);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashB, 64);
    sph_echo512_close(&ctx_echo, hashA);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashA, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashB);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hashA, 64);
    sph_blake512_close(&ctx_blake, hashB);
    
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hashB, 64);
    sph_shavite512_close(&ctx_shavite, hashA);
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hashB);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashB, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashA);
    
    sph_fugue512_init(&ctx_fugue);
    sph_fugue512(&ctx_fugue, hashA, 64);
    sph_fugue512_close(&ctx_fugue, hashB);
    
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashB, 64);
    sph_hamsi512_close(&ctx_hamsi, hashA);
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hashA, 64);
    sph_haval256_5_close(&ctx_haval, hashB);
    
    memset(&hashB[8], 0, 32);
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashB, 64);
    sph_sha512_close(&ctx_sha2, hashA);

    memcpy(output, hashA, 32);
}

void padihash(const char* input, char* output, uint32_t len)
{
    sph_sha512_context       ctx_sha2;
    sph_jh512_context        ctx_jh;
    sph_luffa512_context     ctx_luffa;
    sph_echo512_context      ctx_echo;
    sph_bmw512_context       ctx_bmw; 
    sph_haval256_5_context   ctx_haval;
    sph_cubehash512_context  ctx_cubehash;
    sph_shabal512_context    ctx_shabal;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];	

    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, input, len);
    sph_sha512_close(&ctx_sha2, hashA);

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashA, 64);
    sph_jh512_close(&ctx_jh, hashB);
    
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hashB, 64);
    sph_luffa512_close(&ctx_luffa, hashA);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashA, 64);
    sph_echo512_close(&ctx_echo, hashB);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hashA, 64);
    sph_haval256_5_close(&ctx_haval, hashB);
    
    memset(&hashB[8], 0, 32);
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hashB, 64);
    sph_cubehash512_close(&ctx_cubehash, hashA);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashA, 64);
    sph_shabal512_close(&ctx_shabal, hashB);
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashB, 64);
    sph_sha512_close(&ctx_sha2, hashA);

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashA, 64);
    sph_jh512_close(&ctx_jh, hashB);
    
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hashB, 64);
    sph_luffa512_close(&ctx_luffa, hashA);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashA, 64);
    sph_echo512_close(&ctx_echo, hashB);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hashA, 64);
    sph_haval256_5_close(&ctx_haval, hashB);
    
    memset(&hashB[8], 0, 32);
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hashB, 64);
    sph_cubehash512_close(&ctx_cubehash, hashA);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashA, 64);
    sph_shabal512_close(&ctx_shabal, hashB);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashB, 64);
    sph_shabal512_close(&ctx_shabal, hashA);
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hashA, 64);
    sph_cubehash512_close(&ctx_cubehash, hashB);
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hashB, 64);
    sph_haval256_5_close(&ctx_haval, hashA);
    
    memset(&hashA[8], 0, 32);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashB, 64);
    sph_echo512_close(&ctx_echo, hashA);
    
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hashA, 64);
    sph_luffa512_close(&ctx_luffa, hashB);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hashA);
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashA, 64);
    sph_sha512_close(&ctx_sha2, hashB);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hashA);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);

    memcpy(output, hashB, 32);
}

void globalhash(const char* input, char* output, uint32_t len)
{
    sph_gost512_context      ctx_gost;
    sph_blake512_context     ctx_blake;
    blake2b_state            ctx_blake2b[1];
    blake2s_state            ctx_blake2s[1];
    
    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16];
    
    sph_gost512_init(&ctx_gost);
    sph_gost512 (&ctx_gost, input, len); 
    sph_gost512_close(&ctx_gost, hashA);
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hashA, 64);
    sph_blake512_close(&ctx_blake, hashB);
    
    blake2b_init( ctx_blake2b, BLAKE2B_OUTBYTES );
    blake2b_update( ctx_blake2b, hashB, 64 );
    blake2b_final( ctx_blake2b, hashA, BLAKE2B_OUTBYTES );
    
    blake2s_init( ctx_blake2s, BLAKE2S_OUTBYTES );
    blake2s_update( ctx_blake2s, hashA, 64);
    blake2s_final( ctx_blake2s, output, BLAKE2S_OUTBYTES );
}

void arctichash(const char* input, char* output, uint32_t len)
{
    sph_whirlpool_context    ctx_whirlpool;
    sph_bmw512_context       ctx_bmw;
    sph_echo512_context      ctx_echo;
    sph_groestl512_context   ctx_groestl;
    sph_gost512_context      ctx_gost;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_blake512_context     ctx_blake;
    sph_cubehash512_context  ctx_cubehash;
    sph_simd512_context      ctx_simd;
    
    size_t nOutLen = 64;
    uint8_t hash[26 * 64] = {0};
    
    // Round 1
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, input, len);
    sph_whirlpool_close(&ctx_whirlpool, hash);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hash, nOutLen);
    sph_bmw512_close(&ctx_bmw, hash + 1*nOutLen);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash + 1*nOutLen, nOutLen);
    sph_echo512_close(&ctx_echo, hash + 2);
    
    LYRA2(hash + 3*nOutLen, nOutLen, hash + 2*nOutLen, nOutLen, hash + 2*nOutLen, nOutLen, 1, 8, 8);
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hash + 3*nOutLen, nOutLen);
    sph_groestl512_close(&ctx_groestl, hash + 4*nOutLen);
    
    sph_gost512_init(&ctx_gost);
    sph_gost512(&ctx_gost, hash + 4*nOutLen, nOutLen);
    sph_gost512_close(&ctx_gost, hash + 5*nOutLen);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hash + 5*nOutLen, nOutLen);
    sph_jh512_close(&ctx_jh, hash + 6*nOutLen);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hash + 6*nOutLen, nOutLen);
    sph_keccak512_close(&ctx_keccak, hash + 7*nOutLen);
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hash + 7*nOutLen, nOutLen);
    sph_blake512_close(&ctx_blake, hash + 8*nOutLen);
    
    // Round 2
    
    LYRA2(hash + 9*nOutLen, nOutLen, hash + 8*nOutLen, nOutLen, hash + 8*nOutLen, nOutLen, 1, 8, 8);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hash + 9*nOutLen, nOutLen);
    sph_whirlpool_close(&ctx_whirlpool, hash + 10*nOutLen);
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash + 10*nOutLen, nOutLen);
    sph_cubehash512_close(&ctx_cubehash, hash + 11*nOutLen);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hash + 11*nOutLen, nOutLen);
    sph_keccak512_close(&ctx_keccak, hash + 12*nOutLen);
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hash + 12*nOutLen, nOutLen);
    sph_groestl512_close(&ctx_groestl, hash + 13*nOutLen);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash + 13*nOutLen, nOutLen);
    sph_echo512_close(&ctx_echo, hash + 14*nOutLen);
    
    sph_gost512_init(&ctx_gost);
    sph_gost512(&ctx_gost, hash + 14*nOutLen, nOutLen);
    sph_gost512_close(&ctx_gost, hash + 15*nOutLen);
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash + 15*nOutLen, nOutLen);
    sph_simd512_close(&ctx_simd, hash + 16*nOutLen);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hash + 16*nOutLen, nOutLen);
    sph_bmw512_close(&ctx_bmw, hash + 17*nOutLen);
    
    // Round 3
    
    sph_gost512_init(&ctx_gost);
    sph_gost512(&ctx_gost, hash + 17*nOutLen, nOutLen);
    sph_gost512_close(&ctx_gost, hash + 18*nOutLen);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hash + 18*nOutLen, nOutLen);
    sph_keccak512_close(&ctx_keccak, hash + 19*nOutLen);
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash + 19*nOutLen, nOutLen);
    sph_cubehash512_close(&ctx_cubehash, hash + 20*nOutLen);
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hash + 20*nOutLen, nOutLen);
    sph_groestl512_close(&ctx_groestl, hash + 21*nOutLen);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hash + 21*nOutLen, nOutLen);
    sph_jh512_close(&ctx_jh, hash + 22*nOutLen);
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash + 22*nOutLen, nOutLen);
    sph_echo512_close(&ctx_echo, hash + 23*nOutLen);
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash + 23*nOutLen, nOutLen);
    sph_simd512_close(&ctx_simd, hash + 24*nOutLen);
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hash + 24*nOutLen, nOutLen);
    sph_blake512_close(&ctx_blake, hash + 25*nOutLen);
    
    LYRA2(output, 32, hash + 25*nOutLen, nOutLen, hash + 25*nOutLen, nOutLen, 1, 8, 8);
}

void deserthash(const char* input, char* output, uint32_t len)
{
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
    sph_blake512_context     ctx_blake512;
    sph_gost512_context      ctx_gost;
    sph_bmw512_context       ctx_bmw;
    blake2b_state            ctx_blake2b;

    // The final hash.
    sph_blake256_context     ctx_blake256;
    
    size_t nOutLen = 64;
    uint8_t hash[26 * 64] = {0};
    
    // Round 1: 4 base algos + 6 unique one's.
    
    /** BASE HASHES of DesertHash */
    
    blake2b_init( &ctx_blake2b, BLAKE2B_OUTBYTES );
    blake2b_update( &ctx_blake2b, input, len );
    blake2b_final( &ctx_blake2b, hash, BLAKE2B_OUTBYTES );
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash, BLAKE2B_OUTBYTES);
    sph_simd512_close(&ctx_simd, hash + 1*nOutLen);
    
    sph_sha512_init(&ctx_sha512);
    sph_sha512(&ctx_sha512, hash + 1*nOutLen, nOutLen);
    sph_sha512_close(&ctx_sha512, hash + 2*nOutLen);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hash + 2*nOutLen, nOutLen);
    sph_shabal512_close(&ctx_shabal, hash + 3*nOutLen);
    
    /** BASE HASHES of DesertHash END */
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hash + 3*nOutLen, nOutLen);
    sph_echo512_close(&ctx_echo, hash + 4*nOutLen);
    
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hash + 4*nOutLen, nOutLen);
    sph_hamsi512_close(&ctx_hamsi, hash + 5*nOutLen);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hash + 5*nOutLen, nOutLen);
    sph_keccak512_close(&ctx_keccak, hash + 6*nOutLen);
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hash + 6*nOutLen, nOutLen);
    sph_skein512_close(&ctx_skein, hash + 7*nOutLen);
    
    sph_blake512_init(&ctx_blake512);
    sph_blake512(&ctx_blake512, hash + 7*nOutLen, nOutLen);
    sph_blake512_close(&ctx_blake512, hash + 8*nOutLen);
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hash + 8*nOutLen, nOutLen);
    sph_whirlpool_close(&ctx_whirlpool, hash + 9*nOutLen);
    
    // Round 2: 4 base algos + 6 new one.
    
    /** BASE HASHES of DesertHash */
    
    blake2b_init( &ctx_blake2b, BLAKE2B_OUTBYTES );
    blake2b_update( &ctx_blake2b, hash + 9*nOutLen, nOutLen );
    blake2b_final( &ctx_blake2b, hash + 10*nOutLen, BLAKE2B_OUTBYTES );
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash + 10*nOutLen, BLAKE2B_OUTBYTES);
    sph_simd512_close(&ctx_simd, hash + 11*nOutLen);
    
    sph_sha512_init(&ctx_sha512);
    sph_sha512(&ctx_sha512, hash + 11*nOutLen, nOutLen);
    sph_sha512_close(&ctx_sha512, hash + 12*nOutLen);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hash + 12*nOutLen, nOutLen);
    sph_shabal512_close(&ctx_shabal, hash + 13*nOutLen);
    
    /** BASE HASHES of DesertHash END */
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hash + 13*nOutLen, nOutLen);
    sph_groestl512_close(&ctx_groestl, hash + 14*nOutLen);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hash + 14*nOutLen, nOutLen);
    sph_jh512_close(&ctx_jh, hash + 15*nOutLen);
    
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hash + 15*nOutLen, nOutLen);
    sph_luffa512_close(&ctx_luffa, hash + 16*nOutLen);
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hash + 16*nOutLen, nOutLen);
    sph_cubehash512_close(&ctx_cubehash, hash + 17*nOutLen);
    
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hash + 17*nOutLen, nOutLen);
    sph_shavite512_close(&ctx_shavite, hash + 18*nOutLen);
    
    sph_fugue512_init(&ctx_fugue);
    sph_fugue512(&ctx_fugue, hash + 18*nOutLen, nOutLen);
    sph_fugue512_close(&ctx_fugue, hash + 19*nOutLen);
    
    // Round 3: Finalize this hash: 4 base algos + 2 unique one's + final blake256.
    
    /** BASE HASHES of DesertHash */
    
    blake2b_init( &ctx_blake2b, BLAKE2B_OUTBYTES );
    blake2b_update( &ctx_blake2b, hash + 19*nOutLen, nOutLen );
    blake2b_final( &ctx_blake2b, hash + 20*nOutLen, BLAKE2B_OUTBYTES );
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hash + 20*nOutLen, BLAKE2B_OUTBYTES);
    sph_simd512_close(&ctx_simd, hash + 21*nOutLen);
    
    sph_sha512_init(&ctx_sha512);
    sph_sha512(&ctx_sha512, hash + 21*nOutLen, nOutLen);
    sph_sha512_close(&ctx_sha512, hash + 22*nOutLen);
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hash + 22*nOutLen, nOutLen);
    sph_shabal512_close(&ctx_shabal, hash + 23*nOutLen);
    
    /** BASE HASHES of DesertHash END */
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hash + 23*nOutLen, nOutLen);
    sph_bmw512_close(&ctx_bmw, hash + 24*nOutLen);
    
    sph_gost512_init(&ctx_gost);
    sph_gost512(&ctx_gost, hash + 24*nOutLen, nOutLen);
    sph_gost512_close(&ctx_gost, hash + 25*nOutLen);
    
    sph_blake256_init(&ctx_blake256);
    sph_blake256 (&ctx_blake256, hash + 25*nOutLen, nOutLen);
    sph_blake256_close(&ctx_blake256, output);
}

void cryptoandcoffee_hash(const char* input, char* output, uint32_t len)
{
    blake2s_state             ctx_blake2s;
    sph_blake512_context      ctx_blake;
    sph_bmw512_context        ctx_bmw;
    sph_groestl512_context    ctx_groestl;
    sph_jh512_context         ctx_jh;
    sph_keccak512_context     ctx_keccak;
    sph_skein256_context      ctx_skein256;
    sph_skein512_context      ctx_skein512;
    sph_luffa512_context      ctx_luffa;
    sph_cubehash512_context   ctx_cubehash;
    sph_shavite512_context    ctx_shavite;
    sph_simd512_context       ctx_simd;
    sph_echo512_context       ctx_echo;
    sph_hamsi512_context      ctx_hamsi;
    sph_fugue512_context      ctx_fugue;
    sph_shabal512_context     ctx_shabal;
    sph_whirlpool_context     ctx_whirlpool;
    sph_sha512_context        ctx_sha2;
    sph_haval256_5_context    ctx_haval;
    sph_bmw256_context        ctx_bmw_final;
    
    size_t nHashlen64 = 64, nHashlen32 = 32;
    uint8_t hashRound1[16 * 64] = {0}, hashRound2[16 * 64] = {0}, hashRound3[5 * 64] = {0}, skeinOutHash[2 * 32] = {0}, blake2sOutHash[2 * 32] = {0}, havalOutHash[2 * 32] = {0};
    
    // Base hashes: skein256, blake2s (256 bit). Round 1
    
    sph_skein256_init(&ctx_skein256);
    sph_skein256(&ctx_skein256, input, len);
    sph_skein256_close(&ctx_skein256, skeinOutHash);
    
    blake2s_init( &ctx_blake2s, BLAKE2S_OUTBYTES );
    blake2s_update( &ctx_blake2s, skeinOutHash, 32);
    blake2s_final( &ctx_blake2s, blake2sOutHash, BLAKE2S_OUTBYTES );
    
    // Base hashes end. (Round 1)
    // X17 hashes Round 1.
    
    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, blake2sOutHash, BLAKE2S_OUTBYTES);
    sph_blake512_close(&ctx_blake, hashRound1);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashRound1, nHashlen64);
    sph_bmw512_close(&ctx_bmw, hashRound1 + 1*nHashlen64);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashRound1 + 1*nHashlen64, nHashlen64);
    sph_groestl512_close(&ctx_groestl, hashRound1 + 2*nHashlen64);

    sph_skein512_init(&ctx_skein512);
    sph_skein512 (&ctx_skein512, hashRound1 + 2*nHashlen64, nHashlen64);
    sph_skein512_close(&ctx_skein512, hashRound1 + 3*nHashlen64);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashRound1 + 3*nHashlen64, nHashlen64);
    sph_jh512_close(&ctx_jh, hashRound1 + 4*nHashlen64);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashRound1 + 4*nHashlen64, nHashlen64);
    sph_keccak512_close(&ctx_keccak, hashRound1 + 5*nHashlen64);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, hashRound1 + 5*nHashlen64, nHashlen64);
    sph_luffa512_close(&ctx_luffa, hashRound1 + 6*nHashlen64);
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, hashRound1 + 6*nHashlen64, nHashlen64);
    sph_cubehash512_close(&ctx_cubehash, hashRound1 + 7*nHashlen64);
    
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hashRound1 + 7*nHashlen64, nHashlen64);
    sph_shavite512_close(&ctx_shavite, hashRound1 + 8*nHashlen64);
        
    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, hashRound1 + 8*nHashlen64, nHashlen64);
    sph_simd512_close(&ctx_simd, hashRound1 + 9*nHashlen64);

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, hashRound1 + 9*nHashlen64, nHashlen64);
    sph_echo512_close(&ctx_echo, hashRound1 + 10*nHashlen64);

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, hashRound1 + 10*nHashlen64, nHashlen64);
    sph_hamsi512_close(&ctx_hamsi, hashRound1 + 11*nHashlen64);

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashRound1 + 11*nHashlen64, nHashlen64);
    sph_fugue512_close(&ctx_fugue, hashRound1 + 12*nHashlen64);

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, hashRound1 + 12*nHashlen64, nHashlen64);
    sph_shabal512_close(&ctx_shabal, hashRound1 + 13*nHashlen64);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashRound1 + 13*nHashlen64, nHashlen64);
    sph_whirlpool_close(&ctx_whirlpool, hashRound1 + 14*nHashlen64);

    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashRound1 + 14*nHashlen64, nHashlen64);
    sph_sha512_close(&ctx_sha2, hashRound1 + 15*nHashlen64);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hashRound1 + 15*nHashlen64, nHashlen64);
    sph_haval256_5_close(&ctx_haval, havalOutHash);
    
    // X17 hashes END (Round 1.)
    // Base hashes: skein256, blake2s (256 bit). Round 2
    
    sph_skein256_init(&ctx_skein256);
    sph_skein256(&ctx_skein256, havalOutHash, 32);
    sph_skein256_close(&ctx_skein256, skeinOutHash +1*nHashlen32);
    
    blake2s_init( &ctx_blake2s, BLAKE2S_OUTBYTES );
    blake2s_update( &ctx_blake2s, skeinOutHash +1*nHashlen32, 32);
    blake2s_final( &ctx_blake2s, blake2sOutHash +1*nHashlen32, BLAKE2S_OUTBYTES );
    
    // Base hashes end. (Round 2)
    // X17 hashes Round 2.
    
    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, blake2sOutHash +1*nHashlen32, BLAKE2S_OUTBYTES);
    sph_blake512_close(&ctx_blake, hashRound2);
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashRound2, nHashlen64);
    sph_bmw512_close(&ctx_bmw, hashRound2 + 1*nHashlen64);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashRound2 + 1*nHashlen64, nHashlen64);
    sph_groestl512_close(&ctx_groestl, hashRound2 + 2*nHashlen64);

    sph_skein512_init(&ctx_skein512);
    sph_skein512 (&ctx_skein512, hashRound2 + 2*nHashlen64, nHashlen64);
    sph_skein512_close(&ctx_skein512, hashRound2 + 3*nHashlen64);
    
    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashRound2 + 3*nHashlen64, nHashlen64);
    sph_jh512_close(&ctx_jh, hashRound2 + 4*nHashlen64);
    
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashRound2 + 4*nHashlen64, nHashlen64);
    sph_keccak512_close(&ctx_keccak, hashRound2 + 5*nHashlen64);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, hashRound2 + 5*nHashlen64, nHashlen64);
    sph_luffa512_close(&ctx_luffa, hashRound2 + 6*nHashlen64);
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, hashRound2 + 6*nHashlen64, nHashlen64);
    sph_cubehash512_close(&ctx_cubehash, hashRound2 + 7*nHashlen64);
    
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hashRound2 + 7*nHashlen64, nHashlen64);
    sph_shavite512_close(&ctx_shavite, hashRound2 + 8*nHashlen64);
        
    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, hashRound2 + 8*nHashlen64, nHashlen64);
    sph_simd512_close(&ctx_simd, hashRound2 + 9*nHashlen64);

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, hashRound2 + 9*nHashlen64, nHashlen64);
    sph_echo512_close(&ctx_echo, hashRound2 + 10*nHashlen64);

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, hashRound2 + 10*nHashlen64, nHashlen64);
    sph_hamsi512_close(&ctx_hamsi, hashRound2 + 11*nHashlen64);

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashRound2 + 11*nHashlen64, nHashlen64);
    sph_fugue512_close(&ctx_fugue, hashRound2 + 12*nHashlen64);

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, hashRound2 + 12*nHashlen64, nHashlen64);
    sph_shabal512_close(&ctx_shabal, hashRound2 + 13*nHashlen64);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashRound2 + 13*nHashlen64, nHashlen64);
    sph_whirlpool_close(&ctx_whirlpool, hashRound2 + 14*nHashlen64);

    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashRound2 + 14*nHashlen64, nHashlen64);
    sph_sha512_close(&ctx_sha2, hashRound2 + 15*nHashlen64);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hashRound2 + 15*nHashlen64, nHashlen64);
    sph_haval256_5_close(&ctx_haval, havalOutHash + 1*nHashlen32);
    
    // X17 hashes END (Round 2.)
    // Round 3: Nist 5 hashes
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, havalOutHash + 1*nHashlen32, nHashlen32);
    sph_blake512_close(&ctx_blake, hashRound3);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hashRound3, nHashlen64);
    sph_groestl512_close(&ctx_groestl, hashRound3 + 1*nHashlen64);

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashRound3 + 1*nHashlen64, nHashlen64);
    sph_jh512_close(&ctx_jh, hashRound3 + 2*nHashlen64);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hashRound3 + 2*nHashlen64, nHashlen64);
    sph_keccak512_close(&ctx_keccak, hashRound3 + 3*nHashlen64);

    sph_skein512_init(&ctx_skein512);
    sph_skein512(&ctx_skein512, hashRound3 + 3*nHashlen64, nHashlen64);
    sph_skein512_close(&ctx_skein512, hashRound3 + 4*nHashlen64);
    
    // Finalize the hash now!
    sph_bmw256_init(&ctx_bmw_final);
    sph_bmw256 (&ctx_bmw_final, hashRound3 + 4*nHashlen64, nHashlen64);
    sph_bmw256_close(&ctx_bmw_final, output);
}

void rickhash(const char* input, char* output, uint32_t len)
{
    // 32 bytes
    sph_blake256_context      ctx_blake256;
    sph_bmw256_context        ctx_bmw256;
    sph_groestl256_context    ctx_groestl256;
    sph_jh256_context         ctx_jh256;
    sph_keccak256_context     ctx_keccak256;
    sph_skein256_context      ctx_skein256;
    sph_luffa256_context      ctx_luffa256;
    sph_cubehash256_context   ctx_cubehash256;
    sph_shavite256_context    ctx_shavite256;
    sph_simd256_context       ctx_simd256;
    sph_echo256_context       ctx_echo256;
    sph_hamsi256_context      ctx_hamsi256;
    sph_fugue256_context      ctx_fugue256;
    sph_shabal256_context     ctx_shabal256;
    sph_sha256_context        ctx_sha256;
    sph_haval256_5_context    ctx_haval256;
    
    // 64 bytes
    sph_blake512_context      ctx_blake512;
    sph_bmw512_context        ctx_bmw512;
    sph_groestl512_context    ctx_groestl512;
    sph_jh512_context         ctx_jh512;
    sph_keccak512_context     ctx_keccak512;
    sph_skein512_context      ctx_skein512;
    sph_luffa512_context      ctx_luffa512;
    sph_cubehash512_context   ctx_cubehash512;
    sph_shavite512_context    ctx_shavite512;
    sph_simd512_context       ctx_simd512;
    sph_echo512_context       ctx_echo512;
    sph_hamsi512_context      ctx_hamsi512;
    sph_fugue512_context      ctx_fugue512;
    sph_shabal512_context     ctx_shabal512;
    sph_whirlpool_context     ctx_whirlpool512;
    sph_sha512_context        ctx_sha512;
    
    // Blake2 Stuff
    blake2b_state             ctx_blake2b;
    blake2s_state             ctx_blake2s;
    
    size_t nHashlen32 = 32, nHashlen64 = 64;
    uint8_t h256Hashes[18 * 32] = {0}, h512Hashes[18 * 64] = {0}, finalhash512[64] = {0};
    
    // First of all we hash everything with 64 bytes.
    
    sph_shavite512_init(&ctx_shavite512);
    sph_shavite512(&ctx_shavite512, input, len);
    sph_shavite512_close(&ctx_shavite512, h512Hashes);
    
    blake2b_init( &ctx_blake2b, BLAKE2B_OUTBYTES );
    blake2b_update( &ctx_blake2b, h512Hashes, nHashlen64 );
    blake2b_final( &ctx_blake2b, h512Hashes + 1*nHashlen64, BLAKE2B_OUTBYTES );
    
    sph_bmw512_init(&ctx_bmw512);
    sph_bmw512 (&ctx_bmw512, h512Hashes + 1*nHashlen64, nHashlen64);
    sph_bmw512_close(&ctx_bmw512, h512Hashes + 2*nHashlen64);
    
    sph_sha512_init(&ctx_sha512);
    sph_sha512 (&ctx_sha512, h512Hashes + 2*nHashlen64, nHashlen64);
    sph_sha512_close(&ctx_sha512, h512Hashes + 3*nHashlen64);
    
    sph_blake512_init(&ctx_blake512);
    sph_blake512 (&ctx_blake512, h512Hashes + 3*nHashlen64, nHashlen64);
    sph_blake512_close(&ctx_blake512, h512Hashes + 4*nHashlen64);
    
    sph_echo512_init(&ctx_echo512);
    sph_echo512 (&ctx_echo512, h512Hashes + 4*nHashlen64, nHashlen64);
    sph_echo512_close(&ctx_echo512, h512Hashes + 5*nHashlen64);
    
    LYRA2(h512Hashes + 6*nHashlen64, nHashlen64, h512Hashes + 5*nHashlen64, nHashlen64, h512Hashes + 5*nHashlen64, nHashlen64, 1, 4, 4);
    
    sph_shabal512_init(&ctx_shabal512);
    sph_shabal512 (&ctx_shabal512, h512Hashes + 6*nHashlen64, nHashlen64);
    sph_shabal512_close(&ctx_shabal512, h512Hashes + 7*nHashlen64);
    
    sph_simd512_init(&ctx_simd512);
    sph_simd512 (&ctx_simd512, h512Hashes + 7*nHashlen64, nHashlen64);
    sph_simd512_close(&ctx_simd512, h512Hashes + 8*nHashlen64);
    
    sph_jh512_init(&ctx_jh512);
    sph_jh512 (&ctx_jh512, h512Hashes + 8*nHashlen64, nHashlen64);
    sph_jh512_close(&ctx_jh512, h512Hashes + 9*nHashlen64);
    
    sph_keccak512_init(&ctx_keccak512);
    sph_keccak512 (&ctx_keccak512, h512Hashes + 9*nHashlen64, nHashlen64);
    sph_keccak512_close(&ctx_keccak512, h512Hashes + 10*nHashlen64);
    
    sph_groestl512_init(&ctx_groestl512);
    sph_groestl512 (&ctx_groestl512, h512Hashes + 10*nHashlen64, nHashlen64);
    sph_groestl512_close(&ctx_groestl512, h512Hashes + 11*nHashlen64);
    
    sph_skein512_init(&ctx_skein512);
    sph_skein512 (&ctx_skein512, h512Hashes + 11*nHashlen64, nHashlen64);
    sph_skein512_close(&ctx_skein512, h512Hashes + 12*nHashlen64);
    
    sph_luffa512_init(&ctx_luffa512);
    sph_luffa512 (&ctx_luffa512, h512Hashes + 12*nHashlen64, nHashlen64);
    sph_luffa512_close(&ctx_luffa512, h512Hashes + 13*nHashlen64);
    
    sph_hamsi512_init(&ctx_hamsi512);
    sph_hamsi512 (&ctx_hamsi512, h512Hashes + 13*nHashlen64, nHashlen64);
    sph_hamsi512_close(&ctx_hamsi512, h512Hashes + 14*nHashlen64);
    
    LYRA2(h512Hashes + 15*nHashlen64, nHashlen64, h512Hashes + 14*nHashlen64, nHashlen64, h512Hashes + 14*nHashlen64, nHashlen64, 1, 8, 8);
    
    sph_fugue512_init(&ctx_fugue512);
    sph_fugue512 (&ctx_fugue512, h512Hashes + 15*nHashlen64, nHashlen64);
    sph_fugue512_close(&ctx_fugue512, h512Hashes + 16*nHashlen64);
    
    sph_whirlpool_init(&ctx_whirlpool512);
    sph_whirlpool (&ctx_whirlpool512, h512Hashes + 16*nHashlen64, nHashlen64);
    sph_whirlpool_close(&ctx_whirlpool512, h512Hashes + 17*nHashlen64);
    
    sph_cubehash512_init(&ctx_cubehash512);
    sph_cubehash512 (&ctx_cubehash512, h512Hashes + 17*nHashlen64, nHashlen64);
    sph_cubehash512_close(&ctx_cubehash512, finalhash512);
    
    // Now we hash everything with 32 bytes.
    
    sph_shavite256_init(&ctx_shavite256);
    sph_shavite256(&ctx_shavite256, finalhash512, 64);
    sph_shavite256_close(&ctx_shavite256, h256Hashes);
    
    blake2s_init( &ctx_blake2s, BLAKE2S_OUTBYTES );
    blake2s_update( &ctx_blake2s, h256Hashes, nHashlen32 );
    blake2s_final( &ctx_blake2s, h256Hashes + 1*nHashlen32, BLAKE2S_OUTBYTES );
    
    sph_bmw256_init(&ctx_bmw256);
    sph_bmw256 (&ctx_bmw256, h256Hashes + 1*nHashlen32, nHashlen32);
    sph_bmw256_close(&ctx_bmw256, h256Hashes + 2*nHashlen32);
    
    sph_sha256_init(&ctx_sha256);
    sph_sha256 (&ctx_sha256, h256Hashes + 2*nHashlen32, nHashlen32);
    sph_sha256_close(&ctx_sha256, h256Hashes + 3*nHashlen32);
    
    sph_blake256_init(&ctx_blake256);
    sph_blake256 (&ctx_blake256, h256Hashes + 3*nHashlen32, nHashlen32);
    sph_blake256_close(&ctx_blake256, h256Hashes + 4*nHashlen32);
    
    sph_echo256_init(&ctx_echo256);
    sph_echo256 (&ctx_echo256, h256Hashes + 4*nHashlen32, nHashlen32);
    sph_echo256_close(&ctx_echo256, h256Hashes + 5*nHashlen32);
    
    LYRA2(h256Hashes + 6*nHashlen32, nHashlen32, h256Hashes + 5*nHashlen32, nHashlen32, h256Hashes + 5*nHashlen32, nHashlen32, 1, 4, 4);
    
    sph_shabal256_init(&ctx_shabal256);
    sph_shabal256 (&ctx_shabal256, h256Hashes + 6*nHashlen32, nHashlen32);
    sph_shabal256_close(&ctx_shabal256, h256Hashes + 7*nHashlen32);
    
    sph_simd256_init(&ctx_simd256);
    sph_simd256 (&ctx_simd256, h256Hashes + 7*nHashlen32, nHashlen32);
    sph_simd256_close(&ctx_simd256, h256Hashes + 8*nHashlen32);
    
    sph_jh256_init(&ctx_jh256);
    sph_jh256 (&ctx_jh256, h256Hashes + 8*nHashlen32, nHashlen32);
    sph_jh256_close(&ctx_jh256, h256Hashes + 9*nHashlen32);
    
    sph_keccak256_init(&ctx_keccak256);
    sph_keccak256 (&ctx_keccak256, h256Hashes + 9*nHashlen32, nHashlen32);
    sph_keccak256_close(&ctx_keccak256, h256Hashes + 10*nHashlen32);
    
    sph_groestl256_init(&ctx_groestl256);
    sph_groestl256 (&ctx_groestl256, h256Hashes + 10*nHashlen32, nHashlen32);
    sph_groestl256_close(&ctx_groestl256, h256Hashes + 11*nHashlen32);
    
    sph_skein256_init(&ctx_skein256);
    sph_skein256 (&ctx_skein256, h256Hashes + 11*nHashlen32, nHashlen32);
    sph_skein256_close(&ctx_skein256, h256Hashes + 12*nHashlen32);
    
    sph_luffa256_init(&ctx_luffa256);
    sph_luffa256 (&ctx_luffa256, h256Hashes + 12*nHashlen32, nHashlen32);
    sph_luffa256_close(&ctx_luffa256, h256Hashes + 13*nHashlen32);
    
    sph_hamsi256_init(&ctx_hamsi256);
    sph_hamsi256 (&ctx_hamsi256, h256Hashes + 13*nHashlen32, nHashlen32);
    sph_hamsi256_close(&ctx_hamsi256, h256Hashes + 14*nHashlen32);
    
    LYRA2(h256Hashes + 15*nHashlen32, nHashlen32, h256Hashes + 14*nHashlen32, nHashlen32, h256Hashes + 14*nHashlen32, nHashlen32, 1, 8, 8);
    
    sph_fugue256_init(&ctx_fugue256);
    sph_fugue256 (&ctx_fugue256, h256Hashes + 15*nHashlen32, nHashlen32);
    sph_fugue256_close(&ctx_fugue256, h256Hashes + 16*nHashlen32);
    
    sph_haval256_5_init(&ctx_haval256);
    sph_haval256_5 (&ctx_haval256, h256Hashes + 16*nHashlen32, nHashlen32);
    sph_haval256_5_close(&ctx_haval256, h256Hashes + 17*nHashlen32);
    
    sph_cubehash256_init(&ctx_cubehash256);
    sph_cubehash256 (&ctx_cubehash256, h256Hashes + 17*nHashlen32, nHashlen32);
    sph_cubehash256_close(&ctx_cubehash256, output);
}