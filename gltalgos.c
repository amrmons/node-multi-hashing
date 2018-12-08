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
    int ii = 0;
    
    printf("Starting Pawelhash, length = %d ... \n", len);
    
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
    
    printf("Pawelhash, fugue512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");

    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashA, 64);
    sph_sha512_close(&ctx_sha2, hashB);
    
    printf("Pawelhash, sha512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashB, 64);
    sph_skein512_close(&ctx_skein, hashA);
    
    printf("Pawelhash, skein512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashA, 64);
    sph_jh512_close(&ctx_jh, hashB);
    
    printf("Pawelhash, jh512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hashB, 64);
    sph_keccak512_close(&ctx_keccak, hashA);
    
    printf("Pawelhash, keccak512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hashA, 64);
    sph_luffa512_close(&ctx_luffa, hashB);
    
    printf("Pawelhash, luffa512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashB, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashA);
    
    printf("Pawelhash, whirlpool hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashA, 64);
    sph_shabal512_close(&ctx_shabal, hashB);
    
    printf("Pawelhash, shabal512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashB, 64);
    sph_echo512_close(&ctx_echo, hashA);
    
    printf("Pawelhash, echo512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, hashA, 64);
    sph_groestl512_close(&ctx_groestl, hashB);
    
    printf("Pawelhash, groestl512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hashB, 64);
    sph_haval256_5_close(&ctx_haval, hashA);
    
    memset(&hashA[8], 0, 32);
    
    printf("Pawelhash, haval256_5 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);
    
    printf("Pawelhash, bmw512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashB, 64);
    sph_echo512_close(&ctx_echo, hashA);
    
    printf("Pawelhash, echo512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_fugue512_init(&ctx_fugue);
    sph_fugue512(&ctx_fugue, hashA, 64);
    sph_fugue512_close(&ctx_fugue, hashB);
    
    printf("Pawelhash, fugue512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    printf("Pawelhash, bmw512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");

    sph_gost512_init(&ctx_gost);
    sph_gost512(&ctx_gost, hashA, 64);
    sph_gost512_close(&ctx_gost, hashB);
    
    printf("Pawelhash, gost512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashB, 64);
    sph_shabal512_close(&ctx_shabal, hashA);
    
    printf("Pawelhash, shabal512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashA, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashB);
    
    printf("Pawelhash, whirlpool hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashB, 64);
    sph_groestl512_close(&ctx_groestl, hashA);
    
    printf("Pawelhash, groestl512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");

    memcpy(output, hashA, 32);
    
    printf("Pawelhash, final hash: ");
	for (ii=8; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    printf("Stopping Pawelhash ... \n");
}

void jeonghash(const char* input, char* output, uint32_t len)
{
    int ii = 0;
    
    printf("Starting Jeonghash, length = %d ... \n", len);
    
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
    
    printf("Jeonghash, simd512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashA, 64);
    sph_hamsi512_close(&ctx_hamsi, hashB);
    
    printf("Jeonghash, hamsi512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashB, 64);
    sph_shabal512_close(&ctx_shabal, hashA);
    
    printf("Jeonghash, shabal512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hashA, 64);
    sph_blake512_close(&ctx_blake, hashB);
    
    printf("Jeonghash, blake512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    printf("Jeonghash, bmw512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashA, 64);
    sph_sha512_close(&ctx_sha2, hashB);
    
    printf("Jeonghash, sha512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashB, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashA);
    
    printf("Jeonghash, whirlpool hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hashB);
    
    printf("Jeonghash, skein512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashB, 64);
    sph_skein512_close(&ctx_skein, hashA);
    
    printf("Jeonghash, skein512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashA, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashB);
    
    printf("Jeonghash, whirlpool hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashB, 64);
    sph_sha512_close(&ctx_sha2, hashA);
    
    printf("Jeonghash, sha512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);
    
    printf("Jeonghash, bmw512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hashB, 64);
    sph_blake512_close(&ctx_blake, hashA);
    
    printf("Jeonghash, blake512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashA, 64);
    sph_shabal512_close(&ctx_shabal, hashB);
    
    printf("Jeonghash, shabal512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashB, 64);
    sph_hamsi512_close(&ctx_hamsi, hashA);
    
    printf("Jeonghash, hamsi512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hashA, 64);
    sph_simd512_close(&ctx_simd, hashB);
    
    printf("Jeonghash, simd512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, hashB, 64);
    sph_simd512_close(&ctx_simd, hashA);
    
    printf("Jeonghash, simd512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashA, 64);
    sph_hamsi512_close(&ctx_hamsi, hashB);
    
    printf("Jeonghash, hamsi512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashB, 64);
    sph_shabal512_close(&ctx_shabal, hashA);
    
    printf("Jeonghash, shabal512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hashA, 64);
    sph_blake512_close(&ctx_blake, hashB);
    
    printf("Jeonghash, blake512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    printf("Jeonghash, bmw512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashA, 64);
    sph_sha512_close(&ctx_sha2, hashB);
    
    printf("Jeonghash, sha512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashB, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashA);
    
    printf("Jeonghash, whirlpool hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hashB);
    
    printf("Jeonghash, skein512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");

    memcpy(output, hashB, 32);
    printf("Jeonghash, final hash: ");
	for (ii=8; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    printf("Stopping Jeonghash ... \n");
}

void astralhash(const char* input, char* output, uint32_t len)
{
    int ii = 0;
    
    printf("Starting Astralhash, length = %d ... \n", len);
    
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
    
    printf("Astralhash, luffa512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");

    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hashB);
    
    printf("Astralhash, skein512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashB, 64);
    sph_echo512_close(&ctx_echo, hashA);
    
    printf("Astralhash, echo512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashA, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashB);
    
    printf("Astralhash, whirlpool hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    printf("Astralhash, bmw512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, hashA, 64);
    sph_blake512_close(&ctx_blake, hashB);
    
    printf("Astralhash, blake512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, hashB, 64);
    sph_shavite512_close(&ctx_shavite, hashA);
    
    printf("Astralhash, shavite512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, hashA, 64);
    sph_skein512_close(&ctx_skein, hashB);
    
    printf("Astralhash, skein512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hashB, 64);
    sph_whirlpool_close(&ctx_whirlpool, hashA);
    
    printf("Astralhash, whirlpool hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_fugue512_init(&ctx_fugue);
    sph_fugue512(&ctx_fugue, hashA, 64);
    sph_fugue512_close(&ctx_fugue, hashB);
    
    printf("Astralhash, fugue512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, hashB, 64);
    sph_hamsi512_close(&ctx_hamsi, hashA);
    
    printf("Astralhash, hamsi512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hashA, 64);
    sph_haval256_5_close(&ctx_haval, hashB);
    
    memset(&hashA[8], 0, 32);
    
    printf("Astralhash, haval256_5 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashB, 64);
    sph_sha512_close(&ctx_sha2, hashA);
    
    printf("Astralhash, sha512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");

    memcpy(output, hashA, 32);
    printf("Astralhash, final hash: ");
	for (ii=8; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    printf("Stopping Astralhash ... \n");
}

void padihash(const char* input, char* output, uint32_t len)
{
    int ii = 0;
    
    printf("Starting Padihash, length = %d ... \n", len);
    
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
    
    printf("Padihash, sha512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashA, 64);
    sph_jh512_close(&ctx_jh, hashB);
    
    printf("Padihash, jh512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hashB, 64);
    sph_luffa512_close(&ctx_luffa, hashA);
    
    printf("Padihash, luffa512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashA, 64);
    sph_echo512_close(&ctx_echo, hashB);
    
    printf("Padihash, echo512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    printf("Padihash, bmw512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hashA, 64);
    sph_haval256_5_close(&ctx_haval, hashB);
    
    printf("Padihash, haval256_5 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hashB, 64);
    sph_cubehash512_close(&ctx_cubehash, hashA);
    
    printf("Padihash, cubehash512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashA, 64);
    sph_shabal512_close(&ctx_shabal, hashB);
    
    printf("Padihash, shabal512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashB, 64);
    sph_sha512_close(&ctx_sha2, hashA);
    
    printf("Padihash, sha512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");

    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashA, 64);
    sph_jh512_close(&ctx_jh, hashB);
    
    printf("Padihash, jh512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hashB, 64);
    sph_luffa512_close(&ctx_luffa, hashA);
    
    printf("Padihash, luffa512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashA, 64);
    sph_echo512_close(&ctx_echo, hashB);
    
    printf("Padihash, echo512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashB, 64);
    sph_bmw512_close(&ctx_bmw, hashA);
    
    printf("Padihash, bmw512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hashA, 64);
    sph_haval256_5_close(&ctx_haval, hashB);
    
    printf("Padihash, haval256_5 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hashB, 64);
    sph_cubehash512_close(&ctx_cubehash, hashA);
    
    printf("Padihash, cubehash512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashA, 64);
    sph_shabal512_close(&ctx_shabal, hashB);
    
    printf("Padihash, shabal512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, hashB, 64);
    sph_shabal512_close(&ctx_shabal, hashA);
    
    printf("Padihash, shabal512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, hashA, 64);
    sph_cubehash512_close(&ctx_cubehash, hashB);
    
    printf("Padihash, cubehash512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hashB, 64);
    sph_haval256_5_close(&ctx_haval, hashA);
    
    printf("Padihash, haval256_5 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);
    
    printf("Padihash, bmw512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, hashB, 64);
    sph_echo512_close(&ctx_echo, hashA);
    
    printf("Padihash, echo512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, hashA, 64);
    sph_luffa512_close(&ctx_luffa, hashB);
    
    printf("Padihash, luffa512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hashA);
    
    printf("Padihash, jh512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_sha512_init(&ctx_sha2);
    sph_sha512(&ctx_sha2, hashA, 64);
    sph_sha512_close(&ctx_sha2, hashB);
    
    printf("Padihash, sha512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hashA);
    
    printf("Padihash, jh512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashA[ii]);
	}
	printf ("\n");
    
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);
    
    printf("Padihash, bmw512 hash: ");
	for (ii=0; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");

    memcpy(output, hashB, 32);
    printf("Padihash, final hash: ");
	for (ii=8; ii < 16; ii++)
	{
		printf ("%.8x", hashB[ii]);
	}
	printf ("\n");
    
    printf("Stopping Padihash ... \n");
}

void globalhash(const char* input, char* output, uint32_t len)
{
    sph_gost512_context      ctx_gost;
    sph_blake512_context     ctx_blake;
    blake2b_state            ctx_blake2b[1];
    blake2s_state            ctx_blake2s[1];
    
    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[16], hashB[16], finalhash[8]; // finalhash is a 256 unsigned integer
    
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
    blake2s_final( ctx_blake2s, finalhash, BLAKE2S_OUTBYTES );

    memcpy(output, finalhash, 32);
}