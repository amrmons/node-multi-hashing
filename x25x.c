#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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
#include "sha3/sph_tiger.h"
#include "sha3/sph_gost.h"
#include "sha3/sph_panama.h"
#include "sha3/lane.h"
#include "blake/blake2.h"
#include "lyra2.h"
#include "SWIFFTX/SWIFFTX.h"

void x25x_hash(const char* input, char* output)
{
	sph_blake512_context      ctx_blake;
    sph_bmw512_context        ctx_bmw;
    sph_groestl512_context    ctx_groestl;
    sph_jh512_context         ctx_jh;
    sph_keccak512_context     ctx_keccak;
    sph_skein512_context      ctx_skein;
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
    sph_tiger_context         ctx_tiger;
    sph_gost512_context       ctx_gost;
    sph_sha256_context        ctx_sha;
    sph_panama_context        ctx_panama;

    uint8_t totalHashes[64 * 25];

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close(&ctx_blake, totalHashes);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, totalHashes, 64);
    sph_bmw512_close(&ctx_bmw, totalHashes + 64*1);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, totalHashes + 64*1, 64);
    sph_groestl512_close(&ctx_groestl, totalHashes + 64*2);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, totalHashes + 64*2, 64);
    sph_skein512_close(&ctx_skein, totalHashes + 64*3);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, totalHashes + 64*3, 64);
    sph_jh512_close(&ctx_jh, totalHashes + 64*4);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, totalHashes + 64*4, 64);
    sph_keccak512_close(&ctx_keccak, totalHashes + 64*5);

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, totalHashes + 64*5, 64);
    sph_luffa512_close(&ctx_luffa, totalHashes + 64*6);

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, totalHashes + 64*6, 64);
    sph_cubehash512_close(&ctx_cubehash, totalHashes + 64*7);

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, totalHashes + 64*7, 64);
    sph_shavite512_close(&ctx_shavite, totalHashes + 64*8);

    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, totalHashes + 64*8, 64);
    sph_simd512_close(&ctx_simd, totalHashes + 64*9);

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, totalHashes + 64*9, 64);
    sph_echo512_close(&ctx_echo, totalHashes + 64*10);

    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi, totalHashes + 64*10, 64);
    sph_hamsi512_close(&ctx_hamsi, totalHashes + 64*11);

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, totalHashes + 64*11, 64);
    sph_fugue512_close(&ctx_fugue, totalHashes + 64*12);

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal, totalHashes + 64*12, 64);
    sph_shabal512_close(&ctx_shabal, totalHashes + 64*13);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, totalHashes + 64*13, 64);
    sph_whirlpool_close(&ctx_whirlpool, totalHashes + 64*14);

    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, totalHashes + 64*14, 64);
    sph_sha512_close(&ctx_sha2, totalHashes + 64*15);

    // Temporary var used by swifftx to manage 65 bytes output,
    unsigned char temp[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
    InitializeSWIFFTX();
    ComputeSingleSWIFFTX((unsigned char*)totalHashes + 64*12, temp, false);
    memcpy(totalHashes + 64*16, temp, 64);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, totalHashes + 64*16, 64);
    sph_haval256_5_close(&ctx_haval, totalHashes + 64*17);

    sph_tiger_init(&ctx_tiger);
    sph_tiger (&ctx_tiger, totalHashes + 64*17, 64);
    sph_tiger_close(&ctx_tiger, totalHashes + 64*18);

    LYRA2(totalHashes + 64*19, 32, totalHashes + 64*18, 32, totalHashes + 64*18, 32, 1, 4, 4);

    sph_gost512_init(&ctx_gost);
    sph_gost512 (&ctx_gost, totalHashes + 64*19, 64);
    sph_gost512_close(&ctx_gost, totalHashes + 64*20);

    sph_sha256_init(&ctx_sha);
    sph_sha256 (&ctx_sha,totalHashes + 64*20, 64);
    sph_sha256_close(&ctx_sha, totalHashes + 64*21);

    sph_panama_init(&ctx_panama);
    sph_panama (&ctx_panama, totalHashes + 64*21, 64);
    sph_panama_close(&ctx_panama, totalHashes + 64*22);

    laneHash(512, (BitSequence*)totalHashes + 64*22, 512, (BitSequence*)totalHashes + 64*23);

		// simple shuffle algorithm
		#define X25X_SHUFFLE_BLOCKS (24 /* number of algos so far */ * 64 /* output bytes per algo */ / 2 /* block size */)
		#define X25X_SHUFFLE_ROUNDS 12
		static const uint16_t x25x_round_const[X25X_SHUFFLE_ROUNDS] = {
			0x142c, 0x5830, 0x678c, 0xe08c,
			0x3c67, 0xd50d, 0xb1d8, 0xecb2,
			0xd7ee, 0x6783, 0xfa6c, 0x4b9c
		};

		uint16_t* block_pointer = (uint16_t*)hash;
        int r=0, i=0;
		for (r = 0; r < X25X_SHUFFLE_ROUNDS; r++) {
			for (i = 0; i < X25X_SHUFFLE_BLOCKS; i++) {
				uint16_t block_value = block_pointer[X25X_SHUFFLE_BLOCKS - i - 1];
				block_pointer[i] ^= block_pointer[block_value % X25X_SHUFFLE_BLOCKS] + (x25x_round_const[r] << (i % 16));
			}
		}

    blake2s(output, 32, totalHashes, 64 * 24, NULL, 0);
}
