#include "blake2.h"
#include "hashblake.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

void blake2s_hash(const char* input, char* output, uint32_t len)
{
    uint8_t hash[BLAKE2S_OUTBYTES];
    blake2s_state S[1];
    blake2s_init( S, BLAKE2S_OUTBYTES );
    blake2s_update( S, input, len );
    blake2s_final( S, hash, BLAKE2S_OUTBYTES );
    memcpy(output, hash, 32);
}

void blake2b_hash(const char* input, char* output, uint32_t len)
{
    uint32_t hash[16];
    blake2b_state S[1];
    blake2b_init( S, BLAKE2B_OUTBYTES );
    blake2b_update( S, input, len );
    blake2b_final( S, hash, BLAKE2B_OUTBYTES );
    memcpy(output, hash, 32);
}