#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <string>

#include "x21s.h"
#include "sha3/sph_tiger.h"
extern "C" {
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
    #include "lyra2.h"
    #include "SWIFFTX/SWIFFTX.h"
}

unsigned char ConvertCharToX21sAlgoID(const char *pCharPostion) 
{
    switch(*pCharPostion)
    {
        case 0x30:
            return 0;
        case 0x31:
            return 1;
        case 0x32:
            return 2;
        case 0x33:
            return 3;
        case 0x34:
            return 4;
        case 0x35:
            return 5;
        case 0x36:
            return 6;
        case 0x37:
            return 7;
        case 0x38:
            return 8;
        case 0x39:
            return 9;
        case 0x61:
            return 10;
        case 0x62:
            return 11;
        case 0x63:
            return 12;
        case 0x64:
            return 13;
        case 0x65:
            return 14;
        case 0x66:
            return 15;
    }
    return 0x0;
} 

void x21s_hash(const char* input, char* output)
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
    sph_sha512_context        ctx_sha512;
    sph_haval256_5_context    ctx_haval;
    sph_tiger_context         ctx_tiger;
    sph_gost512_context       ctx_gost;
    sph_sha256_context        ctx_sha;

    uint8_t hash[16*64] = {0};
    unsigned char prevBlockBytes[32] = {0};
    char currentSymbol[4];
    
    memcpy(prevBlockBytes, input + 4, 32);
    std::string hashString;
    
    // The bytes are reversed, so we order it correctly.
    for(int i = 31; i >= 0; i--)
    {
        sprintf(currentSymbol, "%02x", prevBlockBytes[i]);
        hashString.append(currentSymbol);
    }
    
    std::string list = "0123456789abcdef";
    std::string order = list;

    std::string hashFront = hashString.substr(0,48); // preserve first 48 chars
    std::string sixteen = hashString.substr(48,64); // extract last sixteen chars

    for(int i=0; i<16; i++){
      int offset = list.find(sixteen[i]); // find offset of sixteen char

      order.insert(0, 1, order[offset]); // insert the nth character at the beginning
      order.erase(offset+1, 1);  // erase the n+1 character (was nth)
    }

    for (int i=0;i<16;i++)
    {
        const void *toHash;
        int lenToHash;
        if (i == 0) {
            toHash = input;
            lenToHash = 80;
        } else {
            toHash = &hash[(64*i)-64];
            lenToHash = 64;
        }

        int hashSelection = ConvertCharToX21sAlgoID(order.data() +i); // change PrevBlockHash to scrambleHash (x16s)
        switch(hashSelection) {
            case 0:
                sph_blake512_init(&ctx_blake);
                sph_blake512 (&ctx_blake, toHash, lenToHash);
                sph_blake512_close(&ctx_blake, hash + i*64);
                break;
            case 1:
                sph_bmw512_init(&ctx_bmw);
                sph_bmw512 (&ctx_bmw, toHash, lenToHash);
                sph_bmw512_close(&ctx_bmw, hash + i*64);
                break;
            case 2:
                sph_groestl512_init(&ctx_groestl);
                sph_groestl512 (&ctx_groestl, toHash, lenToHash);
                sph_groestl512_close(&ctx_groestl, hash + i*64);
                break;
            case 3:
                sph_jh512_init(&ctx_jh);
                sph_jh512 (&ctx_jh, toHash, lenToHash);
                sph_jh512_close(&ctx_jh, hash + i*64);
                break;
            case 4:
                sph_keccak512_init(&ctx_keccak);
                sph_keccak512 (&ctx_keccak, toHash, lenToHash);
                sph_keccak512_close(&ctx_keccak, hash + i*64);
                break;
            case 5:
                sph_skein512_init(&ctx_skein);
                sph_skein512 (&ctx_skein, toHash, lenToHash);
                sph_skein512_close(&ctx_skein, hash + i*64);
                break;
            case 6:
                sph_luffa512_init(&ctx_luffa);
                sph_luffa512 (&ctx_luffa, toHash, lenToHash);
                sph_luffa512_close(&ctx_luffa, hash + i*64);
                break;
            case 7:
                sph_cubehash512_init(&ctx_cubehash);
                sph_cubehash512 (&ctx_cubehash, toHash, lenToHash);
                sph_cubehash512_close(&ctx_cubehash, hash + i*64);
                break;
            case 8:
                sph_shavite512_init(&ctx_shavite);
                sph_shavite512(&ctx_shavite, toHash, lenToHash);
                sph_shavite512_close(&ctx_shavite, hash + i*64);
                break;
            case 9:
                sph_simd512_init(&ctx_simd);
                sph_simd512 (&ctx_simd, toHash, lenToHash);
                sph_simd512_close(&ctx_simd, hash + i*64);
                break;
            case 10:
                sph_echo512_init(&ctx_echo);
                sph_echo512 (&ctx_echo, toHash, lenToHash);
                sph_echo512_close(&ctx_echo, hash + i*64);
                break;
           case 11:
                sph_hamsi512_init(&ctx_hamsi);
                sph_hamsi512 (&ctx_hamsi, toHash, lenToHash);
                sph_hamsi512_close(&ctx_hamsi, hash + i*64);
                break;
           case 12:
                sph_fugue512_init(&ctx_fugue);
                sph_fugue512 (&ctx_fugue, toHash, lenToHash);
                sph_fugue512_close(&ctx_fugue, hash + i*64);
                break;
           case 13:
                sph_shabal512_init(&ctx_shabal);
                sph_shabal512 (&ctx_shabal, toHash, lenToHash);
                sph_shabal512_close(&ctx_shabal, hash + i*64);
                break;
           case 14:
                sph_whirlpool_init(&ctx_whirlpool);
                sph_whirlpool(&ctx_whirlpool, toHash, lenToHash);
                sph_whirlpool_close(&ctx_whirlpool, hash + i*64);
                break;
           case 15:
                sph_sha512_init(&ctx_sha512);
                sph_sha512 (&ctx_sha512, toHash, lenToHash);
                sph_sha512_close(&ctx_sha512, hash + i*64);
                break;
        }
    }

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, hash + 15*64, 64);
    sph_haval256_5_close(&ctx_haval, hash + 15*64);

    sph_tiger_init(&ctx_tiger);
    sph_tiger (&ctx_tiger, hash + 15*64, 64);
    sph_tiger_close(&ctx_tiger, hash + 15*64);

    LYRA2(hash + 15*64, 32, hash + 15*64, 32, hash + 15*64, 32, 1, 4, 4);

    sph_gost512_init(&ctx_gost);
    sph_gost512 (&ctx_gost, hash + 15*64, 64);
    sph_gost512_close(&ctx_gost, hash + 15*64);

    sph_sha256_init(&ctx_sha);
    sph_sha256 (&ctx_sha, hash + 15*64, 64);
    sph_sha256_close(&ctx_sha, output);
}
