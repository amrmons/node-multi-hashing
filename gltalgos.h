#ifndef GLTALGOS_H
#define GLTALGOS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// hardfork 1 added algos

void pawelhash(const char* input, char* output, uint32_t len);
void astralhash(const char* input, char* output, uint32_t len);
void jeonghash(const char* input, char* output, uint32_t len);
void padihash(const char* input, char* output, uint32_t len);
void globalhash(const char* input, char* output, uint32_t len);

// hardfork 2 added algos

void arctichash(const char* input, char* output, uint32_t len);
void deserthash(const char* input, char* output, uint32_t len);
void cryptoandcoffee_hash(const char* input, char* output, uint32_t len);
void rickhash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
