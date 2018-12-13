#ifndef KECCAKC_H
#define KECCAKC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void keccakc_hash(const char* input, char* output, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif
