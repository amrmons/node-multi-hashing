#ifndef HEX_HASH_H
#define HEX_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void hex_hash(const void* input, size_t len, char* output);

#ifdef __cplusplus
}
#endif

#endif
