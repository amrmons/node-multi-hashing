#ifndef HEX_HASH_H
#define HEX_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

void hex_hash(const char* input, size_t len, char* output);

#ifdef __cplusplus
}
#endif

#endif
