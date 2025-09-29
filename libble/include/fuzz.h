#ifndef FUZZ_OVERHEAD
#define FUZZ_OVERHEAD

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Enhanced signal handling for debugging
#include <execinfo.h>
#include <sys/ucontext.h>

uint8_t** split_buffer(const uint8_t* buffer, size_t length, size_t num_chunks, uint32_t* out_chunk_size);
void free_chunks(uint8_t** chunks, size_t num_chunks);

#endif // FUZZ_OVERHEAD