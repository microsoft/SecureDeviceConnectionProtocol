#ifndef SDCPTESTHELPERS_H
#define SDCPTESTHELPERS_H

#include <stdint.h>

void secure_zero_memory(void* ptr, size_t len);
void print_bytes(const char* label, const uint8_t* bytes, size_t len);
void print_bytes_err(const char* label, const uint8_t* bytes, size_t len);

#endif // SDCPTESTHELPERS_H
