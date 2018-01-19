#include <stdio.h>
#include <stdlib.h>

#include "helpers.h"

void secure_zero_memory(void* ptr, size_t len)
{
    volatile uint8_t *cursor = (volatile uint8_t *)ptr;
    while (len != 0)
    {
        *cursor = 0;
        cursor++;
        len--;
    }
}

void print_bytes(const char* label, const uint8_t* bytes, size_t len)
{
    printf("%s:", label);
    for (size_t i = 0; i < len; ++i)
    {
        if ((i % 32) == 0)
        {
            printf("\n  ");
        }
        printf("%02x", bytes[i]);
    }
    putc('\n', stdout);
}
