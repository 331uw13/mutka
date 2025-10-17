#ifndef LIBMUTKA_STRING_H
#define LIBMUTKA_STRING_H


#include <stdint.h>


// TODO: Some operations need a return value.

struct mutka_str {
    char* bytes;
    uint32_t size;
    uint32_t memsize;
};


void mutka_str_alloc(struct mutka_str* str);
void mutka_str_free(struct mutka_str* str);

// Makes sure the str->bytes is null terminated.
void mutka_str_nullterm(struct mutka_str* str);

// Move 'data' to beginning of 'str'
void mutka_str_move(struct mutka_str* str, char* data, uint32_t size);

// Add byte to end of string.
void mutka_str_pushbyte(struct mutka_str* str, char ch);

// Sets all 'str->size' bytes to 0
void mutka_str_clear(struct mutka_str* str);

// Makes sure str can hold 'size' number of bytes.
void mutka_str_reserve(struct mutka_str* str, uint32_t size);

char mutka_str_lastbyte(struct mutka_str* str);
bool mutka_str_append(struct mutka_str* str, char* data, uint32_t size);

void mutka_bytes_to_hexstr(struct mutka_str* in, struct mutka_str* out);
void mutka_hexstr_to_bytes(struct mutka_str* in, struct mutka_str* out);


#endif
