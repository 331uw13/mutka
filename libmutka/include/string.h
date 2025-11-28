#ifndef LIBMUTKA_STRING_H
#define LIBMUTKA_STRING_H


#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>


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

// Get byte at end of string.
char mutka_str_lastbyte(struct mutka_str* str);

// Remove last byte from string.
void mutka_str_pop_end(struct mutka_str* str);

// Append byte at end of string.
bool mutka_str_append(struct mutka_str* str, char* data, uint32_t size);

// Move str->bytes to destination.
// If 'str->size' doesnt match 'dest_size' the operation is cancelled
// and 'false' is returned. Otherwise 'true' if nothing went horribly wrong.
bool mutka_strtoany(struct mutka_str* str, void* dest, size_t dest_size);


// Miscellaneous utils.

// Find 'part' starting index in 'data'
// if not found -1 is returned.
ssize_t mutka_charptr_find(char* data, size_t data_size, char* part, size_t part_size);

bool mutka_strcmp(char* A, size_t A_size, char* B, size_t B_size);


#endif
