#ifndef LIBMUTKA_STRING_H
#define LIBMUTKA_STRING_H


#include <stdint.h>



struct mutka_str {
    char* bytes;
    uint32_t size;
    uint32_t memsize;
};


void mutka_str_alloc(struct mutka_str* str);
void mutka_str_free(struct mutka_str* str);
void mutka_str_nullterm(struct mutka_str* str);
void mutka_str_move(struct mutka_str* str, char* data, size_t size);
void mutka_str_pushbyte(struct mutka_str* str, char ch);
void mutka_str_clear(struct mutka_str* str);

#endif
