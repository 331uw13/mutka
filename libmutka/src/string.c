#include <stdlib.h>
#include <string.h>

#include "../include/string.h"


#define STR_DEFMEMSIZE 64
#define STR_REALLOC_BYTES 64



// Allocates more memory for string if needed.
static bool mutka_str_memcheck(struct mutka_str* str, uint32_t size_add) {
    if(!str->bytes) {
        str->bytes = malloc(STR_DEFMEMSIZE);
        str->memsize = STR_DEFMEMSIZE;
        str->size = 0;
        // TODO: handle memory errors.
        return true;
    }

    if((str->size + size_add) < str->memsize) {
        return true;
    }


    uint32_t new_size = str->memsize + size_add + STR_REALLOC_BYTES;
    char* new_ptr = realloc(str->bytes, new_size);
    
    if(!new_ptr) {
        // TODO: handle memory errors.
        return false;
    }

    str->bytes = new_ptr;
    str->memsize = new_size;

    return true;
}


void mutka_str_alloc(struct mutka_str* str) {
    str->memsize = STR_DEFMEMSIZE;
    str->bytes = malloc(str->memsize);
    str->size = 0;
    // TODO: handle memory errors.
}

void mutka_str_free(struct mutka_str* str) {
    if(str->bytes) {
        free(str->bytes);
        str->bytes = NULL;
        str->memsize = 0;
        str->size = 0;
    }
}

void mutka_str_nullterm(struct mutka_str* str) {
    if(!str->bytes) {
        return;
    }
    if(str->bytes[str->size] == '\0') {
        return;
    }
    
    if(!mutka_str_memcheck(str, 1)) {
        return; // TODO: handle memory errors.
    }

    str->bytes[str->size] = '\0';
}

void mutka_str_move(struct mutka_str* str, char* data, uint32_t size) {
    if(!mutka_str_memcheck(str, size)) {
        return; // TODO: handle memory errors.
    }

    memmove(str->bytes, data, size);
    str->size = size;
}

void mutka_str_pushbyte(struct mutka_str* str, char ch) {
    if(!mutka_str_memcheck(str, 1)) {
        return; // TODO: handle memory errors.
    }

    str->bytes[str->size] = ch;
    str->size += 1;
}

void mutka_str_clear(struct mutka_str* str) {
    if(!str->bytes) {
        return;
    }

    memset(str->bytes, 0, str->size);
}

void mutka_str_reserve(struct mutka_str* str, uint32_t size) {
    mutka_str_memcheck(str, size);
}

    
static const char HEX[] = "0123456789ABCDEF";
void mutka_bytes_to_hexstr(struct mutka_str* in, struct mutka_str* out) {
    for(uint32_t i = 0; i < in->size; i++) {
        mutka_str_pushbyte(out, HEX[ (abs(in->bytes[i]) >> 4) % 0xF ]);
        mutka_str_pushbyte(out, HEX[ abs(in->bytes[i]) & 0xF ]);
    }
}

#define HEXBUF_SIZE 4
void mutka_hexstr_to_bytes(struct mutka_str* in, struct mutka_str* out) {
    
    char hexbuf[HEXBUF_SIZE] = { 0 };
    uint32_t hexbuf_i = 0;
    
    mutka_str_clear(out);

    for(uint32_t i = 0; i < in->size; i++) {
        hexbuf[hexbuf_i++] = in->bytes[i];

        if(hexbuf_i >= 2) {
            mutka_str_pushbyte(out, strtol(hexbuf, NULL, 16));
            memset(hexbuf, 0, hexbuf_i);
            hexbuf_i = 0;
        }
    }
}




