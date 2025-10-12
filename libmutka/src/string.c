#include <stdlib.h>
#include <string.h>

#include "../include/string.h"


#define STR_DEFMEMSIZE 64
#define STR_REALLOC_BYTES 64



// Allocates more memory for string if needed.
static bool mutka_str_memcheck(struct mutka_str* str, size_t size_add) {
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

    str->bytes[str->size+1] = '\0';
}

void mutka_str_move(struct mutka_str* str, char* data, size_t size) {
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


