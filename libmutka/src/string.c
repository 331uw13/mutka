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
    str->bytes = calloc(1, str->memsize);
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

    mutka_str_clear(str);
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

    memset(str->bytes, 0, (str->size < str->memsize) ? str->size : str->memsize);
    str->size = 0;
}

void mutka_str_reserve(struct mutka_str* str, uint32_t size) {
    mutka_str_memcheck(str, size);
}

/* 
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
*/

char mutka_str_lastbyte(struct mutka_str* str) {
    if(!str) {
        return 0;
    }
    if(!str->bytes) {
        return 0;
    }
    if(str->size >= str->memsize) {
        return 0;
    }

    return str->bytes[(str->size > 0) ? str->size-1 : 0];
}

void mutka_str_pop_end(struct mutka_str* str) {
    if(str->size == 0) {
        return;
    }

    str->bytes[(str->size > 0) ? str->size-1 : 0] = 0;
    str->size--;
}

bool mutka_str_append(struct mutka_str* str, char* data, uint32_t size) {
    if(!mutka_str_memcheck(str, size)) {
        return false;
    }

    memmove(str->bytes + str->size, data, size);
    str->size += size;
    
    return true;
}

ssize_t mutka_charptr_find(char* data, size_t data_size, char* part, size_t part_size) {
    ssize_t found_index = -1;

    if(part_size == 0) {
        goto skip;
    }
    if(data_size < part_size) {
        goto skip;
    }

    
    char* ch = &data[0];
    while(ch < data + data_size) {
        if(*ch == part[0]) {
            if(ch + part_size > data + data_size) {
                break; // Prevent out of bounds read.
            }

            bool found = true;
           
            // First character of 'part' was found, check if rest match.
            for(size_t pi = 0; pi < part_size; pi++) {
                if(*ch != part[pi]) {
                    found = false;
                    break;
                }
                ch++;
            }
            if(found) {
                found_index = (ch - data) - part_size;
                break;
            }
        }
        ch++;
    }

skip:
    return found_index;
}

bool mutka_strcmp(char* A, size_t A_size, char* B, size_t B_size) {
    if(A_size != B_size) {
        return false;
    }

    for(size_t i = 0; i < A_size; i++) {
        if(A[i] != B[i]) {
            return false;
        }
    }

    return true;
}



