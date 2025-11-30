#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <poll.h>
//#include <time.h>
#include <unistd.h>

#include "../include/mutka.h"


static char errmsg[MUTKA_ERRMSG_MAX_SIZE+1] = { 0 };
static size_t errmsg_size = 0;
static void (*errmsg_callback)(char*, size_t) = NULL;



void mutka_sleep_ms(int ms) {
    /*
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000 * ms;
    nanosleep(&ts, NULL);
    */
    usleep(1000 * ms);
}

void mutka_set_errmsg_callback(void(*callback)(char*, size_t)) {
    errmsg_callback = callback; 
}

void mutka_set_errmsg(const char* msg_fmt, ...) {
    if(errmsg_size > 0) {
        // Clear previous error.
        memset(errmsg, 0, (errmsg_size < MUTKA_ERRMSG_MAX_SIZE) ? errmsg_size : MUTKA_ERRMSG_MAX_SIZE);
    }

    va_list args;
    va_start(args, msg_fmt);

    char buffer[MUTKA_ERRMSG_MAX_SIZE+1] = { 0 };
    vsnprintf(
            buffer,
            MUTKA_ERRMSG_MAX_SIZE,
            msg_fmt,
            args);
    
    va_end(args);

    size_t buf_len = strlen(buffer);
    buf_len = (buf_len < MUTKA_ERRMSG_MAX_SIZE) ? buf_len : MUTKA_ERRMSG_MAX_SIZE;
   
    if(errmsg_callback) {
        errmsg_callback(buffer, buf_len);
    } 

    memmove(errmsg, buffer, buf_len);
    errmsg_size = buf_len;
}

const char* mutka_get_errmsg() {
    return errmsg;
}


bool mutka_socket_rdready_inms(int socket_fd, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = socket_fd;
    pfd.events = POLLIN;
    nfds_t num_fds = 1;


    int i = poll(&pfd, num_fds, timeout_ms);

    return i == 1;
}


void mutka_dump_strbytes(struct mutka_str* str, const char* label) {
    mutka_dump_bytes(str->bytes, str->size, label);
}

void mutka_dump_bytes(char* bytes, size_t size, const char* label) {
    if(size == 0) {
        printf("\033[31m[%s] is empty\033[0m\n", label);
        return;
    }

    printf("---[%s]-(%li)---\n", label, size);

    int counter = 0;
    for(size_t i = 0; i < size; i++) {
        printf("\033[38;5;%im", ((i % 2) == 0) ? 137 : 95);
        printf("%02X", (uint8_t)bytes[i]);
        counter++;
        if(counter >= 32) {
            printf("\n");
            counter = 0;
        }
    }
    printf("\033[0m");
    if(counter > 0) {
        printf("\n");
    }
}


size_t mutka_get_encoded_buffer_len(size_t decoded_len) {
    return decoded_len * 2;
}

size_t mutka_get_decoded_buffer_len(size_t encoded_len) {
    return encoded_len / 2;
}

void mutka_encode(struct mutka_str* str, uint8_t* bytes, size_t size) {
    const char* hex = "0123456789ABCDEF";
    mutka_str_clear(str);

    uint8_t* ch = &bytes[0];
    while(ch < bytes + size) {
        mutka_str_pushbyte(str, hex[(*ch & 0xF0) >> 4 ]);
        mutka_str_pushbyte(str, hex[(*ch & 0x0F) >> 0 ]);
        ch++;
    }
}

bool mutka_decode(uint8_t* buf, size_t buf_memsize, char* encoded, size_t size) {
    const size_t decoded_len = mutka_get_decoded_buffer_len(size);
    if(decoded_len > buf_memsize) {
        mutka_set_errmsg("%s: Destination buffer memory size is smaller than expected.", __func__);
        return false;
    }

    size_t buf_i = 0;

    char bytebuf[2] = { 0 };
    uint16_t bytebuf_i = 0;

    char* byte = &encoded[0];
    while(byte < encoded + size) {
        bytebuf[bytebuf_i] = *byte;
        bytebuf_i++;

        if(bytebuf_i >= sizeof(bytebuf)) {
            buf[buf_i++] = strtol(bytebuf, NULL, 16);
            bytebuf_i = 0;
            memset(bytebuf, 0, sizeof(bytebuf));
        }
        
        byte++;
    }

    return true;
}


