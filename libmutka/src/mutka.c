#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>

#include "../include/mutka.h"



static char errmsg[MUTKA_ERRMSG_MAX_SIZE+1] = { 0 };
static size_t errmsg_size = 0;
static void (*errmsg_callback)(char*, size_t) = NULL;


void mutka_set_errmsg_callback(void(*callback)(char*, size_t)) {
    errmsg_callback = callback; 
}

void mutka_set_errmsg(const char* msg_fmt, ...) {
    if(errmsg_size > 0) {
        // Clear previous error.
        memset(errmsg, 0, (errmsg_size < MUTKA_ERRMSG_MAX_SIZE) ? errmsg_size : MUTKA_ERRMSG_MAX_SIZE);
    }

    va_list args;
    va_start(args);

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


void mutka_sleep_ms(int ms) {
    usleep(ms * 1000);
}

