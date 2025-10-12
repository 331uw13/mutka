#ifndef LIBMUTKA_MUTKA_H
#define LIBMUTKA_MUTKA_H


#include <stdbool.h>

#include "server.h"


#define MUTKA_ERRMSG_MAX_SIZE 1023



void mutka_set_errmsg(const char* message, ...);
const char* mutka_get_errmsg();

// Returns 'true' when socket_fd is ready to be read without blocking.
bool mutka_socket_rdready_inms(int socket_fd, int timeout_ms);

void mutka_sleep_ms(int ms);


#endif
