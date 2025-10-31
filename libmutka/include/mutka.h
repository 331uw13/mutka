#ifndef LIBMUTKA_MUTKA_H
#define LIBMUTKA_MUTKA_H


#include <stdbool.h>

#include "server.h"
#include "fileio.h"


#define MUTKA_VERSION_STR "mutka_version:[development]"
#define MUTKA_ERRMSG_MAX_SIZE 1023


void mutka_set_errmsg(const char* message, ...);
const char* mutka_get_errmsg();

void mutka_set_errmsg_callback(void(*callback)(char*, size_t));

// Returns 'true' when socket_fd is ready to be read without blocking.
bool mutka_socket_rdready_inms(int socket_fd, int timeout_ms);

void mutka_sleep_ms(int ms);

void mutka_dump_strbytes(struct mutka_str* str, const char* label); // For debugging.
void mutka_dump_bytes(char* bytes, size_t size, const char* label); // For debugging.

#endif
