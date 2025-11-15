#ifndef LIBMUTKA_MUTKA_H
#define LIBMUTKA_MUTKA_H


#include <stdbool.h>

#include "server.h"
#include "fileio.h"

#define MUTKA_VERSION_STR "libmutka_version:[development]"
#define MUTKA_VERSION_STR_LEN 30


#ifndef MUTKA_ERRMSG_MAX_SIZE
#define MUTKA_ERRMSG_MAX_SIZE 1023
#endif

// This is used to append back of encrypted packets
// it is an identifier for the packet parser to know if it content is encrypted or not.
// Doesnt really matter what it is but as long as 0 bytes dont appear in middle.
#define MUTKA_ENCRYPTED_PACKET_TAIL 0x30FFFFFFEEEEEEEE
#define MUTKA_ENCRYPTED_PACKET_TAIL_NBYTES 8


void mutka_set_errmsg(const char* message, ...);
const char* mutka_get_errmsg();

void mutka_set_errmsg_callback(void(*callback)(char*, size_t));

// Returns 'true' when socket_fd is ready to be read without blocking.
bool mutka_socket_rdready_inms(int socket_fd, int timeout_ms);
void mutka_sleep_ms(int ms);

#define MUTKA_HEX_DUMP(x, label) mutka_dump_bytes(x.bytes, sizeof(x.bytes), label)
void mutka_dump_strbytes(struct mutka_str* str, const char* label); // For debugging.
void mutka_dump_bytes(char* bytes, size_t size, const char* label); // For debugging.

size_t mutka_get_encoded_buffer_len(size_t decoded_len);
size_t mutka_get_decoded_buffer_len(size_t encoded_len);

void mutka_encode(struct mutka_str* str, uint8_t* bytes, size_t size);
bool mutka_decode(uint8_t* buf, size_t buf_memsize, char* encoded, size_t size);


enum mutka_hkdf_ctx {
    HKDFCTX_METADATA_KEYS,
    HKDFCTX_MESSAGE_KEYS
};

bool mutka_get_hkdf_info
(
    char* info,
    size_t info_memsize,
    enum mutka_hkdf_ctx context
);


#endif
