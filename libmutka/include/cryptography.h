#ifndef LIBMUTKA_CRYPTOGRAPHY_H
#define LIBMUTKA_CRYPTOGRAPHY_H

#include <stdbool.h>
#include <stdint.h>

#include "key.h"
#include "string.h"

typedef struct {
    uint8_t bytes[64];
}
signature_t;


// TODO: Refactor to use inline function.
#define MUTKA_CLEAR_KEY(key) memset(key.bytes, 0, sizeof(key.bytes))

/*
struct mutka_keypair {
    key128bit_t public_key;
    key128bit_t private_key;
};
struct mutka_keypair mutka_null_keypair();
*/


#define X25519_KEYLEN 32
#define ED25519_KEYLEN 32
#define AESGCM_TAG_LEN 16
#define AESGCM_IV_LEN 12
#define SCRYPT_SALT_LEN 16
#define HKDF_SALT_LEN 16


void mutka_dump_key(key128bit_t* key, const char* label); // USE ONLY FOR DEBUGGING.
void mutka_dump_sig(signature_t* sig, const char* label);

bool mutka_openssl_X25519_keypair(key128bit_t* privkey_out, key128bit_t* publkey_out);
bool mutka_openssl_ED25519_keypair(key128bit_t* privkey_out, key128bit_t* publkey_out);

bool mutka_openssl_scrypt
(
    struct mutka_str* derived_key,
    uint32_t output_size,
    char*    input,
    size_t   input_size,
    uint8_t* salt,
    size_t   salt_size
);

bool mutka_openssl_HKDF
(
    uint8_t*     output,
    size_t       output_memsize,
    uint8_t*     shared_secret,
    size_t       shared_secret_len,
    uint8_t*     hkdf_salt,
    size_t       hkdf_salt_len,
    const char*  hkdf_info,
    size_t       output_length
);

// The shared secret goes through HKDF before it is written to 'output'
bool mutka_openssl_derive_shared_key
(
    key128bit_t* output,
    key128bit_t* self_privkey,
    key128bit_t* peer_publkey,
    uint8_t*     hkdf_salt, 
    size_t       hkdf_salt_len,
    const char*  hkdf_info
);

bool mutka_openssl_AES256GCM_encrypt
(
    struct mutka_str* cipher_out,
    struct mutka_str* tag_out,
    uint8_t*  gcm_key,
    uint8_t*  gcm_iv,
    char*  aad, 
    size_t aad_len,
    void*  input,
    size_t input_size
);

bool mutka_openssl_AES256GCM_decrypt
(
    struct mutka_str* output,
    uint8_t*  gcm_key,
    uint8_t*  gcm_iv,
    char*  aad, 
    size_t aad_len,
    char*  expected_tag,
    size_t expected_tag_len,
    char*  cipher_bytes, 
    size_t cipher_bytes_size
);

bool mutka_openssl_ED25519_sign
(
    signature_t* signature,
    key128bit_t* private_key,
    char*  data, 
    size_t data_size
);

bool mutka_openssl_ED25519_verify
(
    key128bit_t* public_key,
    signature_t* signature,
    char*  data, 
    size_t data_size
);

/*
uint32_t mutka_get_base64_encoded_length(uint32_t decoded_len);
uint32_t mutka_get_base64_decoded_length(char* encoded, uint32_t encoded_len);

// Returns decoded buffer length.
size_t mutka_openssl_BASE64_decode_tobuf(void* buffer, size_t buffer_memsize, char* encoded, size_t encoded_size);

bool mutka_openssl_BASE64_encode_tostr(struct mutka_str* output, char* data, size_t data_size);
bool mutka_openssl_BASE64_decode_tostr(struct mutka_str* output, char* data, size_t data_size);
*/

#endif
