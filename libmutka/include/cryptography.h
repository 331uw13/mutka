#ifndef LIBMUTKA_CRYPTOGRAPHY_H
#define LIBMUTKA_CRYPTOGRAPHY_H


#include "keypair.h"


#define X25519_KEYLEN 32
#define ED25519_KEYLEN 32
#define AESGCM_TAG_LEN 16
#define AESGCM_IV_LEN 12

bool mutka_openssl_X25519_keypair(struct mutka_keypair* keypair);
bool mutka_openssl_ED25519_keypair(struct mutka_keypair* keypair);

bool mutka_openssl_scrypt(
        struct mutka_str* derived_key, uint32_t output_size,
        char* input, size_t input_size,
        char* salt,  size_t salt_size);

bool mutka_openssl_AES256GCM_encrypt
(
    struct mutka_str* cipher_out,
    struct mutka_str* tag_out,
    char* gcm_key,
    char* gcm_iv,
    char* aad, size_t aad_len,
    char* plain_data, size_t plain_data_size
);

bool mutka_openssl_AES256GCM_decrypt
(
    struct mutka_str* output,
    char* gcm_key,
    char* gcm_iv,
    char* aad, size_t aad_len,
    char* expected_tag, size_t expected_tag_len,
    char* cipher_bytes, size_t cipher_bytes_size
);


/*
bool mutka_openssl_AES256CBC_encrypt(struct mutka_str* cipher_out, 
        char* key, char* iv, char* data, size_t data_size);

bool mutka_openssl_AES256CBC_decrypt(struct mutka_str* data_out,
        char* key, char* iv, char* cipher, size_t cipher_size);
*/


#endif
