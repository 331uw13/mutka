#ifndef LIBMUTKA_CRYPTOGRAPHY_H
#define LIBMUTKA_CRYPTOGRAPHY_H

#include <stdbool.h>

#include "keypair.h"


#define X25519_KEYLEN 32
#define ED25519_KEYLEN 32
#define AESGCM_TAG_LEN 16
#define AESGCM_IV_LEN 12
#define SCRYPT_SALT_LEN 16
#define HKDF_SALT_LEN 16



bool mutka_openssl_X25519_keypair(struct mutka_keypair* keypair);
bool mutka_openssl_ED25519_keypair(struct mutka_keypair* keypair);

bool mutka_openssl_scrypt(
        struct mutka_str* derived_key, uint32_t output_size,
        char* input, size_t input_size,
        char* salt,  size_t salt_size);


bool mutka_openssl_derive_shared_key
(
    struct mutka_str* output,
    struct mutka_str* self_privkey,
    struct mutka_str* peer_publkey,
    char*  hkdf_salt, 
    size_t hkdf_salt_len,
    const char* hkdf_info
);

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

bool mutka_openssl_ED25519_sign
(
    struct mutka_str* output,
    struct mutka_str* private_key,
    char* data, size_t data_size
);

bool mutka_openssl_ED25519_verify
(
    struct mutka_str* public_key,
    struct mutka_str* signature,
    char* data, size_t data_size
);



uint32_t mutka_get_base64_encoded_length(uint32_t decoded_len);
uint32_t mutka_get_base64_decoded_length(uint32_t encoded_len);

bool mutka_openssl_BASE64_encode(struct mutka_str* output, char* data, size_t data_size);
bool mutka_openssl_BASE64_decode(struct mutka_str* output, char* data, size_t data_size);


#endif
