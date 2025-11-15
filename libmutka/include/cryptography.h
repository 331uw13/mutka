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

typedef struct {
    uint8_t bytes[4627];
}
signature_mldsa87_t;


// TODO: Refactor to use inline function.
#define MUTKA_CLEAR_KEY(key) memset(key.bytes, 0, sizeof(key.bytes))

#define X25519_KEYLEN 32
#define ED25519_KEYLEN 32
#define AESGCM_TAG_LEN 16
#define AESGCM_IV_LEN 12
#define SCRYPT_SALT_LEN 16
#define HKDF_SALT_LEN 16

void mutka_dump_key(key128bit_t* key, const char* label); // USE ONLY FOR DEBUGGING.
void mutka_dump_sig(signature_t* sig, const char* label); // 

bool mutka_openssl_X25519_keypair(key128bit_t* privkey_out, key128bit_t* publkey_out);
bool mutka_openssl_ED25519_keypair(key128bit_t* privkey_out, key128bit_t* publkey_out);
bool mutka_openssl_MLKEM1024_keypair(key_mlkem1024_priv_t* privkey_out, key_mlkem1024_publ_t* publkey_out);
//bool mutka_openssl_MLDSA87_keypair(key_mldsa87_priv_t* privkey_out, key_mldsa87_publ_t* publkey_out);



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

bool mutka_openssl_encaps
(
    uint8_t* wrappedkey_out,
    size_t   wrappedkey_out_memsize,
    size_t*  wrappedkey_out_len,
    key128bit_t* shared_secret_out,
    key_mlkem1024_publ_t* peer_publkey
);

bool mutka_openssl_decaps
(
    uint8_t* unwrappedkey_out,
    size_t   unwrappedkey_out_memsize,
    size_t*  unwrappedkey_out_len,
    uint8_t* wrappedkey,
    size_t   wrappedkey_len,
    key_mlkem1024_priv_t* self_privkey
);


// IMPORTANT NOTE: 
// gcm_tag_out expected size is AESGCM_TAG_LEN
// gcm_iv expected size is AESGCM_IV_LEN

bool mutka_openssl_AES256GCM_encrypt
(
    struct mutka_str* cipher_out,
    uint8_t*          gcm_tag_out,
    uint8_t*  gcm_key,
    uint8_t*  gcm_iv,
    char*     aad, 
    size_t    aad_len,
    void*     input,
    size_t    input_size
);

bool mutka_openssl_AES256GCM_decrypt
(
    struct mutka_str* output,
    uint8_t*  gcm_key,
    uint8_t*  gcm_iv,
    char*     aad, 
    size_t    aad_len,
    char*     expected_tag,
    size_t    expected_tag_len,
    char*     cipher_bytes, 
    size_t    cipher_bytes_size
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


bool mutka_openssl_MLDSA87_sign
(
    const char* context_str,
    signature_mldsa87_t* signature,
    key_mldsa87_publ_t* verifykey_out,
    char* data,
    size_t data_size
);

bool mutka_openssl_MLDSA87_verify
(
    const char* context_str,
    signature_mldsa87_t* signature,
    key_mldsa87_publ_t* verifykey,
    char* data,
    size_t data_size
);


#endif
