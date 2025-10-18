#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#include "../include/cryptography.h"
#include "../include/mutka.h"


//#include <stdio.h>

static void openssl_error_ext(const char* file, const char* func, int line) {
    char buffer[256] = { 0 };
    ERR_error_string(ERR_get_error(), buffer);
    mutka_set_errmsg("[OpenSSL] %s() at \"%s\":%i | %s", func, file, line, buffer);
}

#define openssl_error() openssl_error_ext(__FILE__, __func__, __LINE__)


static bool mutka_openssl_keypair_ctx(struct mutka_keypair* keypair, EVP_PKEY_CTX* ctx) {
    bool result = false;

    EVP_PKEY* pkey = NULL;
    //EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);

    size_t private_keylen = 0;
    size_t public_keylen = 0;


    if(!ctx) {
        openssl_error();
        goto out;
    }
    if(EVP_PKEY_keygen_init(ctx) <= 0) {
        openssl_error();
        goto out;
    }
    if(EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        openssl_error();
        goto out;
    }


    // Get private key length.
    if(EVP_PKEY_get_raw_private_key(pkey, NULL, &private_keylen) <= 0) {
        openssl_error();
        goto out;
    }

    // Get public key length.
    if(EVP_PKEY_get_raw_public_key(pkey, NULL, &public_keylen) <= 0) {
        openssl_error();
        goto out;
    }
    

    // Get private key bytes.
   
    mutka_str_reserve(&keypair->private_key, private_keylen);
    keypair->private_key.size = private_keylen;

    if(EVP_PKEY_get_raw_private_key(pkey, (uint8_t*)keypair->private_key.bytes, &private_keylen) <= 0) {
        openssl_error();
        goto out;
    }

    
    // Get public key bytes.
    
    mutka_str_reserve(&keypair->public_key, public_keylen);
    keypair->public_key.size = public_keylen;

    if(EVP_PKEY_get_raw_public_key(pkey, (uint8_t*)keypair->public_key.bytes, &public_keylen) <= 0) {
        openssl_error();
        goto out;
    }


    result = true;

out:
    if(pkey) {
        EVP_PKEY_free(pkey);
    }
    if(ctx) {
        EVP_PKEY_CTX_free(ctx);
    }

    return result;

}


bool mutka_openssl_X25519_keypair(struct mutka_keypair* keypair) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    return mutka_openssl_keypair_ctx(keypair, ctx);
}


bool mutka_openssl_ED25519_keypair(struct mutka_keypair* keypair) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    return mutka_openssl_keypair_ctx(keypair, ctx);
}


bool mutka_openssl_scrypt(
        struct mutka_str* derived_key,
        uint32_t output_size,
        char* input, size_t input_size,
        char* salt,  size_t salt_size) {

    if(!input || !input_size) {
        return false;
    }
    if(!salt || !salt_size) {
        return false;
    }

    mutka_str_reserve(derived_key, output_size);

    const uint64_t N = 524288; // 2 ^ 19
    const uint64_t R = 8;
    const uint64_t P = 2;
    const uint64_t max_mem = 1024 * 1024 * (512 + 64); // ~600 MB

    int res = EVP_PBE_scrypt(
            input, input_size,
            (uint8_t*)salt, salt_size, N, R, P, max_mem, 
            (uint8_t*)derived_key->bytes, output_size);

    if(res > 0) {
        derived_key->size = output_size;
    }

    return (res > 0);
}

bool mutka_openssl_AES256CBC_encrypt(struct mutka_str* cipher_out, 
        char* key, char* iv, char* data, size_t data_size) {

    bool result = false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        openssl_error();
        goto out;
    }

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (uint8_t*)key, (uint8_t*)iv) <= 0) {
        openssl_error();
        goto out;
    }

    mutka_str_clear(cipher_out);
    mutka_str_reserve(cipher_out, data_size + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    if(EVP_EncryptUpdate(ctx, 
                (uint8_t*)cipher_out->bytes, 
                (int*)&cipher_out->size, 
                (uint8_t*)data, data_size) <= 0) {
        openssl_error();
        goto out;
    }

    int final_size = 0;
    if(EVP_EncryptFinal_ex(ctx, 
                (uint8_t*)(cipher_out->bytes + cipher_out->size),
                &final_size) <= 0) {
        openssl_error();
        goto out;
    }

    cipher_out->size += final_size;
    result = true;

out:
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

bool mutka_openssl_AES256CBC_decrypt(struct mutka_str* data_out,
        char* key, char* iv, char* cipher, size_t cipher_size) {

    bool result = false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        openssl_error();
        goto out;
    }

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (uint8_t*)key, (uint8_t*)iv) <= 0) {
        openssl_error();
        goto out;
    }

    mutka_str_clear(data_out);
    mutka_str_reserve(data_out, cipher_size);

    if(EVP_DecryptUpdate(ctx, 
                (uint8_t*)data_out->bytes, 
                (int*)&data_out->size, 
                (uint8_t*)cipher, cipher_size) <= 0) {
        openssl_error();
        goto out;
    }

    int final_size = 0;
    if(EVP_DecryptFinal_ex(ctx, 
                (uint8_t*)(data_out->bytes + data_out->size),
                &final_size) <= 0) {
        openssl_error();
        goto out;
    }

    data_out->size += final_size;
    result = true;

out:
    EVP_CIPHER_CTX_free(ctx);

    return result;
}




