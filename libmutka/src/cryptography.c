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

