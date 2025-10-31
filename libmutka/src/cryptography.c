#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

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


bool mutka_openssl_AES256GCM_encrypt
(
    struct mutka_str* cipher_out,
    struct mutka_str* tag_out,
    char* gcm_key,
    char* gcm_iv,
    char* gcm_aad, size_t gcm_aad_len,
    char* input, size_t input_size
){
    bool result = false;
 
    int out_len = 0;
    int tmp_len = 0;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    EVP_CIPHER_CTX* ctx = NULL;
    EVP_CIPHER* cipher = NULL;

    
    /*
    struct mutka_str input;
    mutka_str_alloc(&input);

    uint8_t rnd_bytes[2] = { 0 };
    RAND_bytes(rnd_bytes, sizeof(rnd_bytes));

    mutka_str_reserve(&input, input_raw_size + rnd_bytes[0] + rnd_bytes[1]);
    mutka_str_move(&input, input_raw, input_raw_size);

    for(size_t i = 0; i < sizeof(rnd_bytes); i++) {
        for(uint8_t j = 0; j < rnd_bytes[i]; j++) {
            mutka_str_pushbyte(&input, 0);
        }
    }
    */


    size_t gcm_iv_len = AESGCM_IV_LEN;


    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        openssl_error();
        goto out;
    }


    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if(!cipher) {
        openssl_error();
        goto out;
    }


    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &gcm_iv_len);



    if(!EVP_EncryptInit_ex2(ctx, cipher, (uint8_t*)gcm_key, (uint8_t*)gcm_iv, params)) {
        openssl_error();
        goto out;
    }

    if(!EVP_EncryptUpdate(ctx, NULL, &out_len, (uint8_t*)gcm_aad, gcm_aad_len)) {
        openssl_error();
        goto out;
    }
    
   
    mutka_str_clear(cipher_out);
    mutka_str_reserve(cipher_out, input_size + EVP_CIPHER_block_size(EVP_aes_256_gcm()));

    if(!EVP_EncryptUpdate(ctx, 
                (uint8_t*)cipher_out->bytes, (int*)&cipher_out->size,
                (uint8_t*)input, input_size)) {
        openssl_error();
        goto out;
    }


    if(!EVP_EncryptFinal_ex(ctx, (uint8_t*)cipher_out->bytes, &tmp_len)) {
        openssl_error();
        goto out;
    }

    mutka_str_reserve(tag_out, AESGCM_TAG_LEN);

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag_out->bytes, AESGCM_TAG_LEN);
    if(!EVP_CIPHER_CTX_get_params(ctx, params)) {
        openssl_error();
        goto out;
    }

    tag_out->size = AESGCM_TAG_LEN;


    result = true;

out:
    if(cipher) {
        EVP_CIPHER_free(cipher);
    }
    if(ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return result;
}


bool mutka_openssl_AES256GCM_decrypt
(
    struct mutka_str* output,
    char* gcm_key,
    char* gcm_iv,
    char* gcm_aad, size_t gcm_aad_len,
    char* expected_tag, size_t expected_tag_len,
    char* cipher_bytes, size_t cipher_bytes_size
){
    bool result = false;

    int out_len = 0;

    EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    size_t gcm_iv_len = AESGCM_IV_LEN;


    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        openssl_error();
        goto out;
    }


    cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    if(!cipher) {
        openssl_error();
        goto out;
    }


    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &gcm_iv_len);


    if(!EVP_DecryptInit_ex2(ctx, cipher, (uint8_t*)gcm_key, (uint8_t*)gcm_iv, params)) {
        openssl_error();
        goto out;
    }

    if(!EVP_DecryptUpdate(ctx, NULL, &out_len, (uint8_t*)gcm_aad, gcm_aad_len)) {
        openssl_error();
        goto out;
    }

    mutka_str_clear(output);
    mutka_str_reserve(output, cipher_bytes_size + 32);


    // Decrypt cipher bytes.
    if(!EVP_DecryptUpdate(ctx, (uint8_t*)output->bytes, (int*)&output->size, (uint8_t*)cipher_bytes, cipher_bytes_size)) {
        openssl_error();
        goto out;
    }


    // Set expected tag value.
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, expected_tag, expected_tag_len);
    
    if(!EVP_CIPHER_CTX_set_params(ctx, params)) {
        openssl_error();
        goto out;
    }

    int rv = EVP_DecryptFinal_ex(ctx, (uint8_t*)output->bytes, &out_len);
    result = (rv > 0);

out:

    if(cipher) {
        EVP_CIPHER_free(cipher);
    }
    if(ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return result;
}

bool mutka_openssl_BASE64_encode(struct mutka_str* output, char* data, size_t data_size) {
    EVP_ENCODE_CTX* ctx = NULL;
    int output_len = 0;
    int tmp_len = 0;
    bool result = false;

    ctx = EVP_ENCODE_CTX_new();
    if(!ctx) {
        openssl_error();
        goto out;
    }

    EVP_EncodeInit(ctx);

    mutka_str_clear(output);
    mutka_str_reserve(output, ((data_size + 2) / 3) * 4 + 1);

    if(!EVP_EncodeUpdate(ctx, (uint8_t*)output->bytes, &output_len, (uint8_t*)data, data_size)) {
        openssl_error();
        goto out;
    }

    EVP_EncodeFinal(ctx, (uint8_t*)output->bytes + output_len, &tmp_len);
    output->size += tmp_len;

    result = true;

out:
    if(ctx) {
        EVP_ENCODE_CTX_free(ctx);
    }

    return result;
}


bool mutka_openssl_BASE64_decode(struct mutka_str* output, char* data, size_t data_size) {
    EVP_ENCODE_CTX* ctx = NULL;
    int output_len = 0;
    int tmp_len = 0;
    bool result = false;

    ctx = EVP_ENCODE_CTX_new();
    if(!ctx) {
        openssl_error();
        goto out;
    }

    EVP_DecodeInit(ctx);

    mutka_str_clear(output);
    mutka_str_reserve(output, (data_size / 4) * 3 + 1);

    if(EVP_DecodeUpdate(ctx, (uint8_t*)output->bytes, &output_len, (uint8_t*)data, data_size) < 0) {
        openssl_error();
        goto out;
    }

    if(EVP_DecodeFinal(ctx, (uint8_t*)output->bytes + output_len, &tmp_len) < 0) {
        openssl_error();
        goto out;
    }

    output->size = output_len + tmp_len;
    result = true;

out:
    if(ctx) {
        EVP_ENCODE_CTX_free(ctx);
    }

    return result;
}

