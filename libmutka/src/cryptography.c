#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <math.h>

#include "../include/cryptography.h"
#include "../include/mutka.h"


void mutka_dump_key(key128bit_t* key, const char* label) {
    mutka_dump_bytes((char*)key->bytes, sizeof(key->bytes), label);
}
void mutka_dump_sig(signature_t* sig, const char* label) {
    mutka_dump_bytes((char*)sig->bytes, sizeof(sig->bytes), label);
}

bool mutka_generate_cipher_keys(struct mutka_cipher_keys* keys) {
    if(!mutka_openssl_X25519_keypair(&keys->x25519_privkey, &keys->x25519_publkey)) {
        return false;
    }
    if(!mutka_openssl_MLKEM1024_keypair(&keys->mlkem_privkey, &keys->mlkem_publkey)) {
        return false;
    }

    memset(keys->x25519_shared_key.bytes, 0, sizeof(keys->x25519_shared_key.bytes));
    memset(keys->mlkem_shared_key.bytes, 0, sizeof(keys->mlkem_shared_key.bytes));

    return true;
}


static void openssl_error_ext(const char* file, const char* func, int line) {
    char buffer[256] = { 0 };
    ERR_error_string(ERR_get_error(), buffer);
    mutka_set_errmsg("[OpenSSL] %s() at \"%s\":%i | %s", func, file, line, buffer);
}

#define openssl_error() openssl_error_ext(__FILE__, __func__, __LINE__)


static bool mutka_openssl_keypair_ctx
(
    EVP_PKEY_CTX* ctx,
    const char* caller_func,
    uint8_t* privkey_out,  const size_t privkey_expected_len,
    uint8_t* publkey_out,  const size_t publkey_expected_len
){
    bool result = false;
    EVP_PKEY* pkey = NULL;

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

    printf("%s: publ = %li, priv = %li\n", caller_func, public_keylen, private_keylen);

    if(private_keylen != privkey_expected_len) {
        mutka_set_errmsg("%s (called from: %s): Unexpected private key length.",
                __func__, caller_func);
        goto out;
    }

    if(public_keylen != publkey_expected_len) {
        mutka_set_errmsg("%s (called from: %s): Unexpected public key length.",
                __func__, caller_func);
        goto out;
    }


    // Get private key bytes.

    if(EVP_PKEY_get_raw_private_key(pkey, privkey_out, &private_keylen) <= 0) {
        openssl_error();
        goto out;
    }

    
    // Get public key bytes.

    if(EVP_PKEY_get_raw_public_key(pkey, publkey_out, &public_keylen) <= 0) {
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


bool mutka_openssl_X25519_keypair(key128bit_t* privkey_out, key128bit_t* publkey_out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    return mutka_openssl_keypair_ctx(ctx, __func__,
            privkey_out->bytes, sizeof(privkey_out->bytes),
            publkey_out->bytes, sizeof(publkey_out->bytes));
}

bool mutka_openssl_ED25519_keypair(key128bit_t* privkey_out, key128bit_t* publkey_out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    return mutka_openssl_keypair_ctx(ctx, __func__,
            privkey_out->bytes, sizeof(privkey_out->bytes),
            publkey_out->bytes, sizeof(publkey_out->bytes));
}

bool mutka_openssl_MLKEM1024_keypair(key_mlkem1024_priv_t* privkey_out, key_mlkem1024_publ_t* publkey_out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024", NULL);
    return mutka_openssl_keypair_ctx(ctx, __func__,
            privkey_out->bytes, sizeof(privkey_out->bytes),
            publkey_out->bytes, sizeof(publkey_out->bytes));
}

bool mutka_openssl_MLDSA87_keypair(key_mldsa87_priv_t* privkey_out, key_mldsa87_publ_t* publkey_out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-87", NULL);
    return mutka_openssl_keypair_ctx(ctx, __func__,
            privkey_out->bytes, sizeof(privkey_out->bytes),
            publkey_out->bytes, sizeof(publkey_out->bytes));   
}

bool mutka_openssl_scrypt(
    struct mutka_str* derived_key,
    uint32_t output_size,
    char*    input,
    size_t   input_size,
    uint8_t* salt,
    size_t   salt_size
){

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
){
    bool result = false;
    EVP_KDF* kdf = NULL;
    EVP_KDF_CTX* ctx = NULL;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if(!kdf) {
        openssl_error();
        goto out;
    }

    ctx = EVP_KDF_CTX_new(kdf);
    if(!ctx) {
        openssl_error();
        goto out;
    }

    OSSL_PARAM params[5] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, SN_sha256, strlen(SN_sha256)),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, shared_secret, shared_secret_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)hkdf_info, strlen(hkdf_info)),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)hkdf_salt, hkdf_salt_len),
        OSSL_PARAM_construct_end()
    };

    if(output_length != output_memsize) {
        mutka_set_errmsg("%s: Failed to get correct output length from HKDF.", __func__);
        goto out;
    }
    
    if(!EVP_KDF_derive(ctx, (uint8_t*)output, output_length, params)) {
        openssl_error();
        goto out;
    }


    result = true;

out:
    if(kdf) {
        EVP_KDF_free(kdf);
    }
    if(ctx) {
        EVP_KDF_CTX_free(ctx);
    }
    return result;
}

bool mutka_openssl_derive_shared_key
(
    key128bit_t* output,
    key128bit_t* self_privkey,
    key128bit_t* peer_publkey,
    uint8_t*  hkdf_salt, 
    size_t    hkdf_salt_len,
    const char* hkdf_info
){
    bool result = false;

    size_t shared_secret_len = 0;
    uint8_t* shared_secret = NULL;

    EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key
        (EVP_PKEY_X25519, NULL, peer_publkey->bytes, sizeof(peer_publkey->bytes));

    EVP_PKEY* self_pkey = EVP_PKEY_new_raw_private_key
        (EVP_PKEY_X25519, NULL, self_privkey->bytes, sizeof(self_privkey->bytes));

    EVP_PKEY_CTX* ctx = NULL;

    if(!peer_pkey) {
        openssl_error();
        goto out;
    }

    if(!self_pkey) {
        openssl_error();
        goto out;
    }

    ctx = EVP_PKEY_CTX_new(self_pkey, NULL);
    if(!ctx) {
        openssl_error();
        goto out;
    }

    if(!EVP_PKEY_derive_init(ctx)) {
        openssl_error();
        goto out;
    }

    if(!EVP_PKEY_derive_set_peer(ctx, peer_pkey)) {
        openssl_error();
        goto out;
    }


    // Get shared secret length.
    if(!EVP_PKEY_derive(ctx, NULL, &shared_secret_len)) {
        openssl_error();
        goto out;
    }

    shared_secret = malloc(shared_secret_len);
    if(!EVP_PKEY_derive(ctx, shared_secret, &shared_secret_len)) {
        openssl_error();
        goto out;
    }

    // Pass the shared secret through HKDF to make the key stronger.
    if(!mutka_openssl_HKDF(
                output->bytes,
                sizeof(output->bytes),
                shared_secret,
                shared_secret_len,
                hkdf_salt,
                hkdf_salt_len,
                hkdf_info,
                X25519_KEYLEN)) {
        goto out;
    }


    result = true;

out:

    if(ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if(peer_pkey) {
        EVP_PKEY_free(peer_pkey);
    }
    if(self_pkey) {
        EVP_PKEY_free(self_pkey);
    }
    if(shared_secret) {
        memset(shared_secret, 0, shared_secret_len);
        free(shared_secret);
    }

    return result;
}


bool mutka_openssl_decaps
(
    key128bit_t* unwrappedkey_out,
    uint8_t* wrappedkey,
    size_t   wrappedkey_len,
    key_mlkem1024_priv_t* self_privkey
){
    bool result = false;
    EVP_PKEY_CTX* pkey_ctx = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024", NULL);
    if(!pkey_ctx) {
        openssl_error();
        goto out;
    }

    OSSL_PARAM pkey_params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void*)self_privkey->bytes, sizeof(self_privkey->bytes)),
        OSSL_PARAM_construct_end()
    };

    if(!EVP_PKEY_fromdata_init(pkey_ctx)) {
        openssl_error();
        goto out;
    }
    if(!EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PRIVATE_KEY, pkey_params)) {
        openssl_error();
        goto out;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    size_t unwrappedkey_len = sizeof(unwrappedkey_out->bytes);

    if(!EVP_PKEY_decapsulate_init(ctx, NULL)) {
        openssl_error();
        goto out;
    }

    if(!EVP_PKEY_decapsulate(ctx,
                unwrappedkey_out->bytes, &unwrappedkey_len,
                wrappedkey, wrappedkey_len)) {
        openssl_error();
        goto out;
    }

    //*unwrappedkey_out_len = unwrappedkey_len;

    result = true;

out:
    if(ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if(pkey_ctx) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if(pkey) {
        EVP_PKEY_free(pkey);
    }

    return result;
}

bool mutka_openssl_encaps
(
    uint8_t*  wrappedkey_out,
    size_t    wrappedkey_out_memsize,
    size_t*   wrappedkey_out_len,
    key128bit_t* sharedsecret_out,
    key_mlkem1024_publ_t* peer_publkey
){
    bool result = false;
    EVP_PKEY_CTX* pkey_ctx = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;

    pkey_ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024", NULL);
    if(!pkey_ctx) {
        openssl_error();
        goto out;
    }

    OSSL_PARAM pkey_params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)peer_publkey->bytes, sizeof(peer_publkey->bytes)),
        OSSL_PARAM_construct_end()
    };

    if(!EVP_PKEY_fromdata_init(pkey_ctx)) {
        openssl_error();
        goto out;
    }
    if(!EVP_PKEY_fromdata(pkey_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, pkey_params)) {
        openssl_error();
        goto out;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);


    size_t wrappedkey_len = wrappedkey_out_memsize;
    size_t shared_secret_len = sizeof(sharedsecret_out->bytes);

    if(!EVP_PKEY_encapsulate_init(ctx, NULL)) {
        openssl_error();
        goto out;
    }

    if(!EVP_PKEY_encapsulate(ctx, 
                wrappedkey_out, &wrappedkey_len,
                sharedsecret_out->bytes, &shared_secret_len)) {
        openssl_error();
        goto out;
    }

    *wrappedkey_out_len = wrappedkey_len;

    result = true;

out:
    if(ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    if(pkey_ctx) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if(pkey) {
        EVP_PKEY_free(pkey);
    }

    return result;
}

bool mutka_openssl_AES256GCM_encrypt
(
    struct mutka_str* cipher_out,
    uint8_t* gcm_tag_out,
    uint8_t* gcm_key,
    uint8_t* gcm_iv,
    char*    gcm_aad,
    size_t   gcm_aad_len,
    void*    input,
    size_t   input_size
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



    if(!EVP_EncryptInit_ex2(ctx, cipher, gcm_key, gcm_iv, params)) {
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


    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, gcm_tag_out, AESGCM_TAG_LEN);
    if(!EVP_CIPHER_CTX_get_params(ctx, params)) {
        openssl_error();
        goto out;
    }

    /*
    //mutka_str_reserve(tag_out, AESGCM_TAG_LEN);

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag_out->bytes, AESGCM_TAG_LEN);
    if(!EVP_CIPHER_CTX_get_params(ctx, params)) {
        openssl_error();
        goto out;
    }

    //tag_out->size = AESGCM_TAG_LEN;
    */

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
    uint8_t* gcm_key,
    uint8_t* gcm_iv,
    char*    gcm_aad,
    size_t   gcm_aad_len,
    char*    expected_tag,
    size_t   expected_tag_len,
    char*    cipher_bytes,
    size_t   cipher_bytes_size
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


    if(!EVP_DecryptInit_ex2(ctx, cipher, gcm_key, gcm_iv, params)) {
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




bool mutka_openssl_ED25519_sign
(
    signature_t* signature,
    key128bit_t* private_key,
    char*  data,
    size_t data_size
){
    bool result = false;
    EVP_MD_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;
    size_t signature_len = 0;

    ctx = EVP_MD_CTX_new();
    if(!ctx) {
        goto out;
    }

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key->bytes, sizeof(private_key->bytes));
    if(!pkey) {
        openssl_error();
        goto out;
    }

    if(!EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, NULL)) {
        goto out;
    }


    // Get signature length first.
    EVP_DigestSign(ctx, NULL, &signature_len, (const uint8_t*)data, data_size);
    if(signature_len == 0) {
        openssl_error();
        goto out;
    }

    EVP_DigestSign(ctx, signature->bytes, &signature_len, (const uint8_t*)data, data_size);

    //output->size = signature_len;
    result = true;

out:
    if(ctx) {
        EVP_MD_CTX_free(ctx);
    }
    if(pkey) {
        EVP_PKEY_free(pkey);
    }

    return result;
}


bool mutka_openssl_ED25519_verify
(
    key128bit_t* public_key,
    signature_t* signature,
    char*  data,
    size_t data_size
){
    bool result = false;
    EVP_MD_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;

    ctx = EVP_MD_CTX_new();
    if(!ctx) {
        goto out;
    }

    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key->bytes, sizeof(public_key->bytes));
    if(!pkey) {
        openssl_error();
        goto out;
    }

    if(!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey)) {
        goto out;
    }

    result = (EVP_DigestVerify(ctx,
                signature->bytes,
                sizeof(signature->bytes),
                (const uint8_t*)data, data_size) == 1);

out:
    if(ctx) {
        EVP_MD_CTX_free(ctx);
    }
    if(pkey) {
        EVP_PKEY_free(pkey);
    }

    return result;
}


bool mutka_openssl_MLDSA87_sign
(
    const char* context_str,
    signature_mldsa87_t* signature,
    key_mldsa87_priv_t* self_privkey,
    uint8_t* data,
    size_t data_size
){
    bool result = false;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_SIGNATURE* sig_alg = NULL;

    const char* method = "ML-DSA-87";
    pkey = EVP_PKEY_new_raw_private_key_ex(NULL, method, NULL, self_privkey->bytes, sizeof(self_privkey->bytes));

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if(!ctx) {
        openssl_error();
        goto out;
    }

    sig_alg = EVP_SIGNATURE_fetch(NULL, method, NULL);
    if(!sig_alg) {
        openssl_error();
        goto out;
    }

    const size_t context_strlen = strlen(context_str);
    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string("context-string", (uint8_t*)context_str, context_strlen),
        OSSL_PARAM_END
    };


    size_t signature_len = 0;
   
    if(EVP_PKEY_sign_message_init(ctx, sig_alg, params) <= 0) {
        openssl_error();
        goto out;
    }

    if(EVP_PKEY_sign(ctx, NULL, &signature_len, data, data_size) <= 0) {
        openssl_error();
        goto out;
    }

    if(signature_len != sizeof(signature->bytes)) {
        mutka_set_errmsg("%s: Unexpected signature length.", __func__);
        goto out;
    }

    if(EVP_PKEY_sign(ctx, signature->bytes, &signature_len, (const uint8_t*)data, data_size) <= 0) {
        openssl_error();
        goto out;
    }

    /*
    size_t public_keylen = 0;

    // Get public key length.
    if(EVP_PKEY_get_raw_public_key(pkey, NULL, &public_keylen) <= 0) {
        openssl_error();
        goto out;
    }

    if(public_keylen != sizeof(verifykey_out->bytes)) {
        mutka_set_errmsg("%s: Unexpected public key length.", __func__);
        goto out;
    }
    // Save public key for verifier.
    if(EVP_PKEY_get_raw_public_key(pkey, verifykey_out->bytes, &public_keylen) <= 0) {
        openssl_error();
        goto out;
    }
    */

    result = true;
out:
    if(sig_alg) {
        EVP_SIGNATURE_free(sig_alg);
    }
    if(pkey) {
        EVP_PKEY_free(pkey);
    }
    if(ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    
    return result;
}


bool mutka_openssl_MLDSA87_verify
(
    const char* context_str,
    signature_mldsa87_t* signature,
    key_mldsa87_publ_t* verifykey,
    uint8_t* data,
    size_t data_size
){
    bool result = false;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_SIGNATURE* sig_alg = NULL;

    const char* method = "ML-DSA-87";

    pkey = EVP_PKEY_new_raw_public_key_ex(NULL, method, NULL, verifykey->bytes, sizeof(verifykey->bytes));
    if(!pkey) {
        openssl_error();
        goto out;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if(!ctx) {
        openssl_error();
        goto out;
    }

    sig_alg = EVP_SIGNATURE_fetch(NULL, method, NULL);
    if(!sig_alg) {
        openssl_error();
        goto out;
    }

    const size_t context_strlen = strlen(context_str);
    const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string("context-string", (uint8_t*)context_str, context_strlen),
        OSSL_PARAM_END
    };


    if(EVP_PKEY_verify_message_init(ctx, sig_alg, params) <= 0) {
        openssl_error();
        goto out;
    }

    result = (EVP_PKEY_verify(ctx, signature->bytes, sizeof(signature->bytes), data, data_size) == 1);

out:
    if(sig_alg) {
        EVP_SIGNATURE_free(sig_alg);
    }
    if(pkey) {
        EVP_PKEY_free(pkey);
    }
    if(ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    
    return result;
}

