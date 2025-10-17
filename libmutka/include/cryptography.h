#ifndef LIBMUTKA_CRYPTOGRAPHY_H
#define LIBMUTKA_CRYPTOGRAPHY_H


#include "keypair.h"


#define X25519_KEYLEN 32
#define ED25519_KEYLEN 32


bool mutka_openssl_X25519_keypair(struct mutka_keypair* keypair);
bool mutka_openssl_ED25519_keypair(struct mutka_keypair* keypair);

bool mutka_openssl_AES256CBC_encrypt(struct mutka_str* cipher_out, 
        char* key, char* iv, char* data, size_t data_size);

bool mutka_openssl_AES256CBC_decrypt(struct mutka_str* data_out,
        char* key, char* iv, char* cipher, size_t cipher_size);



#endif
