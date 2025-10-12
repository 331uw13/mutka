#ifndef LIBMUTKA_CRYPTOGRAPHY_H
#define LIBMUTKA_CRYPTOGRAPHY_H


#include "keypair.h"

bool mutka_openssl_X25519_keypair(struct mutka_keypair* keypair);
bool mutka_openssl_ED25519_keypair(struct mutka_keypair* keypair);



#endif
