#ifndef LIBMUTKA_KEYPAIR_H
#define LIBMUTKA_KEYPAIR_H

#include "string.h"






struct mutka_keypair {
    struct mutka_str public_key;
    struct mutka_str private_key;
};

void mutka_free_keypair(struct mutka_keypair* keypair);
void mutka_null_keypair(struct mutka_keypair* keypair);






#endif
