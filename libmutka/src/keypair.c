#include <stddef.h>

#include "../include/keypair.h"




void mutka_free_keypair(struct mutka_keypair* keypair) {
    mutka_str_clear(&keypair->private_key);
    mutka_str_clear(&keypair->public_key);
    mutka_str_free(&keypair->private_key);
    mutka_str_free(&keypair->public_key);
}


void mutka_null_keypair(struct mutka_keypair* keypair) {
    keypair->public_key.bytes = NULL;
    keypair->public_key.memsize = 0;
    keypair->public_key.size = 0;
    keypair->private_key.bytes = NULL;
    keypair->private_key.memsize = 0;
    keypair->private_key.size = 0;
}

