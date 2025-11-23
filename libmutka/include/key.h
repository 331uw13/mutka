#ifndef MUTKA_KEY_H
#define MUTKA_KEY_H

#include <stdint.h>



typedef struct {
    uint8_t bytes[32];
}
key128bit_t;


typedef struct {
    uint8_t bytes[3168];
}
key_mlkem1024_priv_t;

typedef struct {
    uint8_t bytes[1568];
}
key_mlkem1024_publ_t;

typedef struct {
    uint8_t bytes[1568];
}
key_mlkem1024_cipher_t;


typedef struct {
    uint8_t bytes[2592];
}
key_mldsa87_publ_t;

typedef struct {
    uint8_t bytes[4896];
}
key_mldsa87_priv_t;


#endif
