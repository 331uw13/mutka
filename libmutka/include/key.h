#ifndef MUTKA_KEY_H
#define MUTKA_KEY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>



// Above this entropy the key will be considered "Good".
#define X25519_ENTROPY_BIAS    100.0f
#define MLKEM1024_ENTROPY_BIAS 200.0f
#define MLDSA87_ENTROPY_BIAS   200.0f


float mutka_compute_key_entropy(uint8_t* key_bytes, size_t key_size);


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
