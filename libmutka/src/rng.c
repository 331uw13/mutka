#include <openssl/rand.h>
#include "../include/rng.h"

#include <stdio.h>


uint64_t mutka_rng(struct mutka_rngcfg cfg) {
    uint64_t result = 0;
    
    for(uint32_t i = 0; i < cfg.iterations; i++) {
        uint8_t n = 0;
        RAND_bytes(&n, 1);

        result += n;
    }

    return result % cfg.max_value;
}


