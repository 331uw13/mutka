#ifndef LIBMUTKA_RNG_H
#define LIBMUTKA_RNG_H

#include <stdint.h>


struct mutka_rngcfg {
    uint32_t  iterations;
    uint64_t  max_value;
};



uint64_t mutka_rng(struct mutka_rngcfg cfg);




#endif
