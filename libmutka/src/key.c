#include <math.h>
#include <stdlib.h>

#include "../include/mutka.h"
#include "../include/key.h"




float mutka_compute_key_entropy(uint8_t* key_bytes, size_t key_size) {
    float entropy = 0.0f;


    int counts [UINT8_MAX] = { 0 };
    for(size_t i = 0; i < key_size; i++) {
        counts[key_bytes[i]] += 1;
    }

   
    float* prob = calloc(key_size, sizeof *prob);
    size_t prob_i = 0;

    for(size_t i = 0; i < UINT8_MAX; i++) {
        if(counts[i] <= 0) {
            continue;
        }

        if(prob_i > key_size) {
            mutka_set_errmsg("%s: prob_i > key_size", __func__);
            goto free_and_out;
        }

        prob[prob_i++] = (float)counts[i] / (float)key_size;
    }



    for(size_t i = 0; i < key_size; i++) {
        if(prob[i] > 0.000001f) {
            entropy -= log2f(prob[i]);
        }
    }


free_and_out:

    free(prob);

    return entropy;
}



