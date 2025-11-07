#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../include/memory.h"
#include "../include/mutka.h"




void* mutka_srealloc_array
(
    size_t element_sizeb,
    void* ptr,
    size_t* ptr_num_elements, // Currently allocated number of elements.
    size_t  new_num_elements
){
    if(element_sizeb == 0) {
        goto out;
    }
    if(new_num_elements == 0) {
        goto out;
    }
    if(!ptr_num_elements) {
        goto out;
    }

    void* new_ptr = reallocarray(ptr,
            element_sizeb,
            element_sizeb * new_num_elements);

    if(!new_ptr) {
        mutka_set_errmsg("%s: reallocarray() | %s", __func__, strerror(errno));
        goto out;
    }

    *ptr_num_elements = new_num_elements;
    ptr = new_ptr;
out:
    return ptr;
}



