#ifndef LIBMUTKA_MEMORY_H
#define LIBMUTKA_MEMORY_H

#include <stddef.h>



// If any errors occur, 'ptr' is returned back untouched.
// '*ptr_num_elements' is increased by 'num_add_elements' on success.
void* mutka_srealloc_array
(
    size_t element_sizeb,
    void* ptr,
    size_t* ptr_num_elements, // Currently allocated number of elements.
    size_t  new_add_elements 
);


#endif
