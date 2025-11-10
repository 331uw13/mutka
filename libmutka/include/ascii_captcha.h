#ifndef ASCII_CAPTCHA_H
#define ASCII_CAPTCHA_H

#include <stdint.h>


bool  ascii_captcha_init();
char* get_random_captcha_buffer(size_t* buffer_size_out, char* answer_out, size_t answer_out_len);




#endif
