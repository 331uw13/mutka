#!/bin/bash



FIL_C=$HOME/Github/fil-c-0.675
OPENSSL=../../external/openssl

CC=$FIL_C/build/bin/clang


SRC_FILES=$(find ./src -type f -name *.c)



$CC -Wall -Wextra $SRC_FILES -I$OPENSSL\
    -L../../libmutka -lmutka -o client.example


