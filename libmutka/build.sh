#!/bin/bash

set -xe




FIL_C=$HOME/Github/fil-c-0.675/
OPENSSL=../external/openssl/

CC=$FIL_C/build/bin/clang




SRC_FILES=$(find ./src -type f -name *.c)


$CC -Wall -Wextra -c $SRC_FILES -I$OPENSSL


ar rcs libmutka.a *.o
rm *.o


ar x $OPENSSL/libs/libssl.a
ar x $OPENSSL/libs/libcrypto.a 


ar rcs libmutka.a *.o
rm *.o


