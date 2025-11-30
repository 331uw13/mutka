#!/bin/bash


if [[ -z $1 ]]; then
    echo "the file must have a name"
    exit
fi


filename=$1


header_filename="./include/${filename}.h"
source_filename="./src/${filename}.c"

tee $header_filename << EOF
#ifndef LIBMUTKA_${filename^^}_H
#define LIBMUTKA_${filename^^}_H




#endif
EOF

tee $source_filename << EOF
#include "../include/${filename}.h"




EOF


echo "$header_filename  $source_filename"



