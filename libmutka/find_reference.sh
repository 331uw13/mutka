#!/bin/bash


if [[ -z $1 ]]; then
    echo "Nothing to search for..."
    exit
fi

FILES=$(find ./src -type f)

for file in ${FILES[@]}; do
    
    if cat $file | grep -B 3 -A 3 "$1" ; then
        echo -e "\033[32m=========== [FOUND] \"$1\" From: \"$file\" ===========\033[0m"
    fi
done

