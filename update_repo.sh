#!/bin/bash

if [[ -z $1 ]]; then
    echo "Add commit message."
    exit
fi


rm ./examples/server/host_keys

git add .
git commit -m "$1"
git push -u origin main

