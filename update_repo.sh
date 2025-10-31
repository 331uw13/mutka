#!/bin/bash

if [[ -z $1 ]]; then
    echo "Add commit message."
    exit
fi

(cd libmutka/ && make clean)
(cd examples/server/ && make clean)
(cd examples/client/ && make clean)

rm ./examples/server/host_ed25519_public_key
rm ./examples/server/host_ed25519_private_key

git add .
git commit -m "$1"
git push -u origin main

