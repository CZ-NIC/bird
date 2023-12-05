#!/bin/bash

dir_name="trie-test-case"

cd ../..
make all
echo '------------------------'

if [[ ! -e "$dir_name" ]]; then
    mkdir "$dir_name"
    echo "creating directory '$dir_name'"
fi

cp ./bird ./"$dir_name"
echo 'copying bird executable'

cp ./birdc ./"$dir_name"
echo 'copying birdc executable'

cp ./proto/aggregator/bird.conf ./"$dir_name"
echo 'copying bird.conf'

cd "$dir_name"

echo 'done'
echo
echo 'expected result: 10.100.0.0/16'
