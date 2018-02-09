#!/bin/bash

function test(){
    for i in {1..100} ; do
        echo "QUIT" | nc -w 5 "$1" &
        sleep 0.1
    done
}

for i in {1..5} ; do test "$1" & done


