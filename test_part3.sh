#!/bin/bash

function connect(){
    echo "QUIT" | nc -w 2 server "$1" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
            echo "port $1 is open"
    fi
}

for i in {1..1024} ; do
    connect "$i" &
done

sleep 10
