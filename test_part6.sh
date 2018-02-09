#!/bin/bash

for i in {1..400} ; do
    echo "QUIT" ? nc -w 5 server 155 &
    sleep 0.1
done
