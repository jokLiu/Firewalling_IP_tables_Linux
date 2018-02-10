#!/bin/bash

# delete all the rules
/sbin/iptables -F

server_net=${SERVERNET-enp0s8}
client_net=${CLIENTNET-enp0s3}

part2="PART2"
part3="PART3"

if [ "$#" -ne 1 ] || [ "$1" != "$part2" -a "$1" != "$part3" ]; then
    echo "Usage 1: $0 $part2"
    echo "Usage 2: $0 $part3"
    exit 1
fi

if [ "$1" = "$part2" ]; then
    # drop all the connections from the client-net to the server net which
    # sent to the port 80
    /sbin/iptables -A FORWARD -i "$client_net" -o "$server_net" -d 192.168.101.2 -p tcp --dport 80 -j DROP

elif [ "$1" = "$part3" ]; then
    # forward all the TCP connections to the port 22 from the client-net
    # to the server-net so that SSH connections to the server are still working
    /sbin/iptables -A FORWARD -i "$client_net" -o "$server_net" -d 192.168.101.2 -p tcp --dport 22 -j ACCEPT

    # drop all the other connections from client-net to the server-net
    # this basically includes part2 and part3 because port 80 is among those that
    # has to be dropped
    /sbin/iptables -A FORWARD -i "$client_net" -o "$server_net" -j DROP
fi
