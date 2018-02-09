#!/bin/bash

# delete all the rules
/sbin/iptables -F

server_net=${SERVERNET-enp0s8}
client_net=${CLIENTNET-enp0s3}

# forward all the TCP connections to the port 22 from the client-net
# to the server-net so that SSH connections to the server are still working
/sbin/iptables -A FORWARD -i "$client_net" -o "$server_net" -p tcp --dport 22 -j ACCEPT

# drop all the other connections from client-net to the server-net
# this basically includes part2 and part3 because port 80 is among those that
# has to be dropped
/sbin/iptables -A FORWARD -i "$client_net" -o "$server_net" -j DROP
