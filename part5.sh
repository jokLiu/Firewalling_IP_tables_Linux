#!/bin/bash

# delete all the rules
/sbin/iptables -F

server_net=${SERVERNET-enp0s8}
client_net=${CLIENTNET-enp0s3}

# forward all the connections coming from the client-net that
# has an IP which belongs to the client-net
/sbin/iptables -A FORWARD -i "$client_net" -s 192.168.100.0/24 -j ACCEPT

# forward all the connections coming from the server-net that
# has an IP which belongs to the server-net
/sbin/iptables -A FORWARD -i "$server_net" -s 192.168.101.0/24 -j ACCEPT

# drop all the other connections from client-net to the server-net
# and other way round
/sbin/iptables -A FORWARD -j DROP
