#!/bin/bash

# delete all the rules
/sbin/iptables -F

# forward all the TCP connections to the port 22 from the client-net
# to the server-net so that SSH connections to the server are still working
/sbin/iptables -A FORWARD -i enp0s3 -o enp0s8 -p tcp --dport 22 -j ACCEPT

# drop all the other connections from client-net to the server-net
# this basically includes part2 and part3 because port 80 is among those that
# has to be dropped
/sbin/iptables -A FORWARD -i enp0s3 -o enp0s8 -j DROP
