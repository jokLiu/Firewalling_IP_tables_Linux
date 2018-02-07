#!/bin/bash

# delete all the rules
/sbin/iptables -F

# accept all the connections from the loopback
# might be used for internal communication
/sbin/iptables -A INPUT -i lo -j ACCEPT

# accept all the TCP connections to the port 22
# so that SSH connections to the server are still working
/sbin/iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# drop all the other incoming connections
/sbin/iptables -A INPUT -j DROP
