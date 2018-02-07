#!/bin/bash

# delete all the rules
/sbin/iptables -F

# drop all the packets on the port 80
/sbin/iptables -A INPUT -p tcp --dport 80 -j DROP
