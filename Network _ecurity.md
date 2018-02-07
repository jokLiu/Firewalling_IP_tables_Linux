Network Security
================

Build a Linux Firewall Report
-----------------------------

### VMs Setup

As recommended for the assignment 3 VMs with Linux distribution of
Debian 9 with the LXDE Window Manager from live CD was used. Each VM was
given 1GB of RAM and 4GB of storage (just in case).

The VM specification:

-   Kernel release: 4.9.0-4-686
-   Kernel version: \#1 SMP Debian 4.9.65-3
-   Operating system: Debian 9 GNU/Linux i686

As described two networks were used:

-   client-net: 192.168.100.0/24
-   server-net: 192.168.101.0/24

#### Client VM

1.  Client has one network interface as described: 192.168.100.2/24
2.  This was achieved by modifying /etc/network/interfaces configuration
    file which had the following structure after modification:

``` {.bash}
user@debian:~$ cat /etc/network/interfaces
auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static 
    address 192.168.100.2
    netmask 255.255.255.0
    gateway 192.168.100.1
    network 192.168.100.0
```

3.  /etc/hosts file was modified where two lines for name translation
    were added:

`192.168.101.2    server    192.168.100.1    router`

4.  After the configuration client network setup looks like that.

![client](/home/jokubas/Pictures/client.png)

#### Server VM

1.  Server has one network interface as described: 192.168.101.2/24
2.  This was achieved by modifying /etc/network/interfaces configuration
    file which had the following structure after modification:

``` {.bash}
user@debian:~$ cat /etc/network/interfaces
auto lo
iface lo inet loopback

auto enp0s3
iface enp0s3 inet static 
    address 192.168.101.2
    netmask 255.255.255.0
    gateway 192.168.101.1
    network 192.168.101.0
```

3.  /etc/hosts file was modified where two lines for name translation
    were added:

<!-- -->

    192.168.100.2   client
    192.168.101.1   router

4.  After the configuration client network setup looks like that.

![server](/home/jokubas/Pictures/server.png)

#### Router VM

1.  Router has two network interface as described:

-   192.168.100.1/24, connected to client-net
-   192.168.101.1/24, connected to server-net.

2.  This was achieved by modifying /etc/network/interfaces configuration
    file which had the following structure after modification:

``` {.bash}
user@debian:~$ cat /etc/network/interfaces
auto lo
iface lo inet loopback

# client-net
auto enp0s3
iface enp0s3 inet static 
    address 192.168.100.1
    netmask 255.255.255.0
    network 192.168.100.0
    
# server-net
auto enp0s3
iface enp0s3 inet static 
    address 192.168.101.2
    netmask 255.255.255.0
    network 192.168.101.0
```

3.  /etc/hosts file was modified where two lines for name translation
    were added:

<!-- -->

    192.168.101.2   server
    192.168.100.2   client

4.  After the configuration router setup looks like that.

![router](/home/jokubas/Pictures/router.png)

### Tools Used

-   telnet -tool for testing communication to another node on the
    network

-   nc -tool for testing the communication to other nodes in the network
    and to test whether the connection times out to the specific ports.

-   wget -for downloading/fetching the the index.html pages from other
    nodes on the network

-   Apache2 -web server running on all the nodes to test the connections
    on port 80.

-   ssh -for testing the connections on the port 22.

-   wireshark -for capturing the traffic and testing the correctness of
    the firewall rules.

-   nmap -for scanning the nodes on the network in order to verify the
    correctness of the firewall rules.

-   iptables -creating, deleting and modifying firewall rules.

​

Main Testing
------------

### Server Part

#### Before Firewall Deployment

1.  nmap scan before the deployment of the rule:

![part2\_nmap\_before](/home/jokubas/Pictures/part2_nmap_before.png)

**open** means that an application on the target machine is listening
for connections/packets on that port. It clearly shows that two services
(ssh on port 22 and http on port 80) are listening for incoming
connections.

2.  Wireshark capture of the client fetching the index page with the
    following command: `wget server`

    before the deployment of the firewall rule (capture on the server
    side):![part2\_before](/home/jokubas/Pictures/part2_before.png)

-   In the red outline we see the TCP connection
    establishment (handshake).
-   In yellow outline (packet 6) we see the HTTP GET request from the
    client to the server.
-   In purple outline we see the payload being sent from the server to
    the client and all the packets being ACK(nowledged ) in the
    packet 10.
-   In the blue outline we see the finish of the TCP connection.

From the capture we see that full connection between client and the
server was established, payload carried from the server to the client
and graceful connection finish. This and nmap scan clearly demonstrates
that connection between client and the server is fully working.

### Part 2

Blocking the access to port 80 so that fetching index page times out.
Dropping all the traffic on port 80 so that no result is returned to the
caller.

After deploying the firewall rules from the script **part2.sh** all the
traffic to the port 80 was blocked. This was verified by the nmap scan
and Wireshark capture on the server.

1.  nmap scan after deployment of **part2.sh** script:

![part2\_nmap\_after](/home/jokubas/Pictures/part2_nmap_after.png)

We see that the connection to the port 80 is **filtered** which means
that Nmap a firewall, filter, or other network obstacle is blocking the
port so that Nmap cannot tell whether it is open or closed. This happens
due to the fact that all the connections to the port 80 are dropped
rather than rejected and caller does not receive any feedback about the
connection to port 80 while in the reject case it would send a
notification to the caller and would allow to clearly identify the
information about the port. It is also clear from picture that ssh
connection is still open and this was verified by connecting to the
server via ssh. This can be seen in the image below where in red we see
the nmap scan and then in the green ssh connection happening from the
client to the server.

![part2\_ssh\_after](/home/jokubas/Pictures/part2_ssh_after.png)

2.  Wireshark capture of the client fetching the index page with the
    following command: `wget server`

    before the deployment of the firewall rule (capture on the server):

![part2\_after\_wireshark](/home/jokubas/Pictures/part2_after_wireshark.png)

In the capture we see the client trying to establish the TCP connection
to the server by sending a SYN packet on the port 80 (green outline).
However, because the firewall DROPs all the packets, the server does not
send anything to the client. We can see the retransmission happening
from the client (source IP is always from the client (192.168.100.2)).

3.  We can see the failed `wget server` operation on the client (as
    expected client times out which means the server is dropping the
    packets it should):
    ![part2\_bash\_call](/home/jokubas/Pictures/part2_bash_call.png)

4.  Therefore, it is verified that the firewall is blocking what it
    should block (i.e. connections to port 80) and allowing all the
    other connections (such as SSH to port 22) to be established. Also,
    because Nmap returns filtered to the single port 80 it means that
    all the other ports rejects the connections by sending back the
    \[RST,ACK\] packet while only port 80 connections completely dropped
    the packets.

### Part 3

Blocking the access to all the ports except for port 22 on the server so
that ssh still works but connections to all the other ports time out.
Basically all the INPUT traffic is dropped except for port 22.

After deploying the firewall rules from the script **part3.sh** all the
traffic was blocked except for port 22 and all the SSH connections were
available. This was verified by the Nmap, nc scan and Wireshark capture
on the server.

1.  nmap scan after deployment of **part3.sh** script:

![part3\_good\_nmap](/home/jokubas/Pictures/part3_good_nmap.png)

This time we use nmap with **-Pn** option because the server drops all
the packets and normally nmap would only perform heavy port scanning
when the host found is up. Therefore if we simply run nmap without any
options we get following behavior because all the ports drops the
packets:

    ![part3_nmap_after](/home/jokubas/Pictures/part3_nmap_after.png)

From the advanced **-Pn** version we see that only a single port 22 for
SSH connections is open. This means that all the other ports drops or
rejects the packets. The standard version of nmap, however, shows that
none of the ping requests were returned back to the caller what implies
that all of the ports refused connection and DROPed the packets as
required.

2.  SSH connection from the client to the server after deployment of
    **part3.sh**:

![part3\_sshwithNmap](/home/jokubas/Pictures/part3_sshwithNmap.png)

After deployment of part3.sh we can again see that standard nmap fails
(red outline), however, the SSH connection is successfully established
(green outline).

This can be confirmed by the wireshark capture of the connection:

![part3\_ssh\_wireshark](/home/jokubas/Pictures/part3_ssh_wireshark.png)

It is clearly visible that connection is established and Diffie-Helman
handshake is made from both and and the information passed between to
hosts. This again confirms that SSH connection is still working with the
firewall rules.

3.  Wireshark capture of the telnet connection:

![part3\_wireshark\_telnet\_timeout](/home/jokubas/Pictures/part3_wireshark_telnet_timeout.png)

We see the TCP SYN packets being send from the client to the server,
however, because the packets are being dropped by the firewall on the
server, the server does not send any ACKs and RST back to the client.

The call from the client to random port 1234 can be seen below which
verifies that the connection times out:

![part3\_telnet\_timeout](/home/jokubas/Pictures/part3_telnet_timeout.png)

4.  Additional testing with netcat: I performed additional testing with
    the netcat to make sure that all the connections times out and the
    port 22 notifies that it is still open. I produced the following
    simple script:

\`\`\`bash \#!/bin/bash

\# check if the connection times out or not \# print all the open
connections function connect(){ \# -w 2 flag sets the timeout for the
connection to 2 seconds echo "QUIT" | nc -w 2 server "\$1" &gt;
/dev/null 2&gt;&1 if \[ \$? -eq 0 \]; then echo "port \$1 is open" fi }

\# run the connection to all of the ports for i in {1..65535} ; do
connect "\$i" & done

sleep 10

\`\`\`

After the run the following results were received which further confirms
that only port 22 is open and other ports DROPs the connections which
eventually times out:

![part3\_my\_test](/home/jokubas/Pictures/part3_my_test.png)

5.  To sum up, we got the following behavior: all the connections to the
    server are dropped and none of the feedback is returned to the
    caller except for the connections to the port 22 which allows to
    establish the SSH connection.

### Router Part

### Part 4

Blocking the access to all ports except for destination port 22 from the
**client-net** to the **server-net** in the router so that only SSH
connection passes the firewall on the router to the server-net. All the
connections from the client-net which are not for port 22 are dropped.
Server is still able to send all the packets out of the server-net to
the client-net.

After deploying the firewall rules from the script **part4.sh** all the
traffic was blocked except for port 22 and all the SSH connections were
available. This was verified by the Nmap, nc scan and Wireshark capture
on both the router and the server.

1.  Wireshark capture of Nmap scan on the **router** before deploying
    the **part4.sh** firewall rules:

![part5\_router\_wireshark\_before\_nmap](/home/jokubas/Pictures/part5_router_wireshark_before_nmap.png)

The scan clearly demonstrates that packets are flowing from and to the
both ends. Client (blue outline)(192.168.100.2) sends multiple SYN
requests to the server (green outline) (192.168.101.2). Later server
responds to those packets by sending packet with RST,ACK flags set.
Therefore, the communication between the server and the client are
allowed to pass arbitrary packets. Therefore, with nmap scan we get the
full scan of the server:

![part2\_nmap\_before](/home/jokubas/Pictures/part2_nmap_before.png)

2.  Nmap scan on the **client** after deploying the **part4.sh**
    firewall rules:

![part5\_nmapPn](/home/jokubas/Pictures/part5_nmapPn.png)

After deploying the rules it is clear that for the client only a SSH
connection is open (red outline) because all the other ports are
filtered as seen in the green outline meaning that no response to those
requests have been returned and they were dropped by the router
firewall.

3.  Nmap scan captured with Wireshark on the **router** after deploying
    the **part4.sh** firewall rules. This was the capture of the scan
    above (step
    2):![part5\_router\_wireshark\_nmap\_after](/home/jokubas/Pictures/part5_router_wireshark_nmap_after.png)

Now all the requests from client are being dropped on the router
firewall. This can be seen by exploring the source address which is
almost always the one of the client (192.168.100.2)

with a single exception. Because router allows connections from client
to server on port 22 only. These are the packets that gets through the
routers firewall to the server. When the server receives those it sends
the SYN,ACK bach to the client. This is seen in the green outline where
server's IP is in purple and the ports from which the server responds to
the client are 22 (yellow outline). This verifies the fact that the
server receives ping to the port 22 only. We can make sure that this is
the case by applying filter to the router of the same capture to make
sure that responses from the server are only made from the port 22:

![part5\_router\_wireshark\_filter\_nmap](/home/jokubas/Pictures/part5_router_wireshark_filter_nmap.png)

This fact was also verified by running the Wireshark capture on the
**server** as well during the Nmap scan:

![part5\_wireshark\_server\_nmap\_after](/home/jokubas/Pictures/part5_wireshark_server_nmap_after.png)

We can see that SYN requests on the server were received to the port 22
only. This confirms the correct firewall behavior on the router because
only requests to port 22 are passed throw by the router.

4.  After deployment of **part4.sh** firewall rules the SSH connections
    were passing from client to the server through the router. There was
    no difference in the Wireshark captures before and after the rules
    were deployed. The capture on the **router** of the SSH between the
    server and the client happening can be seen below:

![part5\_router\_wireshark\_ssh](/home/jokubas/Pictures/part5_router_wireshark_ssh.png)

We see packets flowing to both ends and payload being carried through
what confirms that port 22 is still open for the connections coming from
the client-net. The capture of the same connection done on the
**server** can be seen below verifying the fact of SSH still working
with firewall rules being deployed:

![part5\_wireshark\_server\_ssh](/home/jokubas/Pictures/part5_wireshark_server_ssh.png)

5.  Wireshark capture of the telnet connection to the random port (not
    port 22) on the **router** confirms that packets are not going
    through the firewall on the router and that **router** block what it
    should block:

![part5\_telnet\_router](/home/jokubas/Pictures/part5_telnet_router.png)

We see the TCP SYN packets being send from the client to the server,
however, because the packets are being dropped by the firewall on the
**router**, the server does not receive anything and that was confirmed
by the capture on the server which did not capture any traffic. This
confirms that router firewall blocked that traffic.

The call from the client to random port 1596 can be seen below which
verifies that the connection times out:

![part5\_client\_telnet](/home/jokubas/Pictures/part5_client_telnet.png)

6.  I ran same netcat script as in the part3 to confirm that all the
    connections time out except for one on port 22 :

![part3\_my\_test](/home/jokubas/Pictures/part3_my_test.png)

7.  Confirming that router allows all the packets sent by the server to
    go through to the client-net.

I ran wireshark on the client to confirm that all the traffic from the
server reaches the the client and firewall on the router is not dropping
any of those packets. I ran `nmap client` and client captured all the
packets sent from the
server:![part\_client\_good](/home/jokubas/Pictures/part_client_good.png)

This confirms that firewall was passing what it should pass and did not
block any outgoing traffic from the server.

8.  To sum up, we got the following behavior: all the connections to the
    server are dropped and none of the feedback is returned to the
    caller except for the connections to the port 22 which allows to
    establish the SSH connection. This is the same behavior as with the
    part 3, however, now all the connections are being dropped by the
    router rather than the server. The server does not receive any
    traffic that it is suppose to reach which is SSH on port 22. Also,
    we verified that traffic from the server is able to leave the
    server-net freely without any constraints.

### Part 5

### Part 6
