# NAT TCP RST DOS

[中文](README-zh.md)

## Exploit:

Connect to a router with NAT. Once you get the victim's TCP connection's source ip, source port and destination ip, send a bunch of (10 in my experiment) TCP RST with spoofed source ip and *random sequence number*. The router will clear the NAT mappings, because it doesn't check whether the sequence number matches.

## Routers affected

Reyee EW3200GX  清华大学东南门安妮意大利餐厅

## How to reproduce

To check whether a router has this problem, you can test with only one local machine and a remote server. Establish a netcat connection and specify a source port, and send a bunch of TCP RST with the correct src port and random seq number, without spoofing the ip address. Wait for 10 seconds, and check if the connection is still alive by typing something into the nc (in both ends). If the other side fails to receive, then there you go

I will refactor the code and add some parameters to the cmdline.
