#!/bin/bash

ip addr add 10.0.4.1/24 dev tun0
echo "ip address of tun0 is 10.0.4.1"
ifconfig tun0 up
echo "NIC is up"
route add -net 10.0.5.0 netmask 255.255.255.0 dev tun0
sysctl net.ipv4.ip_forward=1
route add -net 10.0.20.0 netmask 255.255.255.0 gw 10.0.10.1
route add -net 10.0.20.0 netmask 255.255.255.0 dev tun0
echo "add route to tun0"
