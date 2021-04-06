#!/bin/bash

# exit on failure of any command
set -e

# make a tun / tap device
sudo mknod /dev/net/tap c 10 200
sudo chmod 0666 /dev/net/tap

# disable ipv6 ( for dev we do not care )
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=1

# check if a net device has been passed
if [ $# -ne 1 ]; then 
	echo "which net device should be used?"
	exit 1;
fi 
echo "setting up with $1 , on the tun subet of 10.0.0.0/24" 

# setup ipv4 forwards to new device
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -I INPUT --source 10.0.0.0/24 -j ACCEPT
sudo iptables -t nat -I POSTROUTING --out-interface $1 -j MASQUERADE
sudo iptables -I FORWARD --in-interface $1 --out-interface tap0 -j ACCEPT
sudo iptables -I FORWARD --in-interface tap0 --out-interface $1 -j ACCEPT
