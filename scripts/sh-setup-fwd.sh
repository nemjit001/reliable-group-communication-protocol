#!/bin/bash
set -ex
if [ $# -ne 1 ]; then 
	echo "which device?"
	exit 1;
fi 
echo "setting up with $1 , on the tun subet of 10.0.0.0/24" 

sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -I INPUT --source 10.0.0.0/24 -j ACCEPT
sudo iptables -t nat -I POSTROUTING --out-interface $1 -j MASQUERADE
sudo iptables -I FORWARD --in-interface $1 --out-interface tap0 -j ACCEPT
sudo iptables -I FORWARD --in-interface tap0 --out-interface $1 -j ACCEPT
