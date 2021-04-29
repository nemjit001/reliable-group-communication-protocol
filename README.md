# Reliable Group Communication Protocol (RGCP)

Designed and implemented as a Bachelor's Thesis for the VU Amsterdam.

## How to use the dev netstack

To use the development netstack and the RGCP protocol, run the shell scripts in the `./scripts` folder in the following order:

1. `sudo ./sh-make-tun-dev.sh` -> setup a virtual network device
2. `sudo ./sh-disable-ipv6.sh` -> disable IPV6 support for the device
3. `sudo ./sh-setup-fwd.sh <ethernet dev>` -> forward incoming packets to the virtual subnet, allowing us to process the packets instead of the kernel

To allow a program to use the development netstack, run the following:

```bash
sudo ./sh-hack-rgcp.sh <path to program>
```

This loads the rgcp netstack library, overloading the socket API syscalls with our own functions.

## Author

<!--  -->
