# linux-skb-lookup-fix
This is an attempt to fix socket-lookups for packets transiting through a VRF to the main routing-table in linux.

## What's the problem?

The Linux kernel's VRF implementation is a bit limited. When a packet arrives on an interface enslaved to a VRF-device it's tagged with the VRF and once it's tagged the kernel won't consider sockets which aren't bound to a device.
So even though the packet is forwarded from a VRF to an interface in the main table and then traverses up through local input the kernel still won't consider sockets listening on the address of that interface. 

* Example config
  * interface lan with ip-address 192.0.2.1/24 - not enslaved (e.g., "lan" is in the main routing-table)  
    sshd is listening on port 22 on all interfaces:  
    `LISTEN 0  4096      *:22         *:*     users:(("sshd",pid=1169,fd=3))`
  * interface blue1 (ip-address irrelevant) - enslaved to VRF BLUE (`ip link show` shows master: BLUE)
  * VRF BLUE has the following route visible via `ip route show vrf BLUE`:  
      `unicast 192.0.2.0/24 dev lan scope host metric 20`
* Packet flow:
  1. A tcp-packet arrives on interface blue1 destined for ip 192.0.2.1 port 22 (sshd on lan).
  2. Since blue1 is enslaved to VRF BLUE the incoming packet's skbuff gets bound to VRF BLUE (skb-\>dev, skb-\>l3mdev etc is set to vrf-interface BLUE).
  3. The destination 192.0.2.1 is checked against VRF BLUE's routing-table and it resolves to route (BLUE) `unicast 192.0.2.0/24 dev lan` -> (main) `local 192.0.2.1` and the packet is forwarded directly to local input.
  4. `tcp_v4_rcv()` tries matching the packet by calling `__inet_lookup_skb(...) which then (few steps further down) calls "compute_score()" for each found socket.
  5. `compute_score()` calls `inet_sk_bound_dev_eq()` which checks if the socket socket is bound, if not it checks if the ingress-device was a vrf-device (sdif is non-zero) and since it was it returns non-zero and the check fails.
  6. The connection-attempt to 192.0.2.1:22 fails even though the packet reached the interface and sshd is listening on port 22. 


## Livepatch Module
This repository contains a livepatch-module implementing a POC which solves the problem.
It's not a great solution, it would be better if there was a more efficient way to check if the destination-interface was a non-vrf interface.

# Using it

Building the livepatch:
```
$ git clone https://github.com/cetex/linux-skb-lookup-fix.git
$ cd linux-skb-lookup-fix/src
$ make
```
The module is output as src/livepatch-skb-lookup-fix.o and can be loaded directly from it.

Loading the livepatch:
```
$ insmod livepatch-skb-lookup-fix.o
```

Signing and loading the patch using the local signing-keys from dkms:
```
$ sudo make sign_load
```
