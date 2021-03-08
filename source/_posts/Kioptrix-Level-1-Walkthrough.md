---
title: Kioptrix Level 1 Walkthrough
date: 2021-03-08 00:07:37
tags: WalkThrough
---

# Find IP Address of target Box
## check current interface:
```
─# ifconfig                                                     
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.119.130  netmask 255.255.255.0  broadcast 192.168.119.255
        inet6 fe80::20c:29ff:fec4:f034  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:c4:f0:34  txqueuelen 1000  (Ethernet)
        RX packets 184146  bytes 51512617 (49.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 167933  bytes 11553532 (11.0 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```
interface is `eth0`

## netdiscover
Using ARP messages to discover hosts
```
netdiscover -i eth0 
```
-i device: your network device (interface)  

{% asset_img  kioptrix_walkthrough_netdiscover.png %}

So the target IP address is `192.168.119.254`

# Enumeration
...