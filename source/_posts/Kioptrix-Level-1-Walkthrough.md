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

![image](/images/netdiscover.png "screenshot of netdiscover")

So the target IP address is `192.168.119.254`
 
# Port Scan
## first Scan
```
nmap -Pn -sS --stats-every 3m --max-scan-delay 20 --max-retries 1 --defeat-rst-ratelimit -p1-65535 -oN ~/kiotrix1.txt 192.168.119.254
```

```
--max-scan-delay to avoid following ICMP package get lost  

      --defeat-rst-ratelimit
           Many hosts have long used rate limiting to reduce the number of ICMP error messages (such as
           port-unreachable errors) they send. Some systems now apply similar rate limits to the RST (reset)
           packets they generate. This can slow Nmap down dramatically as it adjusts its timing to reflect those
           rate limits. You can tell Nmap to ignore those rate limits (for port scans such as SYN scan which don't
           treat non-responsive ports as open) by specifying --defeat-rst-ratelimit.

           Using this option can reduce accuracy, as some ports will appear non-responsive because Nmap didn't
           wait long enough for a rate-limited RST response. With a SYN scan, the non-response results in the port
           being labeled filtered rather than the closed state we see when RST packets are received. This option
           is useful when you only care about open ports, and distinguishing between closed and filtered ports
           isn't worth the extra time.
```
The port identifiers are unsigned 16-bit integers, meaning that the largest number you can put in there is 2^16-1 = 65535

Get error: `All 65535 scanned ports on 192.168.119.254 are filtered`


## Issue
192.168.119.254 is not the IP address of Kioptrix box. I encounter a problem that Kioptrix can not be set use NAT or Host only mode. It will automatically switch to Bridged(Automatic) when launching. So weird. Link: [network setting automatically switched to Bridged in VMWare Player](https://stackoverflow.com/questions/66538382/network-setting-automatically-switched-to-bridged-in-vmware-player)

I will stick with briged mode for now, it is not safe btw.

So the IP address of target Box is `192.168.0.22`

## First Scan continue
```
map -sS -n -Pn -p- -T4 192.168.0.22 

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
443/tcp  open  https
1024/tcp open  kdm
```


## Second Scan
```
nmap -Pn -nvv -sSV -p 22,80,111,139,443,1024 --version-intensity 9 -A -oN 192.168.0.22
```
-n/-R: Never do DNS resolution/Always resolve [default: sometimes]
--version-intensity \<level\>: Set from 0 (light) to 9 (try all probes)
-sSV is a combine of sS and sV, sV service and version detection


## Some Notes
interesint 80, 443 for webserver, tcp 139 samba 

SMB a communication protocal for providing shared access to files, printers, and serial ports between nodes on a network

## UDP Scan
```
nmap --top-ports 1000 -sU -Pn --stats-every 3m --max-retries 1 -T3 192.168.0.22
```

# SSH enumeration
openssh version: `OpenSSH 2.9p2`  
Google it, find some CVE's with Exec Code Overflow [CVE-2002-0640](https://www.cvedetails.com/cve/CVE-2002-0640/)
need OS to ` when OpenBSD is using PAM modules with interactive keyboard authentication (PAMAuthenticationViaKbdInt). `

```
searchsploit openssh
```

Try directly connect to it:
```
ssh 192.168.0.22    
Unable to negotiate with 192.168.0.22 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1

# so use one of the exchange method and try again
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 192.168.0.22 

Unable to negotiate with 192.168.0.22 port 22: no matching cipher found. Their offer: aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,arcfour,aes192-cbc,aes256-cbc,rijndael128-cbc,rijndael192-cbc,rijndael256-cbc,rijndael-cbc@lysator.liu.se

# then add the cipher
ssh -c aes128-cbc -oKexAlgorithms=+diffie-hellman-group1-sha1 192.168.0.22 
root@192.168.0.22's password: 
```
Last resort for passwork attack, easy be detected, if theres a log
Usually SSH is not your first thing to try



## HTTP Enumeration
port 80 and 443
* go to their web page through web broser
* view the source code
* check out https://

### Directory Scan
