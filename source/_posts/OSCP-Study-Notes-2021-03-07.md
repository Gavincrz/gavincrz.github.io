---
title: OSCP Study Notes - 2021/03/07
date: 2021-03-07 14:04:11
tags: [OSCP, Study Notes]
---
# TRY HARDER!!
# Table of Contents:
* [Miscellaneous](#Miscellaneous)
* [Metasploit Setup](#Metasploit-Setup)
    * [Hypervisor Setup](#Hypervisor-Setup)
* [Metasploit Filesystem and Libraries](#METASPLOIT-FILESYSTEM-AND-LIBRARIES)
* [Metasploit Fundamentals](#Metasploit-Fundamentals)
* [Commandline Refresher](#Commandline-refresher)
* [Kali Services](#Kali-Services)
* [Bash Scripting](#Bash-scripting)
* [Information Gathering](#Information-Gathering)
* [Scanning with nmap](#Scanning-with-nmap)
* [Scan with Metasploit](#Scan-with-Metasploit)
* [Kioptrix: Level 1](#Kioptrix:-Level-1)
# Miscellaneous
Zhihu Guide: [如何拿到OSCP渗透测试认证](https://zhuanlan.zhihu.com/p/71112837)  
Start Date: `Sat, 13 Mar 2021, 19:00`  

# Metasploit Setup
Requirements: [METASPLOIT UNLEASHED REQUIREMENTS
](https://www.offensive-security.com/metasploit-unleashed/requirements/)

## Hypervisor Setup
* Download [VMware Player](https://www.vmware.com/products/workstation-player.html)  
* Download [KALI LINUX](http://www.kali.org/downloads/)
* Download [Metasploitable](https://sourceforge.net/projects/metasploitable/files/latest/download)

Direct Control back to host: `Alt`+`Ctl`

### Kali Linux
* RAM: 2GB
* Disk 10GB
* Username: gavin
* PasswordTip: [cc6]
* Update Metasploit: `apt update && apt upgrade`

### MetaSploitable:
* RAM: 512MB
* login: msfadmin:msfadmin

# Metasploit Filesystem and Libraries
Link: [METASPLOIT FILESYSTEM AND LIBRARIES](https://www.offensive-security.com/metasploit-unleashed/filesystem-and-libraries/)  
Installed in Kali Linux by default  
pacakge path: `/usr/share/metasploit-framework`  
DATA/DOCUMENTATION/LIB/MODULES/PLUBINS/SCRIPTS/TOOLS

Two Module Locations:  
* Primary Modules: `/usr/share/metasploit-framework/modules/`
* Custom Modules: `~/.msf4/modules/`

## Modules
* **Exploits**: exploit modules are defined as modules that use payloads  
* **Auxiliary**: Auxiliary modules include port scanners, fuzzers, sniffers, and more.
* **Payloads, Encoders, Nops**: Payloads consist of code that runs remotely, while encoders ensure that payloads make it to their destination intact. Nops keep the payload sizes consistent across exploit attempts.

# Metasploit Fundamentals
* start: `msfconsole`
* [Commands](https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/)

## Payload Type
### Singles
Singles are payloads that are self-contained and completely standalone. A Single payload can be something as simple as adding a user to the target system or running calc.exe
### Stagers
Stagers setup a network connection between the attacker and victim and are designed to be small and reliable. It is difficult to always do both of these well so the result is multiple similar stagers. Metasploit will use the best one when it can and fall back to a less-preferred one when necessary.
### Stages
Stages are payload components that are downloaded by Stagers modules. The various payload stages provide advanced features with no size limits such as Meterpreter, VNC Injection, and the iPhone ‘ipwn’ Shell.

# CommandLine Refresher
pwd, man, ls, cd, mkdir, rmdir, cp, mv, **locate(find file)**, adduser, su, sudo, echo, cat, nano, chmod, ifconfig, ping  

`adduser bob sudo` create bob as sudo user

# Kali Services:
http, ssh, postgresql
## http
`service apache2 start`  
`systemctl enable apache2`  
`service apache2 stop`  

## netstat
`netstat -antp`  
-a, --all                display all sockets (default: connected)  
-n, --numeric            don't resolve names  
-t --tcp
-p, --programs           display PID/Program name for sockets (permission relatied)  

## postgresql
enable postgresql will make msfconsole search more quickly (can not feel it)

# Bash Scripting
`ping -c 1 192.168.119.2 | grep "64 bytes" | cut -d " " -f 4 | sed 's/.$//'`  
-d, --delimiter=DELIM   use DELIM instead of TAB for field delimiter  
-f, --fields=LIST       select only these fields;  also print any line that contains no delimiter character, unless the -s option is specified

`sed 's/.$//'`  
The “.” (dot) indicates any character in sed, and the “$” indicates the end of the line. In other words “.$” means, delete the last character only.

ping all responed IP in the network: 
``` bash
#!/bin/bash
if [ "$1" == "" ] # space after [
then
	echo "Usage: ./ping_script.sh [network]"
	echo "Example: ./ping_script.sh 192.168.119"
else
	for ip in `seq 1 254`; do 
		ping -c 1 $1.$ip | grep "64 bytes" \
		| cut -d " " -f 4 | sed 's/.$//' &
	done
fi
```
``` bash
./pingsweep.sh > iplist.txt
cat iplist.txt | sort -u
``` 
-u show only unique results
```
for ip in $(cat iplist.txt); do nmap -Pn $ip; done
```
nmap:  
-Pn: Treat all hosts as online -- skip host discovery  

# Information Gathering
## Tools:
Google, Exploit-DB, Google Hacking DB, WHOIS, Netcraft, theharvester
## Google
`site:cnn.com  -site:www.cnn.com filetype:pdf `  
`showdan`  devices connect to internet
## Netcraft
Search web by domain https://searchdns.netcraft.com/ `*.cnn.com`
## Whois
looking for domain information `whois cnn.com`
## theHarvester 
`theHarvester -d cnn.com -b google -l 200`  
-d domain  
-b datasource (e.g. bing, linkedin, google)  
-l limit the number of results

`nc -nv xxx.xxx.xxx.xxx <port>`  
-n                      numeric-only IP addresses, no DNS  
-v                      verbose [use twice to be more verbose]  

# Scanning with nmap
pingsweep, but not quite accurate, false postive
``` bash
nmap -sn 192.168.119.1-254
nmap -sn 192.168.119.0/24
```
-sn: Ping Scan - disable port scan

``` bash
nmap -vv -Pn -A -sS -T4 -p- -oN tcpscan.txt 192.168.119.129
```
-A: Enable OS detection, version detection, script scanning, and traceroute  
-sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans  
**use sS to avoid triggering fireware, SEND, ACK, instead of ACK back, send RST(reset))**  
-T<0-5>: Set timing template (higher is faster) **may be get detected when set high, in real world, T4 seems fine**  
-p \<port ranges>: Only scan specified ports  
Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
-p- (all)  
-oN/-oX/-oS/-oG \<file\>: Output scan in normal, XML, s|\<rIptkIddi3,and Grepable format, respectively, to the given filename.  

**Speedup tips: quickly scan for open ports, then do -A on open ports to gather more info**

## UDP scan
```
nmap -vv -Pn -A -sU -T4 --top-ports 200 -oN udpscan.txt 192.168.119.129
```
--top-ports \<number\>: Scan \<number\> most common ports 

**Again, two stage scans, very useful, save time**

## nmap script engining
script stored at `/usr/share/nmap/scrips`
```
nmap -vv -p 137 --script=all 192.168.119.129
```

# Scan with Metasploit
``` metasploit
msfconsole
search portscan

## enter module:
use auxiliary/scanner/portscan/syn

show options
## change options, case insensitive
set ports 1-65535
set rhost 192.169.119.129
set threads 10

## run it
exploit
```

# Kioptrix: Level 1
Download: https://www.vulnhub.com/entry/kioptrix-level-1-1,22/
## Walk Through
{% post_link Kioptrix-Level-1-Walkthrough %}