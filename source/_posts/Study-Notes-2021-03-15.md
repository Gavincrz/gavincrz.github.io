---
title: Study Notes - 2021/03/15
date: 2021-03-15 20:36:12
tags: [Penetration Testing, Study Notes]
---

# NFS Enumeration
port 111   
`nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254`  

## nmap nfs nse script 
`nmap -p 111 --script nfs* 10.11.1.72`  
```
PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /home 10.11.0.0/255.255.0.0
```
mount it to our machine:  
```
mkdir home_72
sudo mount -o nolock 10.11.1.72:/home home_72
```
-o nolock disable filelocking, need for old NFS servers

```
drwxr-xr-x 2 nobody 4294967294 4096 Oct 27  2019 .
drwxr-xr-x 7 root   root       4096 Sep 17  2015 ..
-rwx------ 1 nobody 4294967294   48 Oct 27  2019 creds.txt
```
shows nobody instead of userid, can not create a user id as guide shown  

# SMTP enumeration 
find existing users   
port 25, udp   
```
nc -nv 10.11.1.217 25
VRFY idontexist
```
# SNMP Enumeration
## SNMP MIB Tree
## Scan for SNMP
`sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt`  
--open only display open ports    
`onesixtyone -c community -i ips`   
`onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.119.133 `   

## example 
enumerating the entire MIB tree:  
`snmpwalk -c public -v1 -t 10 10.11.1.14`  
-v snmp version number 
-t increase timeout to 10s  

## enumerating windows users
## enumerating windows processses
## open tcp ports
## software


# Vulnerability Scanning
scanner with nessus  
open in browser: `https://localhost:8834/`  

## Vul scan with nmap
```
cd /usr/share/nmap/scripts/
head script.db
# can grep this file
sudo nmap --scriot vuln 10.11.1.10
```


# Attack web application 
https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project  
1. Injection
2. Broken Authentication
3. Sensitive Data Exposure
4. XML External Entities (XXE)
5. Broken Access Control 
6. Security Misconfiguration
7. Cross-Site Scripting (XSS)
8. Insecure Deserialization
9. Using Components with Known Vulnerabilities
10. Insufficient Logging & Monitoring

## Web application Enumeration
* Programming language and frameworks
* Web server software
* Database software
* server OS 

### Inspecting URLs
php  
For example, a Java-based web application might use .jsp, .do, or .html.
concept of routes, map uri to a section of code
### Inspecting Page Content
Open Debugger, can pretty code content  

Right click -> insepct Element  

View Response headers:  
- proxy 
- firefox network tool 

Server header somtimes reveal the server app and version number  
Header start with `X-` are non-standard HTTP headers, can reveal additional info  

### Inspecting sitemaps
most common site maps files:  
`robots.txt`  
`sitemap.xml`  

### Locating administration consoles
Two common examples are the manager application for Tomcat and phpMyAdmin for MySQL hosted at /manager/html and /phpmyadmin respectively.  

## Web application assessment tools
### DIRB
web content scanner, use wordlist. 
`dirb http://www.megacorpone.com -r -z 10`   
-r to scan non-recursively, and -z 10 to add a 10 millisecond delay to each request  

### Burp suite 
foxyproxy firefox addon  
add ca certificate for burpsuite  
proxy->option->regenerate ca certificate  
goto browser, enable proxy, open http://burp  -> CA certificate to download crt file, import certificate  
send to repeater, send single request  

### Nikto
webserver scanner  - not intend to stealth itself, send info in user-agent to identify itself  
-maxtime  
-T which types of tests  
```
nikto -host=megacorpne.com -maxtime=30s
```

## Exploiting
### exploting admin consoles
Windows client -> XAMPP, start apache and mysql  
```
dirb http://10.11.0.22 -r
==> DIRECTORY: http://10.11.0.22/phpmyadmin/
```

### Burp intruder 
`<input type="hidden" name="set_session" value="7r8oiuuoofdtcgc7ao731o0tcc" />`  
`<input type="hidden" name="token" value="K&amp;$&amp;FR1\.cQ4)QW(" />`  

send to intruder  
select positions, type: Pitchfork, allowing us to set a unique payload list for each position.

