---
title: Study Notes - 2021/03/29
date: 2021-03-29 20:39:22
tags: [Penetration Testing, Study Notes]
---

# Privilege Escalation 

## Manual Enumeration
enumerating users:  
`whoami` work both for win and linux  
windows: `net user <username>`  
Linux: `id`  
reveal other users :  
windows: `net user` 
linux: `cat /etc/passwd`  

enumeratin hostname:  
`hostname`  

## Enumerating OS version 
Windows: systeminfo  
linux: `cat /etc/issue`  
`cat /etc/*-release`  
`uname -a`  

## Running processes and services
`tasklist /SVC`  
/SVC                    Displays services hosted in each process.  
**Does not list task run by privieleged users**  

linux:  
`ps aux`  

## Enumerating Network information  
windows:  
`ipconfig /all`  
`route print`  route information  
`netstat -ano`  network connections  
-a display all active tcp connections  
-n            Displays addresses and port numbers in numerical form.  
-o            Displays the owning process ID associated with each connection.  

Linux:  
`ifconfig -a`  
`ip a`  
`/sbin/route`  
`ss -anp`  
`netstat -anp`  


## Enumerating Firewall Status and Rules  
windows:  
`netsh advfirewall show currentprofile`  
list the firewall rules:  
`netsh advfirewall firewall show rule name=all`  

Linux: must have root privilege to access firewall rules  
For example, the iptables-persistent464 package on Debian Linux saves firewall rules in specific
files under the /etc/iptables directory by default. These files are used by the system to restore
netfilter465 rules at boot time. These files are often left with weak permissions, allowing them to
be read by any local user on the target system.  

grep -Hs iptables /etc/*  
-H display file name with file number 
-s suppress error messages 


## Enumerating Scheduled tasks  
`schtasks /query /fo LIST /v`  
/query argument displays tasks and /FO LIST sets the output format to a simple list. We can also use /V to request verbose output.


Linux:  
The Linux-based job scheduler is known as Cron.467 Scheduled tasks are listed under the /etc/cron.* directories 

ls -lah /etc/cron*  sometimes need permision  
-h human readable  

cat /etc/crontab  


if those script have a weak permissions, we change change it and escalate pribilege  
## Enumerating Installed app and patch levels  
`wmic product get name, version, vendor`  

We can use wmic with the **product** WMI class argument followed by **get**, which, as the name states, is used to retrieve specific property values. We can then choose the properties we are interested in, such as name, version, and vendor  

note: product class only list application installed by the windows installer  

Similarly, and more importantly, wmic can also be used to list system-wide updates by querying the Win32_QuickFixEngineering (qfe) WMI class.
`wmic qfe get Caption, Description, HotFixID, InstalledOn`  

Linux:  
Debian based:  
dpkg -l  
Redhat based:  
rpm  


## Enumerating readble and writable dirs 
**Accesschk**:  
enumerate the Program Files directory in search of any file or directory that allows the Everyone group write permissions  

We will use -u to suppress errors, -w to search for write access permissions, and -s to perform a recursive search.
```
accesschk.exe -uws "Everyone" "C:\Program Files"
```
powershell:  
```
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

Linux:  -type d to locate directories
```
find / -writable -type d 2>/dev/null  
```


## Enumerating Unmounted Disks
`mountvol`  
On Linux-based systems, we can use the `mount` command to list all mounted filesystems. In addition, the `/etc/fstab `file lists all drives that will be mounted at boot time.  
use `lsblk` to view all available disks  

## Enumerating Device Drivers and Kernel Modules 
powershell: 
```
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
```

find version number of each module: 
```
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

Linux:
```
lsmod
/sbin/modinfo libata  
```
modinfo require full path name to run  

## Enumerating Binaries That AutoElevate 
First, on Windows systems, we should check the status of the `AlwaysInstallElevated` registry setting. If this key is enabled (set to 1) in either `HKEY_CURRENT_USER` or `HKEY_LOCAL_MACHINE`, any user can run Windows Installer packages with elevated privileges.

```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
```

If this setting is enabled, we could craft an MSI file and run it to elevate our privileges

Linux:  
find suid-marked binaries, the binary will be executed with the file owner's permission
```
find / -perm -u=s -type f 2>/dev/null
```

