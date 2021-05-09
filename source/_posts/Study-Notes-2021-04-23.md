---
title: Study Notes - 2021/04/23
date: 2021-04-23 23:24:30
tags: [Penetration Testing, Study Notes]
---

# Automated Enumeration 
windows automated enumeration tool:
```
c:\Tools\privilege_escalation\windows-privesc-check-master>windows-privesc-check2.exe
```

-h help  
--dump dump output
-G list groups 


Linux:  
```
./unix-privesc-check standard > output.txt
```

# Windows privilege escalation examples
## Windoes privilege and integrity levels 
Access token assigned to a user  
security id (sid) unique to each object including access token, user account, group account.  
Integrity mechanism:

From Windows Vista onward, processes run on four integrity levels:
• System integrity process: SYSTEM rights
• High integrity process: administrative rights
• Medium integrity process: standard user rights
• Low integrity process: very restricted rights often used in sandboxed processes


## User account control (UAC)  
Even logged in as admin, we are operating at Medium integrity level, to switch, specifying run as administrator:
```
powershell.exe Start-Process cmd.exe -Verb runAs  
```
run cmd.exe in as administrator  
credential prompt and consent prompt  

## User account control bypass
allows an administrator user to bypass UAC by silently elevating our integrity level from medium to high.  

leverage an interesting UAC bypass based on fodhelper.exe   
```
C:\Windows\System32\fodhelper.exe  
```

In order to gather detailed information regarding the fodhelper integrity level and the permissions required to run this process, we will inspect its application manifest

dump the manifest of fohelper.exe:
```
cd C:\Tools\privilege_escalation\SysinternalsSuite
sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe
```

```
<requestedPrivileges>
    <requestedExecutionLevel
        level="requireAdministrator"
    />
</requestedPrivileges>

<autoElevate>true</autoElevate>
```


