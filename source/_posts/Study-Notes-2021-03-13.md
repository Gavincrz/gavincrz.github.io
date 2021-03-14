---
title: Study Notes - 2021/03/13
date: 2021-03-13 19:54:35
tags: [Penetration Testing, Study Notes]
---

Some reviews: 
# Kali Linux
/bin/   
/sbin/  system programs  
/etc/   files  
/tmp/ temporay file delete on boot  
/usr/bin/  user binary  
/usr/share application support files  

## Linux Commands:
```
man -k passwd:  key word search
└─$ man -k '^passwd$'  
passwd (1)           - change user password
passwd (1ssl)        - compute password hashes
passwd (5)           - the password file
man 5 passwd
```

apropos == man -k  

ls -a1  
-1 means one file each line  
cd, mkdir, pwd  
with space:  
cd module\ one/  
mkdir -p /hello/world/{recon, exploit, report}  

### Finding files in kali linux
find, locate, which  

`locate` seach a built in database instead of harddisk, can be update manually. `sudo updatedb`  

find can search size, type....
```
sudo find / -name sbd*
```

## manage linux services
```
sudo systemctl start ssh
sudo ss -antlp | grep sshd
ss  is  used to dump socket statistics.
```
-a all  
-n numerical  
-t tcp  
-l listening  
-p display process  

### list all available services:
```
systemctl list-unit-files
```

## Search/install/remove tools
sudo apt update   
sudo apt upgrade \<package-name>

apt-cache search pure-ftpd     search if package exist, search in package description  
apt show \<pacage-name>  show the description  
apt install \<package-name>   
apt remove --purge  completely remove the package including user configurations  

sudo dpkg -i \<path to the package file.deb>      will not install any dependency   


# Commandline
## Some environment variables:
$PATH, $USER, $PWD, $HOME
### define EV:
```
export b=10.11.1.220
ping -c 2 $b
```
without export, only affect current bash, not inherit by spawning bash  
```
env
```

## Bash history
```
history
!32   # replay line 32
!!    # repeat the last command
```
saved in `~/.bash_history`  
`$HISTSIZE`,  `$HISTFILESIZE`  
`CTRL+R` reverse-i-search  looking for most recent matched command  

## Pipline and redirection
0 STDIN, 1 STDOUT, 2 STDERR  

Redirect to a new file:  
`echo "test" > test.txt`  
Redirect to an existing file:  
`echo "test" >> test.txt`   
Redirect from a file:  
`wc -m < test.text`  connect the file to the STDIN of wc  
Redirect STDERR  
`ls ./test 2>error.txt`  

### Piping
`cat error.txt | wc -m`   output of cat to input of wc  

## Text searching 
`ls -la /usr/bin | grep zip`  
-r recursive search  
-i ignore case  
sed:  
`echo "I need to try hard" | sed 's/hard/harder/'`
cut:  
`echo "hello, world, ???" | cut -f 2 -d ","`  
-f field  
-d delimiter  
**can only acce[t single char delimiter**  
`echo "hello::there::friend" | awk -F "::" '{print $1, $3}'`  
-F field separator  

```
cat access.log | cut -d " " -f 1 | sort -u
cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn
```

-n compare according to string numerical value  
-r reverse the result of comparisons  


# Nano
`Ctrl + K` cut the line  
`Ctrl + U` paste the line  
`Ctrl + W` search in the file  

# Vim
`dd` delete current line  
`yy` copy the current line  
`p` to paste the clipboard content  
`x` delete the char under the current cursor  

# File comparison 
`comm file1 file2`  unique line in file1. file2, and in both file  
`comm -12 file1 file2`  supress col1,2, only display lines in both files   
`diff -c/-u`  
`vimdiff`  `Ctrl + W + arrow` switch window  
`[/] + c` jump to prev/next change  
`d+o` get the change in other window and put to the current one  
`d+p` put the change in current window and put to the other one   

# Manage processes
## background process
`Ctrl + Z` to suspend it, then resume it using `bg`  

`jobs` shows the jobs in the current terminal  
`fg %[jobnum]` return the job to the foreground  


`ps -ef`  
 -e, --everyone  show processes of all users   
 -f, --full      show process uids, ppids  


 # File and Command Monitoring
 `tail and watch`  
 `watch`  run command every 2 second  
 ```
 watch -n 5 w
 ```
w - Show who is logged on and what they are doing.  
-n   every 5 seconds  

# Download Files:
`wget -O [dest] [url]`  
`curl -o [dest] [url]`  
`axwl -a -n 50 -o [dest] [url]`  
-n number of connections use  
-a      Alternate progress indicator  

# Bash environment
`export HISTCONTROL=ignoredups`

System bash `/etc/bash.bashrc`  
