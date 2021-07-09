---
title: Study Notes - 2021/07/08
date: 2021-07-08 22:19:35
tags: [Penetration Testing, Study Notes]
---

# Http tunneling through deep packet inspection 
Senario: only a specific protocal is allowed. E.g. ssh protocal is not allowed. and theres a deep packet inspection in the firewall that only allow http packet. An unused port 1234 is open by misconfiguration (unusal in real case)
port 3389 remote desktop prot 

On compromised linux machine:   
```
ssh -L 0.0.0.0:8888:w.x.y.z:3389 student@127.0.0.1  
```

it is not restricted since they both in the internal subnet  

encapsulate the tunnel within http package

```
sudo apt install httptunnel
```

http tunnel is server-client based, on compromised linux:
```
student@debian:~$ hts --forward-port localhost:8888 1234
```
on kali:
```
kali@kali:~$ htc --forward-port 8080 10.11.0.128:1234
```


