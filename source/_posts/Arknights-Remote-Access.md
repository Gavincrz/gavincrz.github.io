---
title: Arknights Remote Access
date: 2021-06-28 22:24:33
tags: [Project, Thoughts]
---

# Motivation
I played Arknights on Bilibili Server(Android only) with Android emulator, tries to clear some daily task with my iOS device.

# Attempts
- Approch 1: UI less arknights: need to capture and analyze some packages. I searched on github, all auto scripts are based on Android Emulator. 
- Approch 2: have an android emulator running on remote server, and control it with those auto scripts (CV based). However, it seems rented cloud VMs does not support nested virtualization (android emulator is another vm)
- Approch 3 (Current approch): Run emulator on my own windows machine, connect both windows machine and mobile phone (or browser if provide a web based console) to the server. Drawback: access speed would be slow, since need to communicate with both web client and windows machine. Need to keep my own PC running at home while access it. Need authentication to avoid Man-in-the-middle attack. Tried to find a way directly connect two machines behind NAT (NAT Traversal)

# Design - PC side
## Connect Emulator with adb
Download android sdk platform tool (adb included), add to PATH  

default adb server running on `127.0.0.1:5037`

Mumu emulator
```
adb connect 127.0.0.1:7555
adb shell
```

