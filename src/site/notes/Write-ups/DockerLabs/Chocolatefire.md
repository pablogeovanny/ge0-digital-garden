---
{"dg-publish":true,"permalink":"/write-ups/docker-labs/chocolatefire/","tags":["CTF","write-up"]}
---


![Pasted image 20241214125158.png|300](/img/user/attachments/Pasted%20image%2020241214125158.png)

---

> [!INFO] Info about Chocolatefire
>  DIfficulty: Medium

> [!FAQ]- Hints
> No Hints.

---
# Active reconnaissance
## Port scan
Perform a quick general scan on all ports.
```shell
sudo nmap TARGET_IP -n -p- -sS -Pn -vvv --open --min-rate 5000 -oN nmap_scan
```

```c
PORT     STATE SERVICE     REASON
22/tcp   open  ssh         syn-ack ttl 64
5222/tcp open  xmpp-client syn-ack ttl 64
5223/tcp open  hpvirtgrp   syn-ack ttl 64
5262/tcp open  unknown     syn-ack ttl 64
5263/tcp open  unknown     syn-ack ttl 64
5269/tcp open  xmpp-server syn-ack ttl 64
5270/tcp open  xmp         syn-ack ttl 64
5275/tcp open  unknown     syn-ack ttl 64
5276/tcp open  unknown     syn-ack ttl 64
7070/tcp open  realserver  syn-ack ttl 64
7777/tcp open  cbt         syn-ack ttl 64
9090/tcp open  zeus-admin  syn-ack ttl 64
```

---
# Enumeration
Perform a deep scan with common scripts only on ports we are interested in.
```shell
sudo nmap 172.17.0.2 -sCV -p 22,5222,5223,5262,5263,5269,5270,5275,5276,7070,7777,9090 -oN nmap_enum
```
## OS
Linux, Debian
## Port 22 - SSH
tcp   open  ssh            **OpenSSH 8.4p1** Debian 5+deb11u3 (protocol 2.0

## Port 5222 - jabber
tcp open  jabber         Ignite Realtime Openfire Jabber server 3.10.0 or later
xmpp: version: 1.0
stream_id: 9e02evg5la

## Port 5262 - jabber
tcp open  jabber         Ignite Realtime Openfire Jabber server 3.10.0 or later
xmpp: version: 1.0
stream_id: 1w68w32xs4

## Port 5275 - jabber
tcp open  jabber
stream_id: 33idbf0hu2

## Port 5269 - xmpp
tcp open  xmpp           Wildfire XMPP Client

## Port 5270 - xmp
tcp open  xmp?

## Port 5223 - ssl
tcp open  ssl/hpvirtgrp
## Port 5263 - ssl
tcp open  ssl/unknown

## Port 5276 - ssl
tcp open  ssl/unknown

## Port 7777 - socks5
tcp open  socks5         (No authentication; connection not allowed by ruleset)
| socks-auth-info:
|_  No authentication

## Port 7070 - realserver
tcp open  realserver?
fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP:
|     HTTP/1.1 400 Illegal character CNTL=0x0

## Port 9090 - zeus-admin
**Openfire 4.7.4**
![Pasted image 20241214150100.png](/img/user/attachments/Pasted%20image%2020241214150100.png)

---
# Exploitation
## Default or weak credentials
I test some basic credentials and admin:admin works
![Pasted image 20241215084951.png](/img/user/attachments/Pasted%20image%2020241215084951.png)
From the research, I know that *openfire* can interact with the system though a java plugin here:
https://github.com/miko550/CVE-2023-32315?tab=readme-ov-file
In this case also is exploiting *openfire* to bypass the authentication phase, however this is not necessary. I am only interested on the plugin. Download the plugin *openfire-management-tool-plugin.jar* .
Upload the plugin
![Pasted image 20241215085733.png](/img/user/attachments/Pasted%20image%2020241215085733.png)
Now go to the plugin.
![Pasted image 20241215085838.png](/img/user/attachments/Pasted%20image%2020241215085838.png)
And access with the password *123*
![Pasted image 20241215085924.png](/img/user/attachments/Pasted%20image%2020241215085924.png)
We are on the *management tool* and we can perform some actions. Like execute commands, navigate through files and upload files.
![Pasted image 20241215090203.png](/img/user/attachments/Pasted%20image%2020241215090203.png)
I try to get a shell executing command on the section *system command*  but it has restrictions.
The other way to get a reverse shell
1. Go to *file system* 
2. Click on *Create a new file*
   ![Pasted image 20241215090546.png](/img/user/attachments/Pasted%20image%2020241215090546.png)
3. Write the name file and ok
   ![Pasted image 20241215090752.png](/img/user/attachments/Pasted%20image%2020241215090752.png)
4. Write the bash reverse shell and click on save
   ![Pasted image 20241215090851.png|500](/img/user/attachments/Pasted%20image%2020241215090851.png)
5. Start the listener
```shell
rlwrap nc -lnvp 4747
```
7. Go to *system command* section and execute
   ![Pasted image 20241215091143.png](/img/user/attachments/Pasted%20image%2020241215091143.png)
We got the reverse shell, in this case *openfire* is running as the *root* user.
![Pasted image 20241215091243.png](/img/user/attachments/Pasted%20image%2020241215091243.png)
