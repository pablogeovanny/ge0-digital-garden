---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/lian-yu/","tags":["CTF","write-up","Steganography","sudo-l"]}
---


![Pasted image 20250110105432.png|300](/img/user/attachments/Pasted%20image%2020250110105432.png)

---

> [!INFO] Info about Lian_Yu
>  A beginner level security challenge
>  
>  Welcome to Lian_YU, this Arrowverse themed beginner CTF box! Capture the flags and have fun.

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
PORT    STATE SERVICE REASON
21/tcp  open  ftp     syn-ack ttl 61
22/tcp  open  ssh     syn-ack ttl 61
80/tcp  open  http    syn-ack ttl 61
111/tcp open  rpcbind syn-ack ttl 61
```

---
# Enumeration
Perform a deep scan with common scripts only on ports we are interested in.
```shell
sudo nmap TARGET_IP -sCV -p 21,22,80,111 -oN nmap_enum
```
## OS
Linux, Debian
## Port 21 - FTP
tcp  open  ftp     **vsftpd 3.0.2**
## Port 22 - SSH
tcp  open  ssh     **OpenSSH 6.7p1** Debian 5+deb8u8 (protocol 2.0)
## Port 111 - RPC
tcp open  **rpcbind 2-4** (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          34556/udp6  status
|   100024  1          37021/tcp6  status
|   100024  1          58975/tcp   status
|_  100024  1          60900/udp   status
## Port 80 - Apache
tcp  open  http    Apache httpd
|http-server-header: Apache
|http-title: Purgatory
![Pasted image 20250110111117.png](/img/user/attachments/Pasted%20image%2020250110111117.png)
### Fuzz
```shell
ffuf -c -t 100 -u http://<TARGET>/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -mc all -fc 404 -e .php,.html,.txt
```
I found the subdir island
![Pasted image 20250110112220.png](/img/user/attachments/Pasted%20image%2020250110112220.png)
### Island
![Pasted image 20250110112255.png](/img/user/attachments/Pasted%20image%2020250110112255.png)
Important things:
![Pasted image 20250110112729.png](/img/user/attachments/Pasted%20image%2020250110112729.png)

> [!important]- Important
> vigilante
> go!go!go!

Fuzzing again
```shell
ffuf -c -t 100 -u http://10.10.233.165/island/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -fc 404
```

> [!check] What is the Web Directory you found?
> ![Pasted image 20250110114230.png](/img/user/attachments/Pasted%20image%2020250110114230.png)
#### 2100
![Pasted image 20250110114603.png|500](/img/user/attachments/Pasted%20image%2020250110114603.png)

> [!hint] Hint
> ![Pasted image 20250110115525.png](/img/user/attachments/Pasted%20image%2020250110115525.png)

I'll try fuzzing with the extension *.ticket*
```shell
ffuf -c -t 100 -u http://10.10.233.165/island/2100/FUZZ.ticket -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -fc 404
```

> [!check] What is the file name you found?
> ![Pasted image 20250110115724.png](/img/user/attachments/Pasted%20image%2020250110115724.png)

Go to the file
![Pasted image 20250110120018.png](/img/user/attachments/Pasted%20image%2020250110120018.png)
We get a code.
Decode with *cyberchef*
> [!check] what is the FTP Password?
> ![Pasted image 20250110122801.png](/img/user/attachments/Pasted%20image%2020250110122801.png)

It's a password

---
# Exploitation
## FTP
Login with the credentials and the username *vigilante*
![Pasted image 20250110123046.png](/img/user/attachments/Pasted%20image%2020250110123046.png)
Download the files with the command *get*

Furthermore, we can navigate through the system folders, for example with `cd ..` to get another username
![Pasted image 20250110154535.png](/img/user/attachments/Pasted%20image%2020250110154535.png)
## Steganography
### aa
The image aa.jpg
![Pasted image 20250110123558.png](/img/user/attachments/Pasted%20image%2020250110123558.png)
We have the password

Extract it using the password from above
```shell
steghide extract -sf aa.jpg
```
![Pasted image 20250110123736.png](/img/user/attachments/Pasted%20image%2020250110123736.png)

Extract the *zip*
![Pasted image 20250110123808.png](/img/user/attachments/Pasted%20image%2020250110123808.png)

Passwd.txt
![Pasted image 20250110124034.png](/img/user/attachments/Pasted%20image%2020250110124034.png)

*shado* file:
> [!check] What is the file name with SSH password?
> ![Pasted image 20250110134702.png|200](/img/user/attachments/Pasted%20image%2020250110134702.png)
## SSH
Login through SSH
With the other username
![Pasted image 20250110154649.png](/img/user/attachments/Pasted%20image%2020250110154649.png)

> [!check] User flag
> ![Pasted image 20250110154822.png](/img/user/attachments/Pasted%20image%2020250110154822.png)

---
# Privilege escalation
## sudo -l
Check sudo permission
![Pasted image 20250110155114.png](/img/user/attachments/Pasted%20image%2020250110155114.png)
Search a way to exploit it on *gtfobins*
```
sudo pkexec /bin/bash
```
![Pasted image 20250110155241.png](/img/user/attachments/Pasted%20image%2020250110155241.png)
> [!check] Root flag
> ![Pasted image 20250110155331.png](/img/user/attachments/Pasted%20image%2020250110155331.png)

---
