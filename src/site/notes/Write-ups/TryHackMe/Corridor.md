---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/corridor/","tags":["CTF","write-up"]}
---


![Pasted image 20241202160801.png|300](/img/user/attachments/Pasted%20image%2020241202160801.png)

---
> [!INFO] Info about Corridor
>  Can you escape the Corridor?

> [!FAQ]- Hints
> You have found yourself in a strange corridor. Can you find your way back to where you came?
> 
> In this challenge, you will explore potential **IDOR** vulnerabilities. Examine the URL endpoints you access as you navigate the website and note the **hexadecimal** values you find (they look an awful lot like a *hash*, don't they?). This could help you uncover website locations you were not expected to access.
> 
> Where do those doors take you? The numbers and letters seem to follow a pattern...

---
# Active reconnaissance
## Port scan
Executing a fast general scan to all ports.
```shell
sudo nmap TARGET_IP -n -p- -sS -Pn -vvv --open --min-rate 5000 -oN nmap_scan
```

```c
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 60
```

---
# Enumeration
Executing a deep scan with common scripts only to ports that we are interested.
```shell
sudo nmap TARGET_IP -sCV -p 80 -oN nmap_enum
```
## OS
## Port 80 - Werkzeug
tcp http **Werkzeug** httpd **2.0.3** (Python 3.10.2)
Add the IP to  `/etc/hosts`
```shell
sudo echo "10.10.197.203 corridor.thm" | sudo tee -a /etc/hosts
```
![Pasted image 20241202162327.png|400](/img/user/attachments/Pasted%20image%2020241202162327.png)
Each door it's a "coded" url, I'm usign burpsuite
![Pasted image 20241202165410.png](/img/user/attachments/Pasted%20image%2020241202165410.png)
Except for the different url, all pages are cloned

---
# Exploitation
## Understanding the codes
Using `hashid` it's probably a md5
Save all hashes in a file named `hashes`
![Pasted image 20241202173128.png|300](/img/user/attachments/Pasted%20image%2020241202173128.png)
Try to crack with MD5 and works.
![Pasted image 20241202173034.png|500](/img/user/attachments/Pasted%20image%2020241202173034.png)
Create a file of hashes from the `big.txt` to try fuzzing
```shell
cat -p /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt | while read line; do echo -n "$line" | md5sum; done | awk '{print $1}' > big_md5
```
## Fuzz
Fuzzing using the file generated `big_md5`
```shell
ffuf -c -t 100 -u http://corridor.thm/FUZZ -w big_md5 -mc all -fc 404
```
I found a hash that is not part of the 13 from the site
![Pasted image 20241202205713.png|600](/img/user/attachments/Pasted%20image%2020241202205713.png)

> [!check] User flag
> Access with burpsuite or curl
> ![Pasted image 20241202210542.png](/img/user/attachments/Pasted%20image%2020241202210542.png)

---