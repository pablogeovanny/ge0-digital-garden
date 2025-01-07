---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/anthem/","tags":["CTF","write-up"]}
---


![d3387857fc40a19afd406e7034e0bfa0.gif|300](/img/user/attachments/d3387857fc40a19afd406e7034e0bfa0.gif)

---

> [!INFO] Info about Anthem
>  Exploit a Windows machine in this beginner level challenge.
>  
>  This task involves you, paying attention to details and finding the 'keys to the castle'.
>  This room is designed for beginners, however, everyone is welcomed to try it out!
>  
>  Enjoy the Anthem.

> [!FAQ]- Hints
> In this room, you don't need to brute force any login page. Just your preferred browser and Remote Desktop.

---
# Active reconnaissance
## Port scan
Perform a quick general scan on all ports.
```shell
sudo nmap TARGET_IP -n -p- -sS -Pn -vvv --open --min-rate 5000 -oN nmap_scan
```

```c
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 125
3389/tcp open  ms-wbt-server syn-ack ttl 125
```

> [!check]- What port is for the web server?
> 80

> [!check]- What port is for remote desktop service?
> 3389


---
# Enumeration
Perform a deep scan with common scripts only on ports we are interested in.
```shell
sudo nmap TARGET_IP -sCV -p 22,80 -oN nmap_enum
```
## OS
**Windows**; CPE: cpe:/o:microsoft:windows
## Port 80 - Umbraco
tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

|http-title: **Anthem.com** - Welcome to our blog
| http-robots.txt: 4 **disallowed entries**
|/bin/ /config/ /umbraco/ /umbraco_client/

> [!check]- What is the domain of the website?
> Anthem.com 


> [!check]- What is a possible password in one of the pages web crawlers check for?
> ![Pasted image 20250107121712.png](/img/user/attachments/Pasted%20image%2020250107121712.png)


![Pasted image 20250107114105.png](/img/user/attachments/Pasted%20image%2020250107114105.png)
### bin
Its empty
### config
The same main page
### umbraco_client
The same main page
### Umbraco
We have a login page
![Pasted image 20250107114248.png|500](/img/user/attachments/Pasted%20image%2020250107114248.png)

> [!check]- What CMS is the website using?
> Umbraco

> [!check] What's the name of the Administrator
> It's the author of the poem
> ![Pasted image 20250107150044.png](/img/user/attachments/Pasted%20image%2020250107150044.png)

> [!check]- Can we find find the email address of the administrator?
> According to the pattern of Jane Doe and its email *jd@anthem.com*
> The email will be sg@anthem.com
## Port 3389 - RDP
tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: **WIN-LU09299160F**
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2025-01-07T14:18:27+00:00
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Not valid before: 2025-01-06T14:15:34
|Not valid after:  2025-07-08T14:15:34
ssl-date: 2025-01-07T14:19:27+00:00; +1s from scanner timeH

---
# Exploitation
## Port 80 - Umbraco
### Dashboard
After login with credentials
We have:
![Pasted image 20250107150414.png](/img/user/attachments/Pasted%20image%2020250107150414.png)

> [!check] What is flag 1?
> ![Pasted image 20250107153528.png](/img/user/attachments/Pasted%20image%2020250107153528.png)

> [!check] What is flag 2?
> ![Pasted image 20250107153005.png](/img/user/attachments/Pasted%20image%2020250107153005.png)

> [!check] What is flag 3?
> ![Pasted image 20250107153143.png](/img/user/attachments/Pasted%20image%2020250107153143.png)

> [!check] What is flag 4?
> ![Pasted image 20250107153357.png](/img/user/attachments/Pasted%20image%2020250107153357.png)
## Port 3389 - RDP

> [!check]- Let's figure out the username and password to log in to the box.(The box is not on a domain)
> ```shell
> xfreerdp /u:sg /p:UmbracoIsTheBest! /v:10.10.233.117 /shell:cmd.exe
> ```

> [!check] Gain initial access to the machine, what is the contents of user.txt?
> ![Pasted image 20250107160402.png](/img/user/attachments/Pasted%20image%2020250107160402.png)

> [!check] Can we spot the admin password?
> In the hidden folder
> ![Pasted image 20250107165559.png](/img/user/attachments/Pasted%20image%2020250107165559.png)
> Click on setting of restore file and add our user to the permissions file.
> ![Pasted image 20250107165939.png](/img/user/attachments/Pasted%20image%2020250107165939.png)
> And open the file:
> ![Pasted image 20250107170052.png](/img/user/attachments/Pasted%20image%2020250107170052.png)

---
# Privilege escalation
Login to the administrator account
```shell
xfreerdp /u:Administrator /p:ChangeMeBaby1MoreTime /v:10.10.233.117
```

> [!check] Escalate your privileges to root, what is the contents of root.txt?
> ![Pasted image 20250107170456.png](/img/user/attachments/Pasted%20image%2020250107170456.png)

---
