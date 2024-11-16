---
{"dg-publish":true,"permalink":"/notes/ssh/"}
---

- **S**ecure **S**hell
- Default port **22**
- Cryptographic remote access **protocol**
- We will need to confirm the fingerprint of the SSH server’s public key to avoid [[MITM attack\|MITM attack]]
# Username and password Authentication
```shell
ssh bandit0@bandit.labs.overthewire.org -p 2220
ssh bandit0@bandit.labs.overthewire.org -p 2220 -oHostKeyAlgorithms=+ssh-rsa
```

```shell
sshpass -p 'password' ssh bandit0@bandit.labs.overthewire.org -p 2220
```
# RSA keys Authentication
- Data **encrypted** with the **private key** can be **decrypted** with the **public key,** and vice versa.
- tends to be **slower** and uses **larger keys**
## Enable service daemon
```sh
sudo systemctl start sshd
```
## Create keys
Create pair of keys RSA keys in `/home/USER/.ssh
```shell
ssh-keygen
```
`id_rsa` (private) (`400` permissions required to remote connection)
`id_rsa.pub` (public)
## Connect from C2 to C1 without password
### Method 1
 The **public key** (`id_rsa.pub`) of **computer 2** has to be in the file `authorized_keys` in the **computer 1**
 
 1. On the **computer 2**
 Copy the content of the file `/home/USER/.ssh/id_rsa.pub` 
```sh
cat /home/USER/.ssh/id_rsa.pub
```
![Pasted image 20241001192909.png](/img/user/attachments/Pasted%20image%2020241001192909.png)
Copy to the clipboard

2. On the **computer 1**
Using `echo` paste the code and add or replace the `authorized_keys`
```shell
echo "ssh-rsa AAAA......gv7v......y2w/oJ0= kali@kali" >> authorized_keys
```
E.g. This is the new `authorized_keys`of the **computer 1**
![Pasted image 20241002070248.png](/img/user/attachments/Pasted%20image%2020241002070248.png)

3. On the **computer 2**
All is ready, now to connect without password execute:
```shell
ssh USER_OF_COMPUTER_1@IP_COF_COMPUTER_1
```
### Method 2
**Automated** version of the **method 1** but **we need** to introduce the **password** of the **computer 1** **at least once**.
1. On the **computer 2**
```shell
ssh-copy-id -i ~/.ssh/id_rsa.pub COMPUTER_1_USERNAME@COMPUTER_1_IP
```
After this our `id_rsa.pub` will copy on `authorized_keys` of the **computer 1**.
### Method 3
1. Set the **public key of comp1** like "authorized_keys" on its machine
   To **let to** any **connect to comp1** if the **computer2** has the private key of comp1.
```shell
cp id_rsa.pub authorized_keys
```
2. Copy the private key (`id_rsa`) from C1 to C2
3. From C2 connect using that private key file of C1 (`id_rsa`) (the permission should be `600`)
```shell
ssh -i id_rsa user@ipaddres
ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.10.250.21
```
# Port forwarding
`80` port from a victim machine which we don't have access will be available in our machine on `127.0.0.1:33`
```shell
ssh user@"VICTIM_IP" -L 80:127.0.0.1:33
```
# Math
- The key variables that you need to know about for RSA in CTFs are p, q, m, n, e, d, and c.
- “p” and “q” are large prime numbers, “n” is the product of p and q.
- The public key is n and e, the private key is n and d.
- “m” is used to represent the message (in plaintext) and “c” represents the ciphertext (encrypted text).
- https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/

# Tools RSA CTFs
https://github.com/Ganapati/RsaCtfTool
https://github.com/ius/rsatool
# Errors
- If you get an error saying `Unable to negotiate with <IP> port 22: no matching how to key type found. Their offer: ssh-rsa, ssh-dss` 
- this is because OpenSSH have deprecated ssh-rsa. 
- Add `-oHostKeyAlgorithms=+ssh-rsa` to your command to connect.
# Enumeration
Get version and search in [launchpad](https://launchpad.net/ubuntu).
```sh
sudo nmap -sCV -p22 127.0.0.1
```
PORT   STATE SERVICE VERSION
`22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)`
https://launchpad.net/ubuntu
OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## [[Notes/SSH\|SSH]] Enum
```shell
auxiliary/scanner/ssh/ssh_version
auxiliary/scanner/ssh/ssh_login # Brute force
```

</div></div>

# Exploitation
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

# John The Ripper

</div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py
```sh
wget https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py
```
Note that if you don't have ssh2john installed, you can use ssh2john.py, which is located in the /opt/john/ssh2john.py. If you're doing this, replace the `ssh2john` command with `python3 /opt/ssh2john.py` or on Kali, `python /usr/share/john/ssh2john.py`.
```sh
ssh2john [id_rsa private key file] > [output file]
```

ssh2john - Invokes the ssh2john tool  

`[id_rsa private key file]` - The path to the id_rsa file you wish to get the hash of

`>` - This is the output director, we're using this to send the output from this file to the...  

`[output file]` - This is the file that will store the output from

**Example Usage**
ssh2john id_rsa > id_rsa_hash.txt

**Cracking**

``` bash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
```



</div></div>



</div></div>

## Exploit `libssh`
- `libssh` V.0.6.0 - 0.8-0 is vulnerable to an authentication bypass vulnerability in the `libssh` server code that can be exploited to execute commands on the target server.

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## [[Notes/SSH\|SSH]] Exploitation
```shell
use auxiliary/scanner/ssh/libssh_auth_bypass
set SPAWN_PTY true
run
```

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

# Hardening SSH

</div>


- In the admin shell, go to the `/etc/ssh/sshd_config` file and edit it using your favourite text editor (remember to use sudo). 
- Find the line that says `#PasswordAuthentication yes` and change it to `PasswordAuthentication no` (remove the # sign and change yes to no).

- Next, find the line that says `Include /etc/ssh/sshd_config.d/*.conf` and change it to `#Include /etc/ssh/sshd_config.d/*.conf` (add a # sign at the beginning). 
- Save the file, then enter the command `sudo systemctl restart ssh`.

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

# SCP

</div>


- Secure Copy Protocol
MITM**Transferring Files From Your Host**
Secure copy, or SCP, is just that -- a means of securely copying files. Unlike the regular cp command, this command allows you to transfer files between two computers using the SSH protocol to provide both authentication and encryption.

Working on a model of SOURCE and DESTINATION, SCP allows you to:

- Copy files & directories from your current system to a remote system
- Copy files & directories from a remote system to your current system

Send important.txt to other machine with the name transferred.txt
```shell
scp important.txt ubuntu@192.168.1.30:/home/ubuntu/transferred.txt
```

Get the documents.txt to my pc with the name notes.txt
```shell
scp ubuntu@192.168.1.30:/home/ubuntu/documents.txt notes.txt
```
```shell
scp skyfuck@10.10.120.0:/home/skyfuck/* .
```
```shell
scp skyfuck@10.10.120.0:/home/skyfuck/* ~
```


</div></div>



