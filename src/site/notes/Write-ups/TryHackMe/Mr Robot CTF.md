---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/mr-robot-ctf/","tags":["CTF","write-up","linux","easy","DirtyCow"]}
---

---
> [!INFO] Info about Mr Robot CFT
>  Can you root this Mr. Robot styled machine? This is a virtual machine meant for beginners/intermediate users. There are 3 hidden keys located on the machine, can you find them?
>  Credit to [Leon Johnson](https://twitter.com/@sho_luv) for creating this machine. **This machine is used here with the explicit permission of the creator <3**

> [!FAQ]- Hints
> No Hints.

---
# Active reconnaisance

## Enum ports and services
```shell
sudo nmap -sV -Pn -A -v 10.10.24.229
```

```shell
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-server-header: Apache
443/tcp open   ssl/http Apache httpd
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-title: Site doesn't have a title (text/html).
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=www.example.com
| Issuer: commonName=www.example.com
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2015-09-16T10:45:03
| Not valid after:  2025-09-13T10:45:03
| MD5:   3c163b1987c342ad6634c1c9d0aafb97
|_SHA-1: ef0c5fa5931a09a5687ca2c280c4c79207cef71b
|_http-server-header: Apache
```

---
# Vuln analisis
## Port 80
### Fuzzing

http://10.10.24.229/robots.txt
User-agent: *
fsocity.dic
`key-1-of-3.txt`
http://10.10.24.229/key-1-of-3.txt
> [!check]- Flag1
> 073403c8a58a1f80d943455fb30724b9

---
# Exploitation
http://10.10.24.229/fsocity.dic
```shell
cat fsocity.dic | sort | uniq -u
```

```
ER28-0652
abcdefghijklmno
abcdEfghijklmnop
abcdefghijklmnopq
ABCDEFGHIJKLMNOPQRSTUVWXYZ
c3fcd3d76192e4007dfb496cca67e13b
abcdefghijklmnopqrstuvwxyz
iamalearn
imhack
psychedelic
uHack
```
http://10.10.24.229/login
http://10.10.24.229/wp-login.php
>[!todo] Creentials
Wordpress page
User: Elliot
Passwd: ER28-0652

## Wordpress  4.3.1
Usernames: 
>[!todo] Credetials
mich05654
Elliot

## Get access
Upload a php reverse shell in wp admin console plugin, shell.php -> shell.zip
upload, install and activate the plugin
get a bash

---
# Privilege Escalation
## Dehash the file with john
`/home/robot/password.raw-md5`
`robot:c3fcd3d76192e4007dfb496cca67e13b`
>[!todo] Credentials
>robot:abcdefghijklmnopqrstuvwxyz

Get acces as a robot
```shell
su robot
abcdefghijklmnopqrstuvwxyz
```
second flag got it
> [!check]- Flag2
> /home/robot/key-2-of-3.txt
> 822c73956184f694993bede3eb39f959

## DirtyCow
Using linpeas we see [[Hacking Ético y Pentesting/DirtyCow\|DirtyCow]] vuln

It works ant we get the flag3

> [!check]- Flag3
> /root/key-3-of-3.txt
> 04787ddef27c3dee1ee161b21670b4e4

---

