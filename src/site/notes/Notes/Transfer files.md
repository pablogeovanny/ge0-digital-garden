---
{"dg-publish":true,"permalink":"/notes/transfer-files/"}
---

# To linux
## Python 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Transfer files
Using **Python**, in the folder that contain the file to send **on the source machine.** E.g. `file.txt` #flashcard
```python
python -m http.server 4545
```
<!--ID: 1728611164654-->

On the destination machine
```shell
wget http://IP_SOURCE_MACHINE:4545/file.txt
```

</div></div>

## Netcat 
<div class="transclusion internal-embed is-loaded"><a class="markdown-embed-link" href="/notes/netcat/#transfer-files" aria-label="Open link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="svg-icon lucide-link"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></a><div class="markdown-embed">



# Transfer files
1. On the destination machine
```shell
nc -lnvp 1234 > file.txt
```
2. On the source machine
```shell
nc -nv IP_destination 1234 < file.txt
```


</div></div>

## SSH - SCP 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- **S**ecure **C**opy **P**rotocol
- **Transferring Files** between two computers using the **[[Notes/SSH\|SSH]]** protocol 
- Provide both authentication and encryption.
- [[MITM\|MITM]]

Working on a model of SOURCE and DESTINATION, SCP allows you to:
- Copy files & directories from your current system to a remote system
- Copy files & directories from a remote system to your current system

## Send a file
Send file1.txt from my machine to the target machine with the name file2.txt
```shell
scp file1.txt <target_username>@<target_IP>:/home/ubuntu/file2.txt
```
## Download a file
Get the documents.txt from the target machine to my machine. (To my current directory `.`)
```shell
scp <target_username>@<target_IP>:/home/ubuntu/documents.txt .
```
Change the name to notes.txt
```shell
scp <target_username>@<target_IP>:/home/ubuntu/documents.txt notes.txt
```
Examples to get all files from a folder
```shell
scp <target_username>@<target_IP>:/home/ubuntu/* .
```
```shell
scp <target_username>@<target_IP>:/home/ubuntu/* ~
```




</div></div>

# To windows
## Certutil 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Transfer files to windows from a [[HTTP\|HTTP]] server
General use
```powershell
certutil.exe -urlcache -f http://IP:PORT//file.exe file.exe
```

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- [[SFTP\|SFTP]] and [[FTP\|FTP]] client for **Windows**
- **Transfer files** between a local computer and remote servers 
- Use [[FTP\|FTP]], [[FTPS\|FTPS]], [[SCP\|SCP]], [[SFTP\|SFTP]], [[WebDAV\|WebDAV]] or S3 file transfer protocols.
- https://winscp.net/eng/index.php

</div></div>

# [[Metasploit\|Metasploit]]