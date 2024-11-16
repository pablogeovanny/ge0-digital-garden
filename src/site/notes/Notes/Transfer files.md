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

# To windows
## Certutil 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Transfer files to windows from a [[HTTP\|HTTP]] server
General use
```powershell
certutil.exe -urlcache -f http://IP:PORT//file.exe file.exe
```

</div></div>

# [[Metasploit\|Metasploit]]