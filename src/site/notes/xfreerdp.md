---
{"dg-publish":true,"permalink":"/xfreerdp/","hide":true}
---


Login
```shell
xfreerdp /u:<username> /p:<password> /v:<IP>
xfreerdp [/d:domain] /u:<username> /p:<password> /v:<IP>:<PORT>
```
Login with domain and username
```sh
xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:10.10.166.150 /u:Administrator /p:'TryH4ckM3!'
```
# [[Pass-the-Hash\|Pass-the-Hash]]
Connect with the hash
```shell
xfreerdp [/d:domain] /u:<username> /pth:<hash> /v:<IP> 
```
