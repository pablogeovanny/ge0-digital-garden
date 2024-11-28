---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/take-over/","tags":["CTF","write-up","#fuzzing"]}
---


![Pasted image 20241128092958.png|200](/img/user/attachments/Pasted%20image%2020241128092958.png)

---

> [!INFO] Info about TakeOver
>  This challenge revolves around subdomain enumeration.
>  
>  Hello there,  
>  
>  I am the CEO and one of the co-founders of futurevera.thm. In Futurevera, we believe that the future is in space. We do a lot of space research and write blogs about it. We used to help students with space questions, but we are rebuilding our support.  
>  
>  Recently blackhat hackers approached us saying they could takeover and are asking us for a big ransom. Please help us to find what they can takeover.  
>  
>  Our website is located at [https://futurevera.thm](https://futurevera.thm)

> [!FAQ]- Hints
> Hint: Don't forget to add the 10.10.70.121 in /etc/hosts for futurevera.thm ; ).

---
# Active reconnaissance
## Host discovery
## Port scan
Executing a fast general scan to all ports.
```shell
sudo nmap TARGET_IP -n -p- -sS -Pn -vvv --open --min-rate 5000 -oN nmap_scan
```

```c
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 61
80/tcp  open  http    syn-ack ttl 61
443/tcp open  https   syn-ack ttl 61
```

---
# Enumeration
Executing a deep scan with common scripts only to ports that we are interested.
```shell
sudo nmap TARGET_IP -sCV -p 22,80 -oN nmap_enum
```
## OS
Linux,  Ubuntu
## Port 22 - SSH
22/tcp  open  ssh      **OpenSSH 8.2p1** Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
## Port 80 - Apache
80/tcp  open  http     **Apache** httpd **2.4.41** ((Ubuntu))
http-title: Did not follow redirect to https://futurevera.thm/
## Port 443 - Apache
http-server-header: **Apache/2.4.41** (Ubuntu)
ssl-date: TLS randomness does not represent time
ssl-cert: Subject: commonName=futurevera.thm/organizationName=Futurevera/stateOrProvinceName=Oregon/countryName=US
 Not valid before: 2022-03-13T10:05:19
Not valid after:  2023-03-13T10:05:19
http-title: FutureVera
 tls-alpn:
  http/1.1
  ![Pasted image 20241128094222.png](/img/user/attachments/Pasted%20image%2020241128094222.png)

---
# Exploitation
## Port 443 - Apache
### Subdomain enumeration
Based on the route of the machine, I'll proceed with the subdomain enumeration

Using wfuzz
```shell
wfuzz -c -t 50 --hw 329 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.futurevera.thm" https://futurevera.thm/
```

I found two subdomains
![Pasted image 20241128121932.png](/img/user/attachments/Pasted%20image%2020241128121932.png)

Now, add them to the `/etc/hosts` file
```shell
sudo echo "10.10.70.121 blog.futurevera.thm support.futurevera.thm" | sudo tee -a /etc/hosts
```
### Blog
![Pasted image 20241128171634.png](/img/user/attachments/Pasted%20image%2020241128171634.png)
### Support
![Pasted image 20241128171650.png|500](/img/user/attachments/Pasted%20image%2020241128171650.png)
Checking the certificate
I'll show the steps for firefox
![Pasted image 20241128184242.png](/img/user/attachments/Pasted%20image%2020241128184242.png)
Then  view certificate
![Pasted image 20241128184327.png](/img/user/attachments/Pasted%20image%2020241128184327.png)
We can show a dns subdomain
![Pasted image 20241128184439.png](/img/user/attachments/Pasted%20image%2020241128184439.png)
Add the  new sub-subdomain to `/etc/hosts`
```shell
sudo echo "10.10.17.71 secre******52.support.futurevera.thm" | sudo tee -a /etc/hosts
```
Go to the browser and go to the new page.
The flag will be shown.

> [!check] flag
> ![Pasted image 20241128184931.png](/img/user/attachments/Pasted%20image%2020241128184931.png)