---
{"dg-publish":true,"permalink":"/notes/nmap/"}
---

- Net inventory, admin service updates, check host and service activity.
- Default tcp ports. 1000 common ports(randomly).
- TCP [[TCP SYN\|TCP SYN]] are the default scans used by Nmap _if run with sudo permissions_.
- If run **without** sudo permissions, Nmap defaults to the **TCP Connect** [[3-way handshake\|3-way handshake]] scan we saw in the previous task.

| Option                                                                               | Description                                                                |
| ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| `--script=vuln`                                                                      | activate all scripts in the "vuln" category                                |
| `--reason`                                                                           | explains how Nmap made its conclusion                                      |
| `-v`                                                                                 | Verbose                                                                    |
| `-vv`<br>`-vvv`                                                                      | More verbose                                                               |
| `-d`                                                                                 | debugging                                                                  |
| `-dd`                                                                                | more details for debugging                                                 |
| `-A`                                                                                 | Enable OS detection<br>version detection<br>script scanning and traceroute |
| `-O`                                                                                 | Try to get OS                                                              |
| `-Pn`                                                                                | Disable host discovery and scan for open ports                             |

# Host discovery

[[Notes/Nmap\|Nmap]] Host discovery, ping scan without port scan. #flashcard 
```shell
nmap -sn 192.168.1.0/24
```
<!--ID: 1728898860808-->

| Opction                                                                              | Description                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nmap -sn 192.168.1.0/24`<br>`nmap -sn 192.168.0.1-254`<br>`nmap -sn 192.168.0.0/24` | Host discovery only<br>**Ping Scan** - **disable port scan**<br>                                                                                                                                                                                                                                              |
| `nmap -e eth0`                                                                       | Specify interface                                                                                                                                                                                                                                                                                             |
| `nmap -PR -sn TARGETS`<br>`nmap -PR -sn MACHINE_IP/24`                               | Only to perform an **ARP scan** without port-scanning                                                                                                                                                                                                                                                         |
| `nmap -PE -sn`                                                                       | `PE` = **ICMP echo** scan<br>Barrido **Ping ICMP**, Ping Scan - disable port scan<br>Scan any ports -- forcing it to rely primarily on ICMP echo packets<br>Also cause nmap to send a TCP SYN packet to port 443,<br>as well as a TCP ACK (or TCP SYN if not run as root)<br>packet to port 80 of the target. |
| `nmap -PP -sn`                                                                       | **ICMP timestamp** scan - request (ICMP Type 13)                                                                                                                                                                                                                                                              |
| `nmap -PM -sn`                                                                       | **ICMP Address mask** scan - queries (ICMP Type 17) <br>and checks address mask reply (ICMP Type 18).                                                                                                                                                                                                         |
| `nmap -PS -sn MACHINE_IP/24`<br>`nmap -PS21-25`                                      | [[TCP SYN\|TCP SYN]] Ping scan (**root** required)                                                                                                                                                                                                                                                                     |
| `nmap -PA -sn MACHINE_IP/24`<br>`nmap -PA21-25`                                      | TCP [[ACK ping\|ACK ping]] scan (root required)                                                                                                                                                                                                                                                                         |
| `-PU -sn MACHINE_IP/24`                                                              | [[UDP ping\|UDP ping]] scan                                                                                                                                                                                                                                                                                             |
| `-n`                                                                                 | No DNS lookup - online hosts (more fast)                                                                                                                                                                                                                                                                      |
| `-R`                                                                                 | reverse-DNS lookup for all hosts even for offline hosts                                                                                                                                                                                                                                                       |
| `--dns-servers DNS_SERVER`                                                           | use a specific DNS server                                                                                                                                                                                                                                                                                     |
| `nmap 192.168.0.1`<br>`nmap host.com`                                                | Get live hosts, open ports, services, packet types, <br>firewalls, info of OS and versions.                                                                                                                                                                                                                   |
| `nmap -iL list_of_hosts.txt`                                                         | Provide a file as input for your list of targets                                                                                                                                                                                                                                                              |
| `nmap -sL TARGETS`                                                                   | List of the hosts that Nmap will scan without scanning them                                                                                                                                                                                                                                                   |

# Port scan
Nmap General Scan #flashcard 
```shell
sudo nmap IP -n -p- -Pn -sS -vvv --open --min-rate 5000 -oG allPorts
```
<!--ID: 1728389001046-->

| Option                                     | Description                                                              |
| ------------------------------------------ | ------------------------------------------------------------------------ |
| `-sS`                                      | Silent,  [[TCP SYN\|TCP SYN]] scan, Stealthy, Fast                                |
| `-sT`                                      | [[TCP Connect Scans\|TCP Connect Scans]]  using [[3-way handshake\|3-way handshake]]                         |
| `-sU`                                      | [[UDP scan\|UDP scan]]                                                             |
| `nmap --open`                              | Just show open ports                                                     |
| `-r`                                       | Scan the ports in consecutive order                                      |
| `nmap 192.168.1.1/24`                      | Scan all devices and port, OPEN at the same time                         |
| `nmap 192.168.0.1 192.168.0.4 192.168.0.7` | Some IPs                                                                 |
| `nmap 192.168.0.1-34`                      | Range of IPs                                                             |
| `-T<0-5>`                                  | [[Nmap Speed levels\|Nmap Speed levels]]                                                    |
| `--min-rate 5000`                          | Set a min of packets per second before to skip the scan (recommend 5000) |
| `--min-parallelism=100`                    | At least 100 probes in parallel; (host discovery or open ports)          |
| `-F`                                       | Fast 100 common ports                                                    |
| `-p 80`<br>`-p80`                          | Specific port                                                            |
| `-top-ports 2000`                          | 2000 Most used ports                                                     |
| ` -p 1-77`<br>` -p1-77`                    | From 1 to 77                                                             |
| ` -p 22,80`                                | port 22 and 80                                                           |
| ` -p- IP`                                  | All 65535 ports                                                          |
# Advanced port scan (Firewall IDS evasion)

| Option                                                                             | Description                                                                                                                               |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **Against** [[Firewall#Stateless\|Firewall#Stateless]]                                                 | A stateless firewall will check if the incoming packet has the SYN flag set to detect a connection attempt.                               |
| `-f`                                                                               | Fragment IP data into 8 bytes                                                                                                             |
| `-ff`                                                                              | Fragment IP data into 16 bytes                                                                                                            |
| `--source-port PORT_NUM`                                                           | specify source port number                                                                                                                |
| `--data-length 21`                                                                 | append random data to reach given length (58 +21)                                                                                         |
| `--scan-delay <time>ms`                                                            | add a delay between packets sent                                                                                                          |
| `--badsum`                                                                         | generate in invalid checksum for packets                                                                                                  |
| `nmap --mtu 16`                                                                    | Change MTU (8 multiple)                                                                                                                   |
| `-sN MACHINE_IP`                                                                   | [[TCP Null Scan\|TCP Null Scan]] (TCP request is sent with **no flags set** at all, target host should respond with a RST if the port is closed)         |
| `-sF MACHINE_IP`                                                                   | [[TCP FIN Scan\|TCP FIN Scan]] (a request is sent with the **FIN** flag, expects a RST if the port is closed.)                                          |
| `-sX MACHINE_IP`                                                                   | [[TCP Xmas Scan\|TCP Xmas Scan]] (send a **malformed** TCP packet (FIN, PSH, and URG flags simultaneously) and expects a RST response for closed ports.) |
| **Map out the firewall rules.**<br>                                                | Could ACK and window scans are exposing the firewall rules, not the services.                                                             |
| `-sA MACHINE_IP`                                                                   | [[TCP ACK Scan\|TCP ACK Scan]]                                                                                                                          |
| `-sW MACHINE_IP`                                                                   | [[TCP Window Scan\|TCP Window Scan]]                                                                                                                       |
|                                                                                    |                                                                                                                                           |
| `-sM MACHINE_IP`                                                                   | [[TCP Maimon Scan\|TCP Maimon Scan]] (FIN and ACK bits are set.)                                                                                           |
| `--scanflags URGACKPSHRSTSYNFIN MACHINE_IP`                                        | Custom TCP Scan                                                                                                                           |
| `-S SPOOFED_IP MACHINE_IP`<br>` -e NET_INTERFACE -Pn -S SPOOFED_IP MACHINE_IP`<br> | [[Spoofed Source IP\|Spoofed Source IP]]                                                                                                                     |
| `--spoof-mac SPOOFED_MAC -Pn`<br>`--spoof-mac Dell -Pn`                            | [[Spoofed MAC Address\|Spoofed MAC Address]]                                                                                                                   |
| `nmap -D DECOY_IP,ME MACHINE_IP`<br>`nmap -D DECOY_IP,RND,ME MACHINE_IP`           | [[Decoy Scan\|Decoy Scan]] (ME=myIP, RND=randomIP)                                                                                                    |
| `sudo nmap -sI ZOMBIE_IP MACHINE_IP`                                               | [[Idle (Zombie) Scan\|Idle (Zombie) Scan]]                                                                                                                    |

# Post port scan

Nmap Focused scan #flashcard
```shell
sudo nmap IP -sCV -p 22,80 -oN targeted
```
<!--ID: 1728386777374-->

| Option                | Description                                                                                                   |
| --------------------- | ------------------------------------------------------------------------------------------------------------- |
| `-sV`                 | Deep scan, determine service/version info on open ports<br>force [[3-way handshake\|3-way handshake]]<br>don't work with `-sS` |
| `-sV --version-light` | try the most likely probes (2)                                                                                |
| `-sV --version-all`   | try all available probes (9)                                                                                  |
| `-sC`                 | Scan with the default Nmap scripts                                                                            |
| `-sCV`                | -sV + -sC                                                                                                     |
| `-O`                  | detect OS                                                                                                     |
| `--traceroute`        | run traceroute to target                                                                                      |
| `-A`                  | equivalent to `-sV -O -sC --traceroute`                                                                       |
| `-oN`                 | save output in normal format                                                                                  |
| `-oG`                 | save output in grepable format                                                                                |
| `-oX`                 | save output in XML format                                                                                     |
| `-oA`                 | save output in normal, XML and Grepable formats                                                               |
# NSE
- **N**map **S**cripting **E**ngine
- It's a Lua interpreter that allows Nmap to execute Nmap scripts written in Lua language.
- `/usr/share/nmap/scripts`
- `ftp-anon.nse` - to check anonymous ftp account
- `http-robots.txt.nse` to check relevant info about robots files

| Option                                                                                  | Description                                                              |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `locate .nse \| grep smb-*`<br>`locate .nse \| grep ftp-*`                              | Search specific scripts                                                  |
| `-sC` or `--script=default`                                                             | To execute main Scripts                                                  |
| `-sCV`                                                                                  | like -sV + scripts                                                       |
| `--script=<script-name>`<br>`--script=scrpt1,scrpt2`                                    | To run a specific script                                                 |
| `--script "ftp*"`                                                                       | Run all that start with `ftp`                                            |
| `--script`                                                                              | activate a script                                                        |
| `--script=vuln`<br>`--script vuln`                                                      | Run all "vuln" scripts category<br>`/usr/share/nmap/scripts` (Intrusive) |
|                                                                                         |                                                                          |
| `--script="vuln and safe" -sV`                                                          | Use the scripts in the "vuln and safe" category                          |
| `--script-args`                                                                         | Some scripts require arguments                                           |
| `--script=http-enum.nse`                                                                | Enum http service                                                        |
| `--script=http-shellshock --script-args "http-shellshock.uri=/URI_SCRIPT_CGI_PATH.cgi"` | Detect ShellShock [[CVE-2014-6271\|CVE-2014-6271]]                                      |


{ #d52ab0}


## Categories
| Script Category | Description                                                                                                                                               |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth`          | Authentication related scripts                                                                                                                            |
| `broadcast`     | Discover hosts by sending broadcast messages                                                                                                              |
| `brute`         | Performs brute-force password auditing against logins                                                                                                     |
| `default`       | Default scripts, same as `-sC`                                                                                                                            |
| `discovery`     | Retrieve accessible information, such as database tables and DNS names                                                                                    |
| `dos`           | Detects servers vulnerable to Denial of Service (DoS)                                                                                                     |
| `exploit`       | Attempts to exploit various vulnerable services                                                                                                           |
| `external`      | Checks using a third-party service, such as Geoplugin and Virustotal                                                                                      |
| `fuzzer`        | Launch fuzzing attacks                                                                                                                                    |
| `intrusive`     | Intrusive scripts such as brute-force attacks and exploitation<br>Pueden proporcionar información valiosa sobre vulnerabilidades y debilidades en la red. |
| `malware`       | Scans for backdoors                                                                                                                                       |
| `safe`          | Safe scripts that won’t crash the target                                                                                                                  |
| `version`       | Retrieve service versions                                                                                                                                 |
| `vuln`          | Checks for vulnerabilities or exploit vulnerable services                                                                                                 |
## [[SMB\|SMB]]

| Option                                                                                       | Description                                                     |
| -------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `-p445 --script smb-enum-*`                                                                  | Run smb scripts to enum                                         |
| `p445 --script smb-enum-* --script-args smbusername=administrator,smbpassword=smbserver_771` | Run smb scripts to enum with credentials                        |
| `--script smb-protocols`                                                                     | list the supported protocols and dialects of an [[SMB\|SMB]] server. |
| `--script smb-vuln* -p139,445`                                                               | Check vulns                                                     |
## [[NetBIOS\|NetBIOS]]
| Option                 | Description      |
| ---------------------- | ---------------- |
| `--script stat -p 137` | [[NetBIOS\|NetBIOS]] enum |
## [[SNMP\|SNMP]]
| Option                                                   | Desctiption                       |
| -------------------------------------------------------- | --------------------------------- |
| `-sU -p 161 --script snmp-brute`                         | [[Brute-force\|Brute-force]] community strings |
| `-sU -p 161 --script snmp-* demo.ine.local > snmp _info` | Run all scripts ans save results  |
# Output formats

| Option | Desctiption                                     |
| ------ | ----------------------------------------------- |
| `-oN`  | save output in normal format                    |
| `-oG`  | save output in grepable format                  |
| `-oX`  | save output in XML format                       |
| `-oA`  | save output in normal, XML and Grepable formats |
# Port states
1. **Open**:
   A service **is listening** on the specified port.
2. **Closed**:
   **No service is listening** on the specified port, although the port **is accessible**.
   By accessible, we mean that it is **reachable** and is **not blocked** by a firewall or other security appliances/programs.
3. **Filtered**:
   Nmap **cannot determine** if the port is open or closed because the port **is not accessible**.
   This state is usually due to a **firewall preventing Nmap** from reaching that port. Nmap’s packets may be blocked from reaching the port; alternatively, the **responses are blocked** from reaching Nmap’s host.
4. **Unfiltered**:
   Nmap **cannot determine** if the port is open or closed, although the port **is accessible**.
   This state is encountered when using an ACK scan `-sA`.
5. **Open|Filtered**:
   Nmap **cannot determine** whether the port is open or filtered.
6. **Closed|Filtered**:
   Nmap **cannot decide** whether a port is closed or filtered.

# Methodology
![Pasted image 20240708081910.png|200](/img/user/attachments/Pasted%20image%2020240708081910.png)