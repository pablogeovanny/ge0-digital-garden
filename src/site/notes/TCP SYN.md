---
{"dg-publish":true,"permalink":"/tcp-syn/","hide":"true"}
---


SYN scans sends back a RST TCP packet after receiving a SYN/ACK from the server
![Pasted image 20241007220542.png](/img/user/attachments/Pasted%20image%2020241007220542.png)
![Pasted image 20241007220612.png](/img/user/attachments/Pasted%20image%2020241007220612.png)
advantages
- It can be used to bypass older Intrusion Detection systems as they are looking out for a full three way handshake. This is often no longer the case with modern IDS solutions; it is for this reason that SYN scans are still frequently referred to as "stealth" scans.
- SYN scans are often not logged by applications listening on open ports, as standard practice is to log a connection once it's been fully established. Again, this plays into the idea of SYN scans being stealthy.
- Without having to bother about completing (and disconnecting from) a three-way handshake for every port, SYN scans are significantly faster than a standard TCP Connect scan.

There are, however, a couple of disadvantages to SYN scans, namely:

- They require sudo permissions[1] in order to work correctly in Linux. This is because SYN scans require the ability to create raw packets (as opposed to the full TCP handshake), which is a privilege only the root user has by default.
- Unstable services are sometimes brought down by SYN scans, which could prove problematic if a client has provided a production environment for the test.

SYN scans are the default scans used by Nmap _if run with sudo permissions_. If run **without** sudo permissions, Nmap defaults to the TCP Connect scan we saw in the previous task.

Si un puerto está cerrado, el servidor responde con un paquete TCP RST. Si el puerto está filtrado por un cortafuegos, el paquete TCP SYN se descarta o se falsifica con un reinicio TCP.
