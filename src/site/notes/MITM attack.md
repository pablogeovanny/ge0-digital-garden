---
{"dg-publish":true,"permalink":"/mitm-attack/","hide":"true"}
---

- Man in the middle
- Attacker site between the target and the server
- Can change the info
- Sniffing can be used
- Relatively simple to carry out if the two parties do **not confirm the authenticity and integrity** of each message.
- Affect **cleartext protocols**

![Pasted image 20230908214558.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020230908214558.png)

- Set [[Hacking Ético y Pentesting/Keylogger\|keylogger]]
- Get browser info
- Screenshots
- Delete certs
- [[backdoor\|Backdoor]]
# ARP poisoning
## arpspoof
- arpspoof -i interface -t IP1 IP2
- arpspoof -i interface -t IP2 IP1
- IP1 is the address of the access point or gateway
- IP2 is the target system

## Cain & Abel
- Scan MAC adress
- New ARP Poison Routing
- It can be used to monitoring the traffic between two systems and detect this type of attacks
## Tools
- [Ettercap](https://www.ettercap-project.org)
- [Bettercap](https://www.bettercap.org)
# Mitigation
- Proper authentication along with encryption or signing of the exchanged messages.
- With the help of [[PKI\|PKI]] and trusted root certificates, [[TLS\|TLS]] protects from [[MITM attack\|MITM attack]] .
- Set static arp tables
