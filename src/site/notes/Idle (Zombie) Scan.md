---
{"dg-publish":true,"permalink":"/idle-zombie-scan/","hide":"true"}
---


- Requires an idle system connected to the network that you can communicate with.
The attacker system probing an idle machine, a multi-function printer. By sending a SYN/ACK, it responds with an RST packet containing its newly incremented IP ID.
![Pasted image 20240726225136.png|600](/img/user/attachments/Pasted%20image%2020240726225136.png)
## Closed port
its IP ID is not incremented.
![Pasted image 20240726225233.png|600](/img/user/attachments/Pasted%20image%2020240726225233.png)
## Open port
its IP ID is incremented.
![Pasted image 20240726225359.png|600](/img/user/attachments/Pasted%20image%2020240726225359.png)
## Blocked by firewall
The target machine does not respond at all due to firewall rules.
This lack of response will lead to the same result as with the closed port; the idle host won’t increase the IP ID.