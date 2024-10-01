---
{"dg-publish":true,"permalink":"/tcp-window-scan/","hide":"true"}
---


- Like [[TCP ACK Scan\|TCP ACK Scan]], but, it examines the TCP Window field of the RST packets returned. On specific systems, this can reveal that the port is open.
- If a **firewall** **does not block** some **ports**, we will see them like **closed state**, **although** these are **not closed.**
![Pasted image 20240724110057.png](/img/user/attachments/Pasted%20image%2020240724110057.png)