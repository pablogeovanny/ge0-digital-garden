---
{"dg-publish":true,"permalink":"/udp-ping/","hide":"true"}
---



<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- When a packet is sent to an **open** UDP **port**, there should be **no response**. When this happens, Nmap refers to the port as being `open|filtered`
- When a packet is sent to a **_closed_ UDP port**, the target should **respond** with an **ICMP (ping)** packet containing a message that the port is unreachable.

</div></div>

![Pasted image 20240717110800.png](/img/user/attachments/Pasted%20image%2020240717110800.png)
![Pasted image 20240717110807.png](/img/user/attachments/Pasted%20image%2020240717110807.png)