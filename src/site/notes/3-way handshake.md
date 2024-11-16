---
{"dg-publish":true,"permalink":"/3-way-handshake/","hide":"true"}
---


![Pasted image 20241001084720.png|400](/img/user/attachments/Pasted%20image%2020241001084720.png)
![](https://i.imgur.com/ngzBWID.png)

- This request contains something called a _SYN_ (short for _synchronise_) bit, which essentially makes first contact in starting the connection process.
- The server will then respond with a packet containing the **SYN** bit, as well as another "acknowledgement" bit, called _ACK_. 
- Finally, your computer will send a packet that contains the **ACK** bit by itself, confirming that the connection has been setup successfully.

If the server is respond with an RST.
- Could be closed, filtered, blocked by the [[Firewall\|Firewall]] or another reason.
![Pasted image 20241009105121.png](/img/user/attachments/Pasted%20image%2020241009105121.png)