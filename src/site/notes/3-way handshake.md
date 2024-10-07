---
{"dg-publish":true,"permalink":"/3-way-handshake/","hide":"true"}
---


![Pasted image 20241001084720.png](/img/user/Networking/Seguridad%20en%20redes/Fabricaci%C3%B3n%20y%20manipulaci%C3%B3n%20de%20paquetes/attachments/Pasted%20image%2020241001084720.png)
![](https://i.imgur.com/ngzBWID.png)

- This request contains something called a _SYN_ (short for _synchronise_) bit, which essentially makes first contact in starting the connection process.
- The server will then respond with a packet containing the **SYN** bit, as well as another "acknowledgement" bit, called _ACK_. 
- Finally, your computer will send a packet that contains the **ACK** bit by itself, confirming that the connection has been setup successfully.