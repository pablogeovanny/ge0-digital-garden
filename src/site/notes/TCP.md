---
{"dg-publish":true,"permalink":"/tcp/","hide":"true"}
---


- Transmission Control Protocol
- _connection-based_ protocol.
- Multiplexación: Función que permite que los host receptores seleccionen la aplicación correcta para los datos recibidos, esto se realiza a través del numero de puerto
- Recuperación de errores: Permite numerar los datos con una secuencia y establecer un proceso de reconocimiento de los datos recibidos, lo que proporciona fiabilidad.
- Control de flujo usando ventanas: proceso que permite que dos dispositivos acuerden de forma dinámica el intercambio de datos.
- Establecimiento y terminación de conexiones: Proceso de establecimiento de sesiones donde se coordinan números de secuencia y acuses de recibo. Además permite finalizar la comunicación entre 2 entidades.
- Transferencia de datos ordenada y segmentación: Permite fraccionar la información para enviarla y reordenarla al momento de recibirla.
- **Uso en Aplicaciones**: Es ampliamente utilizado en aplicaciones que requieren una entrega fiable de datos, como navegadores web, correo electrónico, y transferencia de archivos.
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



![Pasted image 20230601200521.png](/img/user/Networking/Seguridad%20en%20redes/Anexos/Pasted%20image%2020230601200521.png)

1. **URG**: 
   Indicates that the **urgent pointer** filed is significant. The urgent pointer indicates that the incoming **data is urgent**, and that a TCP segment with the URG flag set is **processed immediately** without consideration of having to wait on previously sent TCP segments.
3. **ACK**:
   Acknowledgement flag indicates that the acknowledgement number is significant. It is used to acknowledge the receipt of a TCP segment.
4. **PSH**:
   Push flag asking TCP to **pass the data** to the application **promptly**.
5. **RST**:
   Reset flag is used to **reset the connection**. Another device, such as a firewall, might send it to **tear a TCP connection.** This flag is also used when data is sent to a host and there is **no service** on the receiving end **to answer.**
6. **SYN**:
   Synchronize flag is used to **initiate a TCP 3-way handshake** and synchronize sequence numbers with the other host. The sequence number should be set randomly during TCP connection establishment.
7. **FIN**:
   The sender has **no more data to send.**

</div></div>

## Advantages and Disadvantages
|   |   |
|---|---|
|**Advantages of TCP**|**Disadvantages of TCP  <br>**|
|Guarantees the accuracy of data.|Requires a reliable connection between the two devices. If one small chunk of data is not received, then the entire chunk of data cannot be used.|
|Capable of synchronising two devices to prevent each other from being flooded with data.|A slow connection can bottleneck another device as the connection will be reserved on the receiving computer the whole time.|
|Performs a lot more processes for reliability.|TCP is significantly slower than UDP because more work has to be done by the devices using this protocol.|
## 
<div class="transclusion internal-embed is-loaded"><a class="markdown-embed-link" href="/3-way-handshake/" aria-label="Open link"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="svg-icon lucide-link"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></a><div class="markdown-embed">





![Pasted image 20241001084720.png](/img/user/Networking/Seguridad%20en%20redes/Fabricaci%C3%B3n%20y%20manipulaci%C3%B3n%20de%20paquetes/attachments/Pasted%20image%2020241001084720.png)
![](https://i.imgur.com/ngzBWID.png)

- This request contains something called a _SYN_ (short for _synchronise_) bit, which essentially makes first contact in starting the connection process.
- The server will then respond with a packet containing the **SYN** bit, as well as another "acknowledgement" bit, called _ACK_. 
- Finally, your computer will send a packet that contains the **ACK** bit by itself, confirming that the connection has been setup successfully.

</div></div>

![Pasted image 20231128153059.png](/img/user/Networking/attachments/Pasted%20image%2020231128153059.png)