---
{"dg-publish":true,"permalink":"/networking/udp/","hide":"true"}
---


- User Datagram Protocol
- No connection-based protocol.
- UDP es un protocolo que no realiza conexión. No proporciona confiabilidad, ni ventanas, ni reordenamiento de los datos. Sin embargo, proporciona transferencia de datos y multiplexación usando números de puerto. Este proceso lo hace utilizando menos Bytes de sobre carga que TCP. Lo que es beneficioso para comunicaciones en tiempo real como VoIP
- Stateless connection
- **Rápido y Ligero**:
- **Uso en Aplicaciones**: Ideal para aplicaciones donde la velocidad es crucial y se pueden tolerar algunas pérdidas de datos, como juegos en línea, streaming de video y voz sobre IP (VoIP).
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



![Pasted image 20230601200659.png](/img/user/Networking/Seguridad%20en%20redes/Anexos/Pasted%20image%2020230601200659.png)

UDP packets are much simpler than TCP packets and have fewer headers. However, both protocols share some standard headers, which are what is annotated in the table below:

|   |   |
|---|---|
|**Header**|**Description**|
|Time to Live (TTL)|This field sets an expiry timer for the packet, so it doesn't clog up your network if it never manages to reach a host or escape!|
|Source Address|The IP address of the device that the packet is being sent from, so that data knows where to return to.|
|Destination Address|The device's IP address the packet is being sent to so that data knows where to travel next.|
|Source Port|This value is the port that is opened by the sender to send the UDP packet from. This value is randomly chosen (out of the ports from 0-65535 that aren't already in use at the time).|
|Destination Port|This value is the port number that an application or service is running on the remote host (the one receiving the data); for example, a webserver running on port 80. Unlike the source port, this value is not chosen at random.|
|Data|This header is where data, i.e. bytes of a file that is being transmitted, is stored.|


</div></div>

|  |  |
| ---- | ---- |
| **Advantages of UDP** | **Disadvantages of UDP** |
| UDP is much faster than TCP. | UDP doesn't care if the data is received. |
| UDP leaves the application layer (user software) to decide if there is any control over how quickly packets are sent. | It is quite flexible to software developers in this sense. |
| UDP does not reserve a continuous connection on a device as TCP does. | This means that unstable connections result in a terrible experience for the user. |
|  |  |

![Pasted image 20231128153210.png](/img/user/Networking/attachments/Pasted%20image%2020231128153210.png)
The diagram below shows a normal UDP connection between Alice and Bob. In real life, this would be between two devices.
![Pasted image 20231227204707.png](/img/user/Pasted%20image%2020231227204707.png)
