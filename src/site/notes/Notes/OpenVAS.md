---
{"dg-publish":true,"permalink":"/notes/open-vas/"}
---

# Installation
## Requeriments
### Install [[Docker\|docker]]
```shell
sudo apt update
sudo apt install docker.io
```
### Start docker service
We have **two** options:
1. **Start** the docker service and **enable** it to autostart after future restarts. (Recommended)
```shell
sudo systemctl enable docker
```
2. **Start** the docker service once (You'll need to start manually after every restart)
Use one of this commands
```shell
sudo systemctl start docker

or

sudo service docker start
```
## Install OpenVAS in a docker container
The OpenVAS will be installed in a docker container make it especifically to it.
Run this command and all instalation will complete after a while, be patient.
```shell
sudo docker run -d -p 443:443 --name openvas mikesplain/openvas
```
Now, OpenVAS is installed in a docker container and also is already running as a server.
As a client we need to connect to the server through the browser, usually to the `https://127.0.0.1:443/` or the *URL* showed in the console after installation.

> [!important] Important
> This just work right now but to make it work after restart, you will need to run docket again with the *start* command from above, or use the *enable* command and forget the start the service every restart

# Problems
If the docker service is running, you can use this command to **show info** from containers like *names*, *status*, ID and others:
```shell
sudo docker ps -a
```
You can check the status of the container in the *STATUS* column. Like *Up* or *Down*

If for any reason the docker service is running but the container it is not running (*Down*)

You need to start the container manually with this command: (You'll need the container's *name*)
```shell
docker start name_of_docker
```

