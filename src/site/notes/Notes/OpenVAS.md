---
{"dg-publish":true,"permalink":"/notes/open-vas/"}
---

Start docker servic
```shell
sudo service docker start
```
```shell
sudo systemctl start docker
```

Install In docker
```sh
sudo docker run -d -p 443:443 --name openvas mikesplain/openvas
```

Start OpenVAS after restart
```shell
docker start name_of_docker
```

Show containers
```shell
sudo docker ps -a
```