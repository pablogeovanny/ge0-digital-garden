---
{"dg-publish":true,"permalink":"/nessus/"}
---

- Nessus essential is a free version of the Nessus vulnerability scanning tool provided by Tenable.
- It allows users to scan up to 16 IP addresses for vulnerabilities, misconfigurations, and compliance issues
- Offering essential scanning capabilities for small teams or individuals looking to improve their security posture without significant investment
# Download
Go to the official download page [here](https://www.tenable.com/downloads/nessus)
Download the *.deb* file, after select the version and platform (If you have Kali linux, it is a Debian based, so select it)
![Pasted image 20250323214003.png|600](/img/user/attachments/Pasted%20image%2020250323214003.png)
# Install
The file should be downloaded on the *Downloads* folder
Open a console
```shell
cd ~/Downloads                   ## Go to the download folder
sudo dpkg -i package_file.deb    ## Install
```
# Start the service
We need to start the Nessus service called *nessusd.service* 
We have **two** options, choose one:
1. **Start** the service and **enable** it to autostart after future restarts. (Recommended)
```shell
sudo systemctl enable nessusd.service
```
2. **Start** the service once (You'll need to start manually after every restart)
Use one of this commands
```shell
sudo systemctl start nessusd.service

or

sudo service nessusd.service start
```
# Open
Now, Nessus is installed and also is already running as a server.
As a client, we need to connect to the server through the browser, usually to the `https://127.0.0.1:8834/` or the *URL* showed in the console after installation.
# Extra tools
## mergeness
- To join nessus informs to a 1 inform
1. Put all files in a folder
2. In that folder copy the .py tool
3. Run tool
## NessusParser-Excel
To convert `.nessus`to `.xlsx`
```shell
python3 nessusparser.py -l ORIGIN_DIR -o DEST_DIR
```