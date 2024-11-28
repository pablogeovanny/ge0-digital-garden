---
{"dg-publish":true,"permalink":"/write-ups/try-hack-me/investigating-windows/","tags":["CTF","write-up"]}
---


---
> [!INFO] Info about Investigating Windows
>  A windows machine has been hacked, its your job to go investigate this windows machine and find clues to what the hacker might have done.
>  This is a challenge that is exactly what is says on the tin, there are a few challenges around investigating a windows machine that has been previously compromised.
>  Connect to the machine using RDP. The credentials the machine are as follows:
>  Username: Administrator  
>  Password: letmein123!

> [!FAQ]- Hints
> No Hints.

---
# Connect
We can deploy the machine on tryhackme page or connect via RDP
Connect using [[xfreerdp\|xfreerdp]]12
```powershell
xfreerdp /u:Administrator /p:letmein123! /v:10.10.164.154
```
# Open powershell
![Pasted image 20241127095505.png|300](/img/user/attachments/Pasted%20image%2020241127095505.png)
# What's the version and year of the Windows machine?
Execute the command to get system information
```powershell
systeminfo
```
![Pasted image 20241127095330.png](/img/user/attachments/Pasted%20image%2020241127095330.png)
# Which user logged in last?
Execute the command to check the logon users
```powershell
query user
```
![Pasted image 20241127095900.png](/img/user/attachments/Pasted%20image%2020241127095900.png)
# When did John log onto the system last?
Use the command
```powershell
net user john
```
![Pasted image 20241127102424.png](/img/user/attachments/Pasted%20image%2020241127102424.png)
# What IP does the system connect to when it first starts?
When the system starts the IP is showed
![Pasted image 20241127203604.png](/img/user/attachments/Pasted%20image%2020241127203604.png)
# What two accounts had administrative privileges (other than the Administrator user)?
Show users from the administrator group, that user have administrator privileges.
![Pasted image 20241127115616.png](/img/user/attachments/Pasted%20image%2020241127115616.png)
# What's the name of the scheduled task that is malicious.
List schedule tasks
```powershell
schtasks /query /fo /LIST
```
![Pasted image 20241127122114.png|600](/img/user/attachments/Pasted%20image%2020241127122114.png)
Tog get more info of each of them execute
```powershell
schtasks /query /tn "TASK_NAME_HERE" /fo LIST /v 
```
You'll notice that one of them is triyng  to execute an `ps1` file.
# What file was the task trying to run daily?
Is one of all interesting tasks Check all of them getting more info with
```powershell
schtasks /query /tn "Clean file system" /fo LIST /v 
```
![Pasted image 20241127124820.png](/img/user/attachments/Pasted%20image%2020241127124820.png)
# What port did this file listen locally for?
```powershell
schtasks /query /tn "Clean file system" /fo LIST /v 
```
![Pasted image 20241127130440.png](/img/user/attachments/Pasted%20image%2020241127130440.png)
# When did Jenny last logon?
```powershell
net user Jenny
```
![Pasted image 20241127134258.png](/img/user/attachments/Pasted%20image%2020241127134258.png)

# At what date did the compromise take place?
```powershell
schtasks /query /tn "Clean file system" /fo LIST /v
```
![Pasted image 20241127134653.png](/img/user/attachments/Pasted%20image%2020241127134653.png)
# During the compromise, at what time did Windows first assign special privileges to a new logon?
Open the *Event Viewer*
Select *Security* 
![Pasted image 20241127205632.png](/img/user/attachments/Pasted%20image%2020241127205632.png)
# What tool was used to get Windows passwords?
Check the file
![Pasted image 20241127211727.png](/img/user/attachments/Pasted%20image%2020241127211727.png)
# What was the attackers external control and command servers IP?
The machine is connecting to external so let's check the Windows Host File Location
```powershell
type C:\\Windows\\System32\\drivers\\etc\\hosts
```
![Pasted image 20241127220037.png](/img/user/attachments/Pasted%20image%2020241127220037.png)
# What was the extension name of the shell uploaded via the servers website?
![Pasted image 20241127220308.png](/img/user/attachments/Pasted%20image%2020241127220308.png)
# What was the last port the attacker opened?
Check the firewall config, inbound rules and check the port
![Pasted image 20241127220952.png](/img/user/attachments/Pasted%20image%2020241127220952.png)
![Pasted image 20241127221059.png](/img/user/attachments/Pasted%20image%2020241127221059.png)
# Check for DNS poisoning, what site was targeted?
```powershell
type C:\\Windows\\System32\\drivers\\etc\\hosts
```
![Pasted image 20241127220037.png](/img/user/attachments/Pasted%20image%2020241127220037.png)
