---
{"dg-publish":true,"permalink":"/notes/command-injection-attacks/"}
---

- **Abuse** of an **application**'s behaviour to **execute OS commands** on the **OS**. 
- **No matter the programming language** the application uses, it can result in **execute OS commands**.
- Occurs when server-side code (like PHP) in a web application **makes a call to a function that interacts with the server's console** directly.
- An injection web vulnerability allows an attacker to **take advantage of that call to execute** operating system **commands** arbitrarily **on the server**.
- Also often known as [[Pentesting Web/RCE\|RCE]], (They are not the same).
- Might accomplish a [[Pentesting Web/RCE\|RCE]].
- The possibilities for the attacker from here are endless:
	- they could **list files**, **read** their contents, **run** some basic **commands** to do some **recon** on the server or whatever they wanted.
![Pasted image 20240804170616.png|600](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020240804170616.png)
![Pasted image 20230909100049.png|700](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020230909100049.png)
# Discovering
## PHP example
The application takes data that a user enters in an input field named `$title` to search a directory for a song title
![Pasted image 20240804174648.png|800](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020240804174648.png)
**1.** The application stores MP3 files in a directory contained on the operating system.
**2.** The user inputs the song title they wish to search for. The application stores this input into the `$title` variable.
**3.** The data within this `$title` variable is passed to the command `grep` to search a text file named `songtitle.txt` for the entry of whatever the user wishes to search for.
**4.** The output of this search of `songtitle.txt` will determine whether the application informs the user that the song exists or not.
An attacker could abuse this application by **injecting** their own **commands** for the application to execute.
Rather than using `grep` to search for an entry in `songtitle.txt`, they could **ask** the application **to read data** from a more **sensitive** file.
## Python example
![Pasted image 20240804175415.png|600](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020240804175415.png)
1. The "flask" package is used to set up a web server
2. A function that uses the "subprocess" package to execute a command on the device
3. We use a route in the webserver that will execute whatever is provided. For example, to execute `whoami`, we'd need to visit http://flaskapp.thm/whoami
# Exploiting
- Analyze the application behavior.
- For example, the shell operators `;`, `&` and `&&` will combine two (or more) system commands and execute them both

| Method      | Description                                                                                                                                                                                                                                             |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Blind**   | There is **no direct output** from the application when testing payloads. <br>You will have to investigate the behaviours of the application to determine whether or not your payload was successful.                                                   |
| **Verbose** | There is **direct feedback** from the application once you have tested a payload.<br>For example, running the `whoami` command to see what user the application is running under.<br>The web application will output the username on the page directly. |
## Detect Blind command injection
Use payloads that will cause some time delay.
- E.g. `ping`, `sleep`

Forcing some output.
- Using redirection operators such as `>`
- E.g. Execute `whoami` and redirect the output to a file and we can read it using `cat`.

[[Operative System/Linux/Commands/curl\|curl]] is a great way to test
-  E.g. `curl http://vulnerable.app/process.php%3Fsearch%3DThe%20Beatles%3B%20whoami`
## Detecting Verbose command injection
- For example, the output of commands such as `ping` or `whoami` is directly displayed on the web application.
## Bypassing filters
- For example, an application may **strip out quotation marks**; we can instead **use** the **hexadecimal** value of this to achieve the same result.
![Pasted image 20240816092359.png|600](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020240816092359.png)
## Useful payloads
### Linux

| Payload | Description                                                                                                                                                                                                          |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| whoami  | See what user the application is running under.                                                                                                                                                                      |
| ls      | List the contents of the current directory. You may be able to find files such as configuration files, environment files (tokens and application keys), and many more valuable things.                               |
| ping    | This command will invoke the application to hang. This will be useful in testing an application for blind command injection.                                                                                         |
| sleep   | This is another useful payload in testing an application for blind command injection, where the machine does not have `ping` installed.                                                                              |
| nc      | Netcat can be used to spawn a reverse shell onto the vulnerable application. You can use this foothold to navigate around the target machine for other services, files, or potential means of escalating privileges. |

[[Linux Command Injection Payload List\|Linux Command Injection Payload List]]
### Windows

| Payload | Description                                                                                                                                                                            |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| whoami  | See what user the application is running under.                                                                                                                                        |
| dir     | List the contents of the current directory. You may be able to find files such as configuration files, environment files (tokens and application keys), and many more valuable things. |
| ping    | This command will invoke the application to hang. This will be useful in testing an application for blind command injection.                                                           |
| timeout | This command will also invoke the application to hang. It is also useful for testing an application for blind command injection if the `ping` command is not installed.                |

[[Windows Command Injection Payload List\|Windows Command Injection Payload List]]
# Remediating
- **Minimal use** of potentially dangerous **functions** or **libraries** in a programming language
- **Filtering input** without relying on a user’s input.
## PHP vuln functions
interact with the operating system to execute commands via shell
- Exec
- Passthru
- System
Example
![Pasted image 20240816091458.png|600](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020240816091458.png)
1. The application will only accept a specific pattern of characters (the digits  0-9)
2. The application will then only proceed to execute this data which is all numerical.
## Input sanitization
Example check if it's a number with the `filter_input` PHP function 
![Pasted image 20240816091828.png|600](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020240816091828.png)
# Some types
## HTML embedding
- Use to break web sites virtually.
- Add HTML based content to the vulnerable app.
## Shell injection
- Try to create an string to get access the shell of the web server.
- Could be: `system()`, `StartProcess()`, `java.lang.Runtime.exec()`, `System.Diagnostics.Process.Start()` and similar API commands.
## File injection
- To inject malicious code on the files system.
![Pasted image 20230909100216.png|600](/img/user/Networking/Seguridad%20en%20redes/Fundamentos%20de%20seguridad%20ofensiva/attachments/Pasted%20image%2020230909100216.png)