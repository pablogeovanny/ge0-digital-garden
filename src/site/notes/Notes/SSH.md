---
{"dg-publish":true,"permalink":"/notes/ssh/","dg-note-properties":{"aliases":["Secure Shell"]}}
---

- Default port **22**
- Allows the secure transmission of data and commands over a network
- Cryptographic remote access **protocol**
- We will need to confirm the fingerprint of the SSH server’s public key to avoid [[MITM attack\|MITM attack]]
- To connect to a remote Linux host via SSH, a corresponding SSH server must be available and running
# SSH server
- The most commonly used SSH server is the OpenSSH server.
## [[OpenSSH\|OpenSSH]]
# Enable service daemon
```sh
sudo systemctl start sshd
sudo systemctl enable sshd
```
# On Windows
## Setting up
List Windows packages for OpenSSH.
```Powershell
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
```
![Pasted image 20260726113513.png\|584](/img/user/attachments/Pasted%20image%2020260726113513.png)

Install the [[Notes/SSH\|SSH]] package *client* to the windows host.
```Powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```
Install the [[Notes/SSH\|SSH]] package *server* to the windows host.
```Powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

Starting the SSH Service
```Powershell
Start-Service sshd 
```
Setting Startup Type
```Powershell
Set-Service -Name sshd -StartupType 'Automatic'
```
## Access
Connecting from Windows to get a [[CMD\|CMD]] by default)
```cmd
ssh username@IP_or_Domain
```
To get a [[PowerShell\|PowerShell]] session, type *powershell*
```powershell
powershell
```
# Username and password Authentication
```shell
ssh username@IP_or_Domain -p 2220
ssh bandit0@bandit.labs.overthewire.org -p 2220 -oHostKeyAlgorithms=+ssh-rsa
```

```shell
sshpass -p 'password' ssh bandit0@bandit.labs.overthewire.org -p 2220
```
# [[RSA\|RSA]] keys Authentication
- Data **encrypted** with the **private key** can be **decrypted** with the **public key,** and vice versa.
- tends to be **slower** and uses **larger keys**
## Generate keys
- Create a pair of keys RSA keys in `/home/USER/.ssh
- Optionally provide a **passphrase** (leave it empty for no passphrase).
```shell
ssh-keygen
or
ssh-keygen -t rsa -b 2048
```

| Keys         | Description                                                      |
| ------------ | ---------------------------------------------------------------- |
| `id_rsa`     | **Private**<br>(`400` permissions required to remote connection) |
| `id_rsa.pub` | **Public**                                                       |

## Connect from M2 to M1 without password
<div class="excalidraw-svg"><svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 264.9040334371282 163.5827512168902" width="264.9040334371282" height="163.5827512168902" class="excalidraw-svg" style="max-width: 100%; height: auto; width: 400px;"><!-- svg-source:excalidraw --><metadata/><defs><style class="style-fonts">      @font-face { font-family: Excalifont; src: url(data:font/woff2;base64,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); }</style></defs><rect x="0" y="0" width="264.9040334371282" height="163.5827512168902" fill="#ffffff"/><g stroke-linecap="round" transform="translate(17.401067039514643 10) rotate(0 31.63299416860964 38.232323349387)"><path d="M63.27 38.23 C63.27 40.23, 63.13 42.24, 62.88 44.21 C62.62 46.18, 62.23 48.15, 61.72 50.05 C61.21 51.94, 60.57 53.81, 59.82 55.59 C59.07 57.37, 58.19 59.09, 57.22 60.7 C56.26 62.32, 55.17 63.86, 54 65.27 C52.83 66.68, 51.56 67.99, 50.23 69.16 C48.89 70.33, 47.46 71.39, 45.99 72.3 C44.52 73.2, 42.98 73.98, 41.41 74.59 C39.84 75.21, 38.21 75.68, 36.58 75.99 C34.95 76.31, 33.28 76.46, 31.63 76.46 C29.98 76.46, 28.31 76.31, 26.68 75.99 C25.06 75.68, 23.43 75.21, 21.86 74.59 C20.29 73.98, 18.74 73.2, 17.27 72.3 C15.8 71.39, 14.37 70.33, 13.04 69.16 C11.71 67.99, 10.43 66.68, 9.27 65.27 C8.1 63.86, 7.01 62.32, 6.04 60.7 C5.07 59.09, 4.2 57.37, 3.45 55.59 C2.7 53.81, 2.06 51.94, 1.55 50.05 C1.04 48.15, 0.65 46.18, 0.39 44.21 C0.13 42.24, 0 40.23, 0 38.23 C0 36.24, 0.13 34.22, 0.39 32.25 C0.65 30.28, 1.04 28.31, 1.55 26.42 C2.06 24.52, 2.7 22.65, 3.45 20.88 C4.2 19.1, 5.07 17.37, 6.04 15.76 C7.01 14.15, 8.1 12.61, 9.27 11.2 C10.43 9.79, 11.71 8.47, 13.04 7.3 C14.37 6.13, 15.8 5.07, 17.27 4.17 C18.74 3.26, 20.29 2.49, 21.86 1.87 C23.43 1.26, 25.06 0.78, 26.68 0.47 C28.31 0.16, 29.98 0, 31.63 0 C33.28 0, 34.95 0.16, 36.58 0.47 C38.21 0.78, 39.84 1.26, 41.41 1.87 C42.98 2.49, 44.52 3.26, 45.99 4.17 C47.46 5.07, 48.89 6.13, 50.23 7.3 C51.56 8.47, 52.83 9.79, 54 11.2 C55.17 12.61, 56.26 14.15, 57.22 15.76 C58.19 17.37, 59.07 19.1, 59.82 20.88 C60.57 22.65, 61.21 24.52, 61.72 26.42 C62.23 28.31, 62.62 30.28, 62.88 32.25 C63.13 34.22, 63.2 37.24, 63.27 38.23 C63.33 39.23, 63.33 37.24, 63.27 38.23" stroke="transparent" stroke-width="1" fill="none"/></g><g stroke-linecap="round"><g transform="translate(21.926143895513675 55.34008761750604) rotate(0 26.448638628346124 11.561387201477395)" fill-rule="evenodd"><path d="M0 0 L0.11 9.42 L40.66 29.72 L52.4 21.41 L52.9 12.3 L13.58 -6.6 L0 0" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C0.03 2.4, 0.06 4.79, 0.11 9.42 M0 0 C0.02 2.02, 0.05 4.04, 0.11 9.42 M0.11 9.42 C14.56 16.66, 29.01 23.89, 40.66 29.72 M0.11 9.42 C12 15.37, 23.88 21.32, 40.66 29.72 M40.66 29.72 C45.16 26.53, 49.66 23.35, 52.4 21.41 M40.66 29.72 C44.68 26.87, 48.71 24.02, 52.4 21.41 M52.4 21.41 C52.56 18.52, 52.71 15.63, 52.9 12.3 M52.4 21.41 C52.56 18.52, 52.71 15.64, 52.9 12.3 M52.9 12.3 C37.42 4.86, 21.94 -2.58, 13.58 -6.6 M52.9 12.3 C41.49 6.82, 30.08 1.33, 13.58 -6.6 M13.58 -6.6 C9.53 -4.63, 5.48 -2.66, 0 0 M13.58 -6.6 C8.56 -4.16, 3.54 -1.72, 0 0 M0 0 C0 0, 0 0, 0 0 M0 0 C0 0, 0 0, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(22.89285058078535 55.640213919946774) rotate(0 25.61716812233965 10.191774646231224)"><path d="M0 0 C14.29 7.46, 28.58 14.92, 39.05 20.38 M0 0 C14.51 7.58, 29.03 15.15, 39.05 20.38 M39.05 20.38 C43.76 17.09, 48.48 13.8, 51.23 11.87 M39.05 20.38 C42.67 17.85, 46.3 15.32, 51.23 11.87" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(62.40743865100198 84.72315571240509) rotate(0 -0.08865561764929453 -4.015930478814951)"><path d="M0 0 C-0.04 -1.81, -0.08 -3.63, -0.18 -8.03 M0 0 C-0.07 -3.04, -0.13 -6.08, -0.18 -8.03" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(38.88969093493465 14.478931240557813) rotate(0 18.915880487914865 25.701680357781697)" fill-rule="evenodd"><path d="M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22 M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(25.494510846207092 40.16900176919174) rotate(0 23.935218500353926 1.0837497832572467)" fill-rule="evenodd"><path d="M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0 M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(28.67632902802511 39.723623823958434) rotate(0 20.429769424907594 0.9579109377231276)" fill-rule="evenodd"><path d="M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0" stroke="none" stroke-width="0" fill="#343a40" fill-rule="evenodd"/><path d="M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0 M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(50.9500589616096 73.97508162593888) rotate(0 4.027777777777828 3.101851851851734)" fill-rule="evenodd"><path d="M0 0 L8.02 4.03 L8.06 6.2 L0.15 2.37 L0 0" stroke="none" stroke-width="0" fill="#495057" fill-rule="evenodd"/><path d="M0 0 C2.25 1.13, 4.49 2.26, 8.02 4.03 M0 0 C2.32 1.17, 4.64 2.33, 8.02 4.03 M8.02 4.03 C8.03 4.55, 8.04 5.06, 8.06 6.2 M8.02 4.03 C8.04 4.9, 8.05 5.77, 8.06 6.2 M8.06 6.2 C5.01 4.72, 1.97 3.25, 0.15 2.37 M8.06 6.2 C5.45 4.94, 2.84 3.67, 0.15 2.37 M0.15 2.37 C0.1 1.51, 0.04 0.66, 0 0 M0.15 2.37 C0.11 1.75, 0.07 1.12, 0 0 M0 0 C0 0, 0 0, 0 0 M0 0 C0 0, 0 0, 0 0" stroke="#495057" stroke-width="1" fill="none"/></g></g><mask/><g transform="translate(10 99.37807530501794) rotate(0 48.19995880126953 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">Machine 2</text></g><g stroke-linecap="round" transform="translate(185.60106398775685 14.32555813954906) rotate(0 31.632994168609642 38.232323349387)"><path d="M63.27 38.23 C63.27 40.23, 63.13 42.24, 62.88 44.21 C62.62 46.18, 62.23 48.15, 61.72 50.05 C61.21 51.94, 60.57 53.81, 59.82 55.59 C59.07 57.37, 58.19 59.09, 57.22 60.7 C56.26 62.32, 55.17 63.86, 54 65.27 C52.83 66.68, 51.56 67.99, 50.23 69.16 C48.89 70.33, 47.46 71.39, 45.99 72.3 C44.52 73.2, 42.98 73.98, 41.41 74.59 C39.84 75.21, 38.21 75.68, 36.58 75.99 C34.95 76.31, 33.28 76.46, 31.63 76.46 C29.98 76.46, 28.31 76.31, 26.68 75.99 C25.06 75.68, 23.43 75.21, 21.86 74.59 C20.29 73.98, 18.74 73.2, 17.27 72.3 C15.8 71.39, 14.37 70.33, 13.04 69.16 C11.71 67.99, 10.43 66.68, 9.27 65.27 C8.1 63.86, 7.01 62.32, 6.04 60.7 C5.07 59.09, 4.2 57.37, 3.45 55.59 C2.7 53.81, 2.06 51.94, 1.55 50.05 C1.04 48.15, 0.65 46.18, 0.39 44.21 C0.13 42.24, 0 40.23, 0 38.23 C0 36.24, 0.13 34.22, 0.39 32.25 C0.65 30.28, 1.04 28.31, 1.55 26.42 C2.06 24.52, 2.7 22.65, 3.45 20.88 C4.2 19.1, 5.07 17.37, 6.04 15.76 C7.01 14.15, 8.1 12.61, 9.27 11.2 C10.43 9.79, 11.71 8.47, 13.04 7.3 C14.37 6.13, 15.8 5.07, 17.27 4.17 C18.74 3.26, 20.29 2.49, 21.86 1.87 C23.43 1.26, 25.06 0.78, 26.68 0.47 C28.31 0.16, 29.98 0, 31.63 0 C33.28 0, 34.95 0.16, 36.58 0.47 C38.21 0.78, 39.84 1.26, 41.41 1.87 C42.98 2.49, 44.52 3.26, 45.99 4.17 C47.46 5.07, 48.89 6.13, 50.23 7.3 C51.56 8.47, 52.83 9.79, 54 11.2 C55.17 12.61, 56.26 14.15, 57.22 15.76 C58.19 17.37, 59.07 19.1, 59.82 20.88 C60.57 22.65, 61.21 24.52, 61.72 26.42 C62.23 28.31, 62.62 30.28, 62.88 32.25 C63.13 34.22, 63.2 37.24, 63.27 38.23 C63.33 39.23, 63.33 37.24, 63.27 38.23" stroke="transparent" stroke-width="1" fill="none"/></g><g stroke-linecap="round"><g transform="translate(190.12614084375588 59.6656457570551) rotate(0 26.448638628346124 11.561387201477395)" fill-rule="evenodd"><path d="M0 0 L0.11 9.42 L40.66 29.72 L52.4 21.41 L52.9 12.3 L13.58 -6.6 L0 0" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C0.04 3.35, 0.08 6.71, 0.11 9.42 M0 0 C0.03 2.68, 0.07 5.36, 0.11 9.42 M0.11 9.42 C15.77 17.26, 31.43 25.1, 40.66 29.72 M0.11 9.42 C12.79 15.77, 25.47 22.12, 40.66 29.72 M40.66 29.72 C43.88 27.44, 47.1 25.16, 52.4 21.41 M40.66 29.72 C44.57 26.95, 48.49 24.17, 52.4 21.41 M52.4 21.41 C52.57 18.27, 52.74 15.14, 52.9 12.3 M52.4 21.41 C52.51 19.31, 52.63 17.22, 52.9 12.3 M52.9 12.3 C41.85 6.99, 30.79 1.68, 13.58 -6.6 M52.9 12.3 C37.17 4.74, 21.45 -2.81, 13.58 -6.6 M13.58 -6.6 C9.17 -4.46, 4.77 -2.32, 0 0 M13.58 -6.6 C9.94 -4.83, 6.31 -3.07, 0 0 M0 0 C0 0, 0 0, 0 0 M0 0 C0 0, 0 0, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(191.09284752902755 59.96577205949583) rotate(0 25.61716812233965 10.191774646231224)"><path d="M0 0 C14.97 7.81, 29.93 15.63, 39.05 20.38 M0 0 C14.79 7.72, 29.58 15.44, 39.05 20.38 M39.05 20.38 C41.53 18.65, 44 16.92, 51.23 11.87 M39.05 20.38 C43.71 17.13, 48.37 13.88, 51.23 11.87" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(230.60743559924418 89.04871385195415) rotate(0 -0.08865561764929453 -4.015930478814951)"><path d="M0 0 C-0.07 -3.06, -0.14 -6.13, -0.18 -8.03 M0 0 C-0.05 -2.33, -0.1 -4.66, -0.18 -8.03" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(207.08968788317685 18.804489380106872) rotate(0 18.91588048791487 25.701680357781697)" fill-rule="evenodd"><path d="M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22 M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(193.6945077944493 44.4945599087408) rotate(0 23.935218500353926 1.0837497832572467)" fill-rule="evenodd"><path d="M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0 M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(196.8763259762673 44.04918196350749) rotate(0 20.42976942490759 0.9579109377231347)" fill-rule="evenodd"><path d="M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0" stroke="none" stroke-width="0" fill="#343a40" fill-rule="evenodd"/><path d="M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0 M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(219.1500559098518 78.30063976548794) rotate(0 4.027777777777828 3.101851851851734)" fill-rule="evenodd"><path d="M0 0 L8.02 4.03 L8.06 6.2 L0.15 2.37 L0 0" stroke="none" stroke-width="0" fill="#495057" fill-rule="evenodd"/><path d="M0 0 C3.17 1.59, 6.33 3.18, 8.02 4.03 M0 0 C2.26 1.14, 4.52 2.27, 8.02 4.03 M8.02 4.03 C8.03 4.49, 8.04 4.95, 8.06 6.2 M8.02 4.03 C8.03 4.75, 8.04 5.48, 8.06 6.2 M8.06 6.2 C5.11 4.77, 2.17 3.34, 0.15 2.37 M8.06 6.2 C6.27 5.34, 4.48 4.47, 0.15 2.37 M0.15 2.37 C0.1 1.62, 0.06 0.88, 0 0 M0.15 2.37 C0.12 1.86, 0.09 1.36, 0 0 M0 0 C0 0, 0 0, 0 0 M0 0 C0 0, 0 0, 0 0" stroke="#495057" stroke-width="1" fill="none"/></g></g><mask/><g transform="translate(163.96410728966725 102.5323416599339) rotate(0 45.46996307373047 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">Machine 1</text></g><g stroke-linecap="round"><g transform="translate(85.47016996984914 54.03872287143125) rotate(0 45.99393274290076 -2.2770457788367224)"><path d="M-0.27 -0.22 C15.3 -1.03, 76.63 -3.79, 92.26 -4.33 M1.78 -1.38 C17.28 -2.02, 75.94 -2.06, 91.19 -2.72" stroke="#1e1e1e" stroke-width="2" fill="none"/></g><g transform="translate(85.47016996984914 54.03872287143125) rotate(0 45.99393274290076 -2.2770457788367224)"><path d="M67.87 6.3 C72.21 4.13, 77.57 4.39, 91.19 -2.72 M67.87 6.3 C75.89 3.05, 85.43 -0.36, 91.19 -2.72" stroke="#1e1e1e" stroke-width="2" fill="none"/></g><g transform="translate(85.47016996984914 54.03872287143125) rotate(0 45.99393274290076 -2.2770457788367224)"><path d="M67.54 -10.8 C72.01 -9.49, 77.45 -5.75, 91.19 -2.72 M67.54 -10.8 C75.71 -7.51, 85.38 -4.39, 91.19 -2.72" stroke="#1e1e1e" stroke-width="2" fill="none"/></g></g><mask/><g transform="translate(11.364085927362552 127.33229893532453) rotate(0 43.43994903564453 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">Attacker</text></g><g transform="translate(174.69732792005686 128.5827512168902) rotate(0 33.499961853027344 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">Target</text></g></svg></div>
### Method 1
 - This is the manual version of the *method 2*
 - **We need access** to both machines, the **passwords are not needed**
 - The **public key** (`id_rsa.pub`) of **computer 2** has to be in the file `authorized_keys` in the **computer 1**
 <div class="excalidraw-svg"><svg version="1.1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 383.00001525878906 220.31369335248286" width="383.00001525878906" height="220.31369335248286" class="excalidraw-svg" style="max-width: 100%; height: auto; width: 400px;"><!-- svg-source:excalidraw --><metadata/><defs><style class="style-fonts">      @font-face { font-family: Excalifont; src: url(data:font/woff2;base64,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); }</style></defs><rect x="0" y="0" width="383.00001525878906" height="220.31369335248286" fill="#ffffff"/><g stroke-linecap="round" transform="translate(58.04902590688806 67.82192164322424) rotate(0 31.63299416860964 38.232323349387)"><path d="M63.27 38.23 C63.27 40.23, 63.13 42.24, 62.88 44.21 C62.62 46.18, 62.23 48.15, 61.72 50.05 C61.21 51.94, 60.57 53.81, 59.82 55.59 C59.07 57.37, 58.19 59.09, 57.22 60.7 C56.26 62.32, 55.17 63.86, 54 65.27 C52.83 66.68, 51.56 67.99, 50.23 69.16 C48.89 70.33, 47.46 71.39, 45.99 72.3 C44.52 73.2, 42.98 73.98, 41.41 74.59 C39.84 75.21, 38.21 75.68, 36.58 75.99 C34.95 76.31, 33.28 76.46, 31.63 76.46 C29.98 76.46, 28.31 76.31, 26.68 75.99 C25.06 75.68, 23.43 75.21, 21.86 74.59 C20.29 73.98, 18.74 73.2, 17.27 72.3 C15.8 71.39, 14.37 70.33, 13.04 69.16 C11.71 67.99, 10.43 66.68, 9.27 65.27 C8.1 63.86, 7.01 62.32, 6.04 60.7 C5.07 59.09, 4.2 57.37, 3.45 55.59 C2.7 53.81, 2.06 51.94, 1.55 50.05 C1.04 48.15, 0.65 46.18, 0.39 44.21 C0.13 42.24, 0 40.23, 0 38.23 C0 36.24, 0.13 34.22, 0.39 32.25 C0.65 30.28, 1.04 28.31, 1.55 26.42 C2.06 24.52, 2.7 22.65, 3.45 20.88 C4.2 19.1, 5.07 17.37, 6.04 15.76 C7.01 14.15, 8.1 12.61, 9.27 11.2 C10.43 9.79, 11.71 8.47, 13.04 7.3 C14.37 6.13, 15.8 5.07, 17.27 4.17 C18.74 3.26, 20.29 2.49, 21.86 1.87 C23.43 1.26, 25.06 0.78, 26.68 0.47 C28.31 0.16, 29.98 0, 31.63 0 C33.28 0, 34.95 0.16, 36.58 0.47 C38.21 0.78, 39.84 1.26, 41.41 1.87 C42.98 2.49, 44.52 3.26, 45.99 4.17 C47.46 5.07, 48.89 6.13, 50.23 7.3 C51.56 8.47, 52.83 9.79, 54 11.2 C55.17 12.61, 56.26 14.15, 57.22 15.76 C58.19 17.37, 59.07 19.1, 59.82 20.88 C60.57 22.65, 61.21 24.52, 61.72 26.42 C62.23 28.31, 62.62 30.28, 62.88 32.25 C63.13 34.22, 63.2 37.24, 63.27 38.23 C63.33 39.23, 63.33 37.24, 63.27 38.23" stroke="transparent" stroke-width="1" fill="none"/></g><g stroke-linecap="round"><g transform="translate(62.574102762887094 113.16200926073029) rotate(0 26.448638628346124 11.561387201477395)" fill-rule="evenodd"><path d="M0 0 L0.11 9.42 L40.66 29.72 L52.4 21.41 L52.9 12.3 L13.58 -6.6 L0 0" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C0.03 2.4, 0.06 4.79, 0.11 9.42 M0 0 C0.02 2.02, 0.05 4.04, 0.11 9.42 M0.11 9.42 C14.56 16.66, 29.01 23.89, 40.66 29.72 M0.11 9.42 C12 15.37, 23.88 21.32, 40.66 29.72 M40.66 29.72 C45.16 26.53, 49.66 23.35, 52.4 21.41 M40.66 29.72 C44.68 26.87, 48.71 24.02, 52.4 21.41 M52.4 21.41 C52.56 18.52, 52.71 15.63, 52.9 12.3 M52.4 21.41 C52.56 18.52, 52.71 15.64, 52.9 12.3 M52.9 12.3 C37.42 4.86, 21.94 -2.58, 13.58 -6.6 M52.9 12.3 C41.49 6.82, 30.08 1.33, 13.58 -6.6 M13.58 -6.6 C9.53 -4.63, 5.48 -2.66, 0 0 M13.58 -6.6 C8.56 -4.16, 3.54 -1.72, 0 0 M0 0 C0 0, 0 0, 0 0 M0 0 C0 0, 0 0, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(63.54080944815877 113.46213556317102) rotate(0 25.61716812233965 10.191774646231224)"><path d="M0 0 C14.29 7.46, 28.58 14.92, 39.05 20.38 M0 0 C14.51 7.58, 29.03 15.15, 39.05 20.38 M39.05 20.38 C43.76 17.09, 48.48 13.8, 51.23 11.87 M39.05 20.38 C42.67 17.85, 46.3 15.32, 51.23 11.87" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(103.0553975183754 142.54507735562933) rotate(0 -0.08865561764929808 -4.015930478814951)"><path d="M0 0 C-0.04 -1.81, -0.08 -3.63, -0.18 -8.03 M0 0 C-0.07 -3.04, -0.13 -6.08, -0.18 -8.03" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(79.53764980230807 72.30085288378206) rotate(0 18.915880487914865 25.701680357781697)" fill-rule="evenodd"><path d="M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22 M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(66.14246971358051 97.99092341241598) rotate(0 23.935218500353926 1.0837497832572467)" fill-rule="evenodd"><path d="M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0 M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(69.32428789539853 97.54554546718268) rotate(0 20.429769424907594 0.9579109377231276)" fill-rule="evenodd"><path d="M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0" stroke="none" stroke-width="0" fill="#343a40" fill-rule="evenodd"/><path d="M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0 M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(91.59801782898302 131.79700326916313) rotate(0 4.027777777777828 3.101851851851734)" fill-rule="evenodd"><path d="M0 0 L8.02 4.03 L8.06 6.2 L0.15 2.37 L0 0" stroke="none" stroke-width="0" fill="#495057" fill-rule="evenodd"/><path d="M0 0 C2.25 1.13, 4.49 2.26, 8.02 4.03 M0 0 C2.32 1.17, 4.64 2.33, 8.02 4.03 M8.02 4.03 C8.03 4.55, 8.04 5.06, 8.06 6.2 M8.02 4.03 C8.04 4.9, 8.05 5.77, 8.06 6.2 M8.06 6.2 C5.01 4.72, 1.97 3.25, 0.15 2.37 M8.06 6.2 C5.45 4.94, 2.84 3.67, 0.15 2.37 M0.15 2.37 C0.1 1.51, 0.04 0.66, 0 0 M0.15 2.37 C0.11 1.75, 0.07 1.12, 0 0 M0 0 C0 0, 0 0, 0 0 M0 0 C0 0, 0 0, 0 0" stroke="#495057" stroke-width="1" fill="none"/></g></g><mask/><g transform="translate(56.24796497088904 10) rotate(0 48.19995880126953 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">Machine 2</text></g><g stroke-linecap="round" transform="translate(226.24902285513025 72.1474797827733) rotate(0 31.632994168609642 38.232323349387)"><path d="M63.27 38.23 C63.27 40.23, 63.13 42.24, 62.88 44.21 C62.62 46.18, 62.23 48.15, 61.72 50.05 C61.21 51.94, 60.57 53.81, 59.82 55.59 C59.07 57.37, 58.19 59.09, 57.22 60.7 C56.26 62.32, 55.17 63.86, 54 65.27 C52.83 66.68, 51.56 67.99, 50.23 69.16 C48.89 70.33, 47.46 71.39, 45.99 72.3 C44.52 73.2, 42.98 73.98, 41.41 74.59 C39.84 75.21, 38.21 75.68, 36.58 75.99 C34.95 76.31, 33.28 76.46, 31.63 76.46 C29.98 76.46, 28.31 76.31, 26.68 75.99 C25.06 75.68, 23.43 75.21, 21.86 74.59 C20.29 73.98, 18.74 73.2, 17.27 72.3 C15.8 71.39, 14.37 70.33, 13.04 69.16 C11.71 67.99, 10.43 66.68, 9.27 65.27 C8.1 63.86, 7.01 62.32, 6.04 60.7 C5.07 59.09, 4.2 57.37, 3.45 55.59 C2.7 53.81, 2.06 51.94, 1.55 50.05 C1.04 48.15, 0.65 46.18, 0.39 44.21 C0.13 42.24, 0 40.23, 0 38.23 C0 36.24, 0.13 34.22, 0.39 32.25 C0.65 30.28, 1.04 28.31, 1.55 26.42 C2.06 24.52, 2.7 22.65, 3.45 20.88 C4.2 19.1, 5.07 17.37, 6.04 15.76 C7.01 14.15, 8.1 12.61, 9.27 11.2 C10.43 9.79, 11.71 8.47, 13.04 7.3 C14.37 6.13, 15.8 5.07, 17.27 4.17 C18.74 3.26, 20.29 2.49, 21.86 1.87 C23.43 1.26, 25.06 0.78, 26.68 0.47 C28.31 0.16, 29.98 0, 31.63 0 C33.28 0, 34.95 0.16, 36.58 0.47 C38.21 0.78, 39.84 1.26, 41.41 1.87 C42.98 2.49, 44.52 3.26, 45.99 4.17 C47.46 5.07, 48.89 6.13, 50.23 7.3 C51.56 8.47, 52.83 9.79, 54 11.2 C55.17 12.61, 56.26 14.15, 57.22 15.76 C58.19 17.37, 59.07 19.1, 59.82 20.88 C60.57 22.65, 61.21 24.52, 61.72 26.42 C62.23 28.31, 62.62 30.28, 62.88 32.25 C63.13 34.22, 63.2 37.24, 63.27 38.23 C63.33 39.23, 63.33 37.24, 63.27 38.23" stroke="transparent" stroke-width="1" fill="none"/></g><g stroke-linecap="round"><g transform="translate(230.77409971112928 117.48756740027935) rotate(0 26.448638628346117 11.561387201477395)" fill-rule="evenodd"><path d="M0 0 L0.11 9.42 L40.66 29.72 L52.4 21.41 L52.9 12.3 L13.58 -6.6 L0 0" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C0.04 3.35, 0.08 6.71, 0.11 9.42 M0 0 C0.03 2.68, 0.07 5.36, 0.11 9.42 M0.11 9.42 C15.77 17.26, 31.43 25.1, 40.66 29.72 M0.11 9.42 C12.79 15.77, 25.47 22.12, 40.66 29.72 M40.66 29.72 C43.88 27.44, 47.1 25.16, 52.4 21.41 M40.66 29.72 C44.57 26.95, 48.49 24.17, 52.4 21.41 M52.4 21.41 C52.57 18.27, 52.74 15.14, 52.9 12.3 M52.4 21.41 C52.51 19.31, 52.63 17.22, 52.9 12.3 M52.9 12.3 C41.85 6.99, 30.79 1.68, 13.58 -6.6 M52.9 12.3 C37.17 4.74, 21.45 -2.81, 13.58 -6.6 M13.58 -6.6 C9.17 -4.46, 4.77 -2.32, 0 0 M13.58 -6.6 C9.94 -4.83, 6.31 -3.07, 0 0 M0 0 C0 0, 0 0, 0 0 M0 0 C0 0, 0 0, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(231.74080639640096 117.78769370272008) rotate(0 25.61716812233965 10.191774646231224)"><path d="M0 0 C14.97 7.81, 29.93 15.63, 39.05 20.38 M0 0 C14.79 7.72, 29.58 15.44, 39.05 20.38 M39.05 20.38 C41.53 18.65, 44 16.92, 51.23 11.87 M39.05 20.38 C43.71 17.13, 48.37 13.88, 51.23 11.87" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(271.2553944666176 146.8706354951784) rotate(0 -0.08865561764929453 -4.015930478814951)"><path d="M0 0 C-0.07 -3.06, -0.14 -6.13, -0.18 -8.03 M0 0 C-0.05 -2.33, -0.1 -4.66, -0.18 -8.03" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(247.73764675055025 76.62641102333112) rotate(0 18.91588048791487 25.701680357781697)" fill-rule="evenodd"><path d="M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22 M0 0 C2.88 0.38, 11.38 0.18, 17.29 2.31 C23.21 4.44, 31.98 8.35, 35.48 12.76 C38.98 17.17, 38.06 23.88, 38.3 28.78 C38.54 33.67, 38.58 38.44, 36.94 42.15 C35.29 45.86, 31.14 50.29, 28.44 51.04 C25.73 51.79, 25.25 51.83, 20.7 46.63 C16.16 41.42, 4.57 27.04, 1.16 19.81 C-2.25 12.57, 0.4 5.98, 0.25 3.22" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(234.3424666618227 102.31648155196504) rotate(0 23.935218500353926 1.0837497832572467)" fill-rule="evenodd"><path d="M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0" stroke="none" stroke-width="0" fill="#ced4da" fill-rule="evenodd"/><path d="M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0 M0 0 C0.72 2.29, -1.8 9.05, 4.31 13.76 C10.42 18.48, 29.64 27.33, 36.67 28.29 C43.7 29.25, 44.79 25.53, 46.49 19.51 C48.19 13.48, 48.32 -1.82, 46.87 -7.86 C45.42 -13.9, 43.36 -13.7, 37.77 -16.74 C32.18 -19.77, 19.34 -25.34, 13.34 -26.08 C7.35 -26.82, 4.03 -25.5, 1.8 -21.15 C-0.42 -16.81, 0.3 -3.53, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(237.52428484364071 101.87110360673174) rotate(0 20.42976942490759 0.9579109377231347)" fill-rule="evenodd"><path d="M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0" stroke="none" stroke-width="0" fill="#343a40" fill-rule="evenodd"/><path d="M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0 M0 0 C0.6 1.93, -1.26 7.63, 3.62 11.57 C8.51 15.5, 23.29 22.4, 29.29 23.59 C35.3 24.77, 37.9 23.46, 39.65 18.69 C41.39 13.91, 41.09 0.38, 39.77 -5.08 C38.46 -10.53, 36.5 -11.26, 31.74 -14.07 C26.98 -16.87, 16.25 -21.3, 11.21 -21.92 C6.17 -22.54, 3.38 -21.43, 1.52 -17.78 C-0.35 -14.12, 0.25 -2.96, 0 0" stroke="#495057" stroke-width="2" fill="none"/></g></g><mask/><g stroke-linecap="round"><g transform="translate(259.7980147772252 136.1225614087122) rotate(0 4.027777777777828 3.101851851851734)" fill-rule="evenodd"><path d="M0 0 L8.02 4.03 L8.06 6.2 L0.15 2.37 L0 0" stroke="none" stroke-width="0" fill="#495057" fill-rule="evenodd"/><path d="M0 0 C3.17 1.59, 6.33 3.18, 8.02 4.03 M0 0 C2.26 1.14, 4.52 2.27, 8.02 4.03 M8.02 4.03 C8.03 4.49, 8.04 4.95, 8.06 6.2 M8.02 4.03 C8.03 4.75, 8.04 5.48, 8.06 6.2 M8.06 6.2 C5.11 4.77, 2.17 3.34, 0.15 2.37 M8.06 6.2 C6.27 5.34, 4.48 4.47, 0.15 2.37 M0.15 2.37 C0.1 1.62, 0.06 0.88, 0 0 M0.15 2.37 C0.12 1.86, 0.09 1.36, 0 0 M0 0 C0 0, 0 0, 0 0 M0 0 C0 0, 0 0, 0 0" stroke="#495057" stroke-width="1" fill="none"/></g></g><mask/><g transform="translate(210.21207226055628 13.154266354915961) rotate(0 45.46996307373047 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">Machine 1</text></g><g stroke-linecap="round"><g transform="translate(126.11812883722256 111.86064451465549) rotate(0 45.99393274290076 -2.2770457788367224)"><path d="M-0.27 -0.22 C15.3 -1.03, 76.63 -3.79, 92.26 -4.33 M1.78 -1.38 C17.28 -2.02, 75.94 -2.06, 91.19 -2.72" stroke="#1e1e1e" stroke-width="2" fill="none"/></g><g transform="translate(126.11812883722256 111.86064451465549) rotate(0 45.99393274290076 -2.2770457788367224)"><path d="M67.87 6.3 C72.21 4.13, 77.57 4.39, 91.19 -2.72 M67.87 6.3 C75.89 3.05, 85.43 -0.36, 91.19 -2.72" stroke="#1e1e1e" stroke-width="2" fill="none"/></g><g transform="translate(126.11812883722256 111.86064451465549) rotate(0 45.99393274290076 -2.2770457788367224)"><path d="M67.54 -10.8 C72.01 -9.49, 77.45 -5.75, 91.19 -2.72 M67.54 -10.8 C75.71 -7.51, 85.38 -4.39, 91.19 -2.72" stroke="#1e1e1e" stroke-width="2" fill="none"/></g></g><mask/><g transform="translate(57.612050898251596 37.954223630306586) rotate(0 43.43994903564453 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">Attacker</text></g><g transform="translate(220.94529289094592 39.20467591187224) rotate(0 33.499961853027344 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">Target</text></g><g transform="translate(10 182.27890470406192) rotate(0 55.00001525878907 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">id_rsa.pub</text></g><g transform="translate(208.19993591308594 182.97891691109317) rotate(0 82.40003967285156 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">authorized_keys</text></g><g stroke-linecap="round"><g transform="translate(121.99996948242188 210.67892911812442) rotate(0 41.53379654511809 -1.0500918256891794)"><path d="M-1.06 -0.45 C12.78 -0.73, 70.06 -1.37, 84.13 -1.66 M0.58 -1.73 C14.22 -1.84, 69.81 -0.42, 83.46 -0.37" stroke="#1e1e1e" stroke-width="2" fill="none"/></g><g transform="translate(121.99996948242188 210.67892911812442) rotate(0 41.53379654511809 -1.0500918256891794)"><path d="M59.83 7.81 C68.25 5.73, 77.39 1.31, 83.46 -0.37 M59.83 7.81 C65.22 6.4, 70.26 4.71, 83.46 -0.37" stroke="#1e1e1e" stroke-width="2" fill="none"/></g><g transform="translate(121.99996948242188 210.67892911812442) rotate(0 41.53379654511809 -1.0500918256891794)"><path d="M60.11 -9.29 C68.42 -4.74, 77.45 -2.53, 83.46 -0.37 M60.11 -9.29 C65.3 -6.99, 70.29 -4.97, 83.46 -0.37" stroke="#1e1e1e" stroke-width="2" fill="none"/></g></g><mask/><g transform="translate(132.79998779296875 183.07895353218692) rotate(0 35.399993896484375 12.5)"><text x="0" y="17.619999999999997" font-family="Excalifont, Xiaolai, sans-serif, Segoe UI Emoji" font-size="20px" fill="#1e1e1e" text-anchor="start" style="white-space: pre;" direction="ltr" dominant-baseline="alphabetic">Copy</text></g></svg></div>
The process to do this depend on some factors but If the `authorized_keys` file doesn't exist, we can simply copy the entire `id_rsa.pub` and change the name, but if the `authorized_keys` exists could content another authorized keys that we shouldn't delete. In this case we could add our key in the bottom of the `authorized_keys` like below:

 1. On the **computer 2**
 **Copy the content** of the file `/home/USER/.ssh/id_rsa.pub`
```sh
cat /home/USER/.ssh/id_rsa.pub
```
![Pasted image 20241001192909.png](/img/user/attachments/Pasted%20image%2020241001192909.png)
Copy to the clipboard

2. On the **computer 1**
Using `echo` paste the code and add or replace the `authorized_keys`
```shell
echo "ssh-rsa AAAA......gv7v......y2w/oJ0= kali@kali" >> authorized_keys
```
E.g. This is the new `authorized_keys`of the **computer 1**
![Pasted image 20241002070248.png](/img/user/attachments/Pasted%20image%2020241002070248.png)

3. On the **computer 2**
All is done, now to **connect** without password execute:
```shell
ssh USER_OF_COMPUTER_1@IP_COF_COMPUTER_1
```
### Method 2
**Automated** version of the **method 1** but we **need** to introduce the **password** of the computer 1 **at least once**.
1. On the **computer 2**
```shell
ssh-copy-id -i ~/.ssh/id_rsa.pub COMPUTER_1_USERNAME@COMPUTER_1_IP

or

ssh-copy-id COMPUTER_1_USERNAME@COMPUTER_1_IP
```
After this our `id_rsa.pub` will copy on `authorized_keys` of the **computer 1**.
2. On the **computer 2**
All is done, now to **connect** without password execute:
```shell
ssh USER_OF_COMPUTER_1@IP_COF_COMPUTER_1
```
### Method 3
1. Set the **public key of comp1** like "authorized_keys" on its machine (Could not work depending on configuration)
   To **let to** any **connect to comp1** if the **computer2** has the private key of comp1.
```shell
cp id_rsa.pub authorized_keys
```
2. Copy the private key (`id_rsa`) from C1 to C2
3. From C2 connect using that private key file of C1 (`id_rsa`) (the permission should be `600`)
```shell
ssh -i id_rsa user@ipaddres
ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.10.250.21
```
# Port forwarding
`80` port from a victim machine which we don't have access will be available in our machine on `127.0.0.1:33`
```shell
ssh user@"VICTIM_IP" -L 80:127.0.0.1:33
```
# Transfer files 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- **S**ecure **C**opy **P**rotocol
- **Transferring Files** between two computers using the **[[Notes/SSH\|SSH]]** protocol 
- Provide both authentication and encryption.
- [[MITM\|MITM]]

Working on a model of SOURCE and DESTINATION, SCP allows you to:
- Copy files & directories from your current system to a remote system
- Copy files & directories from a remote system to your current system

## Send a file
Send file1.txt from my machine to the target machine with the name file2.txt
```shell
scp file1.txt <target_username>@<target_IP>:/home/ubuntu/file2.txt
```
## Download a file
Get the documents.txt from the target machine to my machine. (To my current directory `.`)
```shell
scp <target_username>@<target_IP>:/home/ubuntu/documents.txt .
```
Change the name to notes.txt
```shell
scp <target_username>@<target_IP>:/home/ubuntu/documents.txt notes.txt
```
Examples to get all files from a folder
```shell
scp <target_username>@<target_IP>:/home/ubuntu/* .
```
```shell
scp <target_username>@<target_IP>:/home/ubuntu/* ~
```




</div></div>

# Math
- The key variables that you need to know about for RSA in CTFs are p, q, m, n, e, d, and c.
- “p” and “q” are large prime numbers, “n” is the product of p and q.
- The public key is n and e, the private key is n and d.
- “m” is used to represent the message (in plaintext) and “c” represents the ciphertext (encrypted text).
- https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/

# Tools RSA CTFs
https://github.com/Ganapati/RsaCtfTool
https://github.com/ius/rsatool
# Errors
- If you get an error saying `Unable to negotiate with <IP> port 22: no matching how to key type found. Their offer: ssh-rsa, ssh-dss` 
- this is because OpenSSH have deprecated ssh-rsa. 
- Add `-oHostKeyAlgorithms=+ssh-rsa` to your command to connect.
# Enumeration
Get version and search in [launchpad](https://launchpad.net/ubuntu).
```sh
sudo nmap -sCV -p22 127.0.0.1
```
PORT   STATE SERVICE VERSION
`22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)`
https://launchpad.net/ubuntu
OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
## Using Metasploit 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## [[Notes/SSH\|SSH]] Enum
```shell
auxiliary/scanner/ssh/ssh_version
auxiliary/scanner/ssh/ssh_login # Brute force
```

</div></div>

# Exploitation
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">

<div class="markdown-embed-title">

# John The Ripper

</div>


## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py
```sh
wget https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py
```
Note that if you don't have ssh2john installed, you can use ssh2john.py, which is located in the /opt/john/ssh2john.py. If you're doing this, replace the `ssh2john` command with `python3 /opt/ssh2john.py` or on Kali, `python /usr/share/john/ssh2john.py`.
```sh
ssh2john [id_rsa private key file] > [output file]
```

ssh2john - Invokes the ssh2john tool  

`[id_rsa private key file]` - The path to the id_rsa file you wish to get the hash of

`>` - This is the output director, we're using this to send the output from this file to the...  

`[output file]` - This is the file that will store the output from

**Example Usage**
ssh2john id_rsa > id_rsa_hash.txt

**Cracking**

``` bash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt
```



</div></div>


</div></div>

## Exploit `libssh`
- `libssh` V.0.6.0 - 0.8-0 is vulnerable to an authentication bypass vulnerability in the `libssh` server code that can be exploited to execute commands on the target server.

<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## [[Notes/SSH\|SSH]] Exploitation
```shell
use auxiliary/scanner/ssh/libssh_auth_bypass
set SPAWN_PTY true
run
```

</div></div>

# 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- In the admin shell, go to the `/etc/ssh/sshd_config` file and edit it using your favourite text editor (remember to use sudo). 
- Find the line that says `#PasswordAuthentication yes` and change it to `PasswordAuthentication no` (remove the # sign and change yes to no).

- Next, find the line that says `Include /etc/ssh/sshd_config.d/*.conf` and change it to `#Include /etc/ssh/sshd_config.d/*.conf` (add a # sign at the beginning). 
- Save the file, then enter the command `sudo systemctl restart ssh`.

</div></div>



