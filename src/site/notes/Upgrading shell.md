---
{"dg-publish":true,"permalink":"/upgrading-shell/"}
---

Try to get an interactive shell
```shell
/bin/bash -i
/bin/sh -i
```
Try to get a root bash
```shell
sudo -u root /bin/bash
```
List shells available
```shell
chsh -l
cat /etc/shells
```
# Technique 1: 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



## Upgrading shell
1. Uses Python to spawn a better featured bash shell; #flashcard 
```sh
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
<!--ID: 1728610890928-->

some targets may need replace `python` with `python2` or `python3`

2. access to term commands such as `clear`. #flashcard 
```sh
export TERM=xterm
```
<!--ID: 1728611027052-->

3. Background the shell using `Ctrl + Z` and then. #flashcard
```sh
stty raw -echo; fg
```
<!--ID: 1728611066502-->

This does two things: 
- First, it **turns off our own terminal echo** (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes).
- then **foregrounds the shell,** thus completing the process.
- Note that **if the shell dies,** any input in your own terminal will **not be visible** (as a result of having disabled terminal echo). To **fix this, type** `reset` and press enter.

</div></div>

# Technique 2: 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- Rlwrap is a program which, in simple terms, gives us **access to history**, **tab autocompletion** and the **arrow keys** immediately upon receiving a shell.

Launch  an r*** listener #flashcard 
``` sh
rlwrap nc -lnvp <port>
```
<!--ID: 1729624905744-->

- particularly useful when dealing with Windows shells
- On Linux target, it's possible to completely stabilise,
- using Ctrl + Z.
```sh
stty raw -echo; fg
```

</div></div>

# Technique 3: [[socat\|Socat]]
# Technique 4: [[Notes/SSH\|SSH]]
# Extra
## 
<div class="transclusion internal-embed is-loaded"><div class="markdown-embed">



- On my machine to get info from stty
```sh
stty -a
```
- Next, in your reverse/bind shell, type in:
`stty rows <number>`  
and
`stty cols <number>`


</div></div>
