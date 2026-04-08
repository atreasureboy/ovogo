---
name: nmap
description: nmap — 网络端口扫描与服务识别
---

你是 nmap 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# nmap — 网络端口扫描与服务识别

## 基本信息

| 项目 | 内容 |
|------|------|
| 命令 | `nmap` |
| 路径 | `/usr/bin/nmap`（系统自带） |
| 适用场景 | 端口扫描、服务版本识别、OS 识别、漏洞脚本检测 |

---

## 核心参数速查

### 扫描方式

| 参数 | 说明 |
|------|------|
| `-sS` | TCP SYN 扫描（半开扫描，需 root，最常用） |
| `-sT` | TCP Connect 扫描（不需要 root） |
| `-sU` | UDP 扫描 |
| `-sV` | 服务版本探测 |
| `-sC` | 运行默认 NSE 脚本 |
| `-A` | 全面扫描（-sV -sC -O --traceroute） |
| `-O` | 操作系统识别 |
| `-Pn` | 跳过主机发现（假设所有主机在线） |
| `-n` | 不进行 DNS 解析（加速） |
| `-p <ports>` | 指定端口（`-p 80,443`、`-p 1-1000`、`-p-` 全端口） |
| `--top-ports <num>` | 扫描最常见的 N 个端口 |
| `--open` | 只显示开放端口 |

### 速度与性能

| 参数 | 说明 |
|------|------|
| `-T0` 到 `-T5` | 速度模板（0=最慢最隐蔽，5=最快最激进） |
| `-T4` | 推荐速度（快速但稳定） |
| `--min-rate <num>` | 最小每秒发包数 |
| `--max-rate <num>` | 最大每秒发包数 |
| `--min-parallelism <num>` | 最小并行探测数 |

### 输出格式

| 参数 | 说明 |
|------|------|
| `-oN <file>` | 普通文本格式 |
| `-oX <file>` | XML 格式 |
| `-oG <file>` | Grepable 格式 |
| `-oA <prefix>` | 同时输出所有格式 |
| `-v` | 详细输出 |
| `-vv` | 更详细输出 |

### NSE 脚本

| 参数 | 说明 |
|------|------|
| `--script <name>` | 运行指定脚本 |
| `--script <category>` | 运行某类脚本 |
| `--script-args <args>` | 传递脚本参数 |
| `--script-updatedb` | 更新脚本数据库 |

---

## 典型使用场景

### 1. 快速 Top1000 端口扫描
```bash
nmap -Pn -n -T4 --top-ports 1000 target.com -oN quick_scan.txt
```

### 2. 全端口扫描（高速）
```bash
nmap -Pn -n -T4 --min-rate 5000 -p- target.com -oN full_ports.txt
```

### 3. 服务版本 + 默认脚本（标准扫描）
```bash
nmap -sV -sC -T4 -p 22,80,443,3306,8080 target.com -oA service_scan
```

### 4. 全面扫描（包含 OS 识别）
```bash
nmap -A -T4 -p- target.com -oA full_scan
```

### 5. 针对已知开放端口做深度扫描
```bash
# 第一步：快速找到开放端口
nmap -Pn -n -T4 --min-rate 5000 -p- target.com | grep open | awk -F'/' '{print $1}' | tr '\n' ','
# 第二步：对开放端口深度扫描
nmap -sV -sC -p 22,80,443,8080 target.com -oA deep_scan
```

### 6. UDP 扫描（常见 UDP 服务）
```bash
nmap -sU --top-ports 100 -T4 target.com
```

### 7. 子网段扫描（内网）
```bash
nmap -sV --open -T4 192.168.1.0/24 -oA internal_scan
```

### 8. 漏洞扫描脚本
```bash
# 运行所有漏洞脚本
nmap --script vuln target.com

# SMB 漏洞（EternalBlue等）
nmap --script smb-vuln* -p 445 target.com

# HTTP 相关漏洞
nmap --script http-vuln* -p 80,443 target.com
```

### 9. 暴力破解脚本
```bash
# SSH 弱口令
nmap --script ssh-brute -p 22 target.com \
     --script-args userdb=users.txt,passdb=/opt/wordlists/rockyou.txt

# FTP 弱口令
nmap --script ftp-brute -p 21 target.com

# HTTP 基础认证
nmap --script http-brute -p 80 target.com
```

### 10. 服务特定脚本
```bash
# SMB 枚举
nmap --script smb-enum-shares,smb-enum-users -p 445 target.com

# MySQL 枚举
nmap --script mysql-info,mysql-enum -p 3306 target.com

# HTTP 标题和方法
nmap --script http-title,http-methods -p 80,443 target.com

# SSL 证书信息
nmap --script ssl-cert,ssl-enum-ciphers -p 443 target.com
```

### 11. 规避检测（慢速隐蔽扫描）
```bash
nmap -sS -T1 -f --data-length 25 --randomize-hosts target.com
```

### 12. 结合 masscan（先快速发现，再精细识别）
```bash
# masscan 快速找开放端口
masscan -p1-65535 target.com --rate=10000 -oG masscan_result.txt
# 提取端口
grep open masscan_result.txt | awk -F' ' '{print $4}' | awk -F'/' '{print $1}' | sort -u | tr '\n' ','
# nmap 精细识别
nmap -sV -sC -p <上述端口> target.com -oA nmap_detail
```

---

## 常用脚本分类

| 类别 | 说明 | 示例脚本 |
|------|------|---------|
| `auth` | 认证/暴破 | `ssh-brute`, `ftp-brute` |
| `vuln` | 漏洞检测 | `smb-vuln-ms17-010`, `http-shellshock` |
| `discovery` | 信息发现 | `dns-brute`, `http-enum` |
| `exploit` | 漏洞利用 | 谨慎使用 |
| `brute` | 暴力破解 | 各服务暴破脚本 |
| `safe` | 安全无损脚本 | 绝大多数 discovery 类 |

---

## 输出解读

```
PORT    STATE  SERVICE  VERSION
22/tcp  open   ssh      OpenSSH 8.2p1 Ubuntu
│        │      │        │
端口   状态   服务名   版本信息
```

**STATE 说明：**
- `open` — 端口开放，服务正在监听
- `closed` — 端口关闭，但主机在线
- `filtered` — 防火墙过滤，无法判断
- `open|filtered` — 无法区分（常见于 UDP 扫描）
