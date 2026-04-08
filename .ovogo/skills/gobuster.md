---
name: gobuster
description: gobuster — 目录/DNS/VHost 枚举工具
---

你是 gobuster 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# gobuster — 目录/DNS/VHost 枚举工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 命令 | `gobuster` |
| 路径 | 系统 PATH 直接可用 |
| 适用场景 | 目录枚举、DNS 子域名枚举、虚拟主机发现、S3 Bucket 枚举 |
| 字典目录 | `/opt/wordlists/seclists/` |

---

## 运行模式

| 模式 | 命令 | 说明 |
|------|------|------|
| `dir` | `gobuster dir` | 目录/文件枚举 |
| `dns` | `gobuster dns` | DNS 子域名枚举 |
| `vhost` | `gobuster vhost` | 虚拟主机枚举 |
| `s3` | `gobuster s3` | AWS S3 Bucket 枚举 |
| `fuzz` | `gobuster fuzz` | 模糊测试 |

---

## 核心参数速查（通用）

| 参数 | 说明 |
|------|------|
| `-u <url>` | 目标 URL |
| `-w <wordlist>` | 字典文件 |
| `-t <num>` | 并发线程数（默认 10） |
| `-o <file>` | 输出到文件 |
| `-q` | 安静模式（不显示进度） |
| `-v` | 详细模式 |
| `--delay <ms>` | 请求间延迟 |
| `--timeout <sec>` | 超时秒数 |
| `-r` | 跟随重定向 |
| `-k` | 跳过 TLS 证书验证 |
| `-H <header>` | 自定义请求头 |
| `-c <cookie>` | 指定 Cookie |
| `-U <user>` | HTTP 基础认证用户名 |
| `-P <pass>` | HTTP 基础认证密码 |
| `--proxy <url>` | 使用代理 |
| `-z` | 不显示进度条 |

### dir 模式专用参数

| 参数 | 说明 |
|------|------|
| `-x <ext>` | 追加文件扩展名（`,`分隔） |
| `-s <codes>` | 匹配状态码（默认 `200,204,301,302,307,401,403,405,500`） |
| `-b <codes>` | 过滤状态码（黑名单） |
| `-l` | 显示响应长度 |
| `-e` | 显示完整 URL |
| `--exclude-length <len>` | 排除指定响应长度 |
| `--no-tls-validation` | 跳过 TLS 验证 |

### dns 模式专用参数

| 参数 | 说明 |
|------|------|
| `-d <domain>` | 目标域名 |
| `-r <resolver>` | 指定 DNS 服务器 |
| `-i` | 显示 IP 地址 |
| `--wildcard` | 强制继续（即使存在泛解析） |

---

## 典型使用场景

### 1. 基础目录枚举
```bash
gobuster dir \
    -u https://target.com \
    -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
    -t 50
```

### 2. 带扩展名枚举（PHP 站点）
```bash
gobuster dir \
    -u https://target.com \
    -w /opt/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt \
    -x php,html,txt,bak,old,zip,tar.gz \
    -t 50
```

### 3. 大字典深度枚举
```bash
gobuster dir \
    -u https://target.com \
    -w /opt/wordlists/seclists/Discovery/Web-Content/big.txt \
    -x php,html,js,txt \
    -t 100 -o gobuster_results.txt
```

### 4. 过滤特定状态码
```bash
gobuster dir \
    -u https://target.com \
    -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
    -b 404,403 -t 50 -l
```

### 5. 带认证的目录枚举
```bash
gobuster dir \
    -u https://target.com \
    -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
    -c "session=YOUR_SESSION_TOKEN" \
    -H "Authorization: Bearer TOKEN" \
    -t 30
```

### 6. DNS 子域名枚举
```bash
gobuster dns \
    -d target.com \
    -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -t 50
```

### 7. DNS 枚举（显示 IP + 指定 DNS 服务器）
```bash
gobuster dns \
    -d target.com \
    -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -r 8.8.8.8 -i -t 50
```

### 8. 虚拟主机发现
```bash
gobuster vhost \
    -u https://target.com \
    -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -t 50 --append-domain
```

### 9. 扫描特定目录路径
```bash
gobuster dir \
    -u https://target.com/wp-content/plugins/ \
    -w /opt/wordlists/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt \
    -t 30
```

### 10. 速率限制（规避 WAF）
```bash
gobuster dir \
    -u https://target.com \
    -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
    -t 10 --delay 500ms \
    --random-agent
```

### 11. API 端点枚举
```bash
gobuster dir \
    -u https://target.com/api \
    -w /opt/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    -H "Content-Type: application/json" \
    -s 200,201,204,301,400,401,403 \
    -t 30
```

---

## 常用字典路径

```bash
# 通用 Web 目录
/opt/wordlists/seclists/Discovery/Web-Content/common.txt
/opt/wordlists/seclists/Discovery/Web-Content/big.txt
/opt/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt
/opt/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt
/opt/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# 子域名
/opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/opt/wordlists/subdomains-top5000.txt

# CMS 专用
/opt/wordlists/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt
/opt/wordlists/seclists/Discovery/Web-Content/CMS/joomla.txt
```

---

## gobuster vs ffuf 选择

| 场景 | 推荐 |
|------|------|
| 简单目录枚举 | gobuster（语法简单） |
| 复杂过滤条件 | ffuf（更灵活的过滤） |
| POST 参数 Fuzz | ffuf（gobuster 不支持） |
| 多字典 Fuzz | ffuf（支持多个 -w） |
| 响应内容匹配 | ffuf（-mr 正则） |
| 子域名枚举 | 两者均可 |
