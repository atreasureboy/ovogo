---
name: ffuf
description: ffuf — Web 模糊测试与目录枚举工具
---

你是 ffuf 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# ffuf — Web 模糊测试与目录枚举工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 二进制路径 | `/root/go/bin/ffuf` |
| 适用场景 | 目录枚举、文件发现、参数 Fuzz、子域名枚举、虚拟主机发现 |
| 字典目录 | `/opt/wordlists/seclists/` |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-u <url>` | 目标 URL，用 `FUZZ` 标记注入位置 |
| `-w <wordlist>` | 指定字典文件（可用 `:KEYWORD` 指定关键字） |
| `-c` | 彩色输出 |
| `-v` | 详细输出（显示完整 URL） |
| `-o <file>` | 输出到文件 |
| `-of <format>` | 输出格式（`json`/`ejson`/`html`/`md`/`csv`/`all`） |
| `-t <num>` | 并发线程数（默认 40，64核推荐 **200**） |
| `-p <delay>` | 请求间隔（秒，支持范围 `0.1-2.0`） |
| `-rate <num>` | 每秒请求速率限制 |
| `-timeout <sec>` | 请求超时秒数 |
| `-H <header>` | 自定义请求头 |
| `-b <cookie>` | 指定 Cookie |
| `-X <method>` | HTTP 方法（GET/POST/PUT等） |
| `-d <data>` | POST 请求数据 |
| `-mc <codes>` | 匹配状态码（默认 `200,204,301,302,307,401,403,405,500`） |
| `-fc <codes>` | 过滤状态码 |
| `-ms <size>` | 匹配响应大小 |
| `-fs <size>` | 过滤响应大小 |
| `-mr <regex>` | 匹配响应内容（正则） |
| `-fr <regex>` | 过滤响应内容（正则） |
| `-ml <lines>` | 匹配响应行数 |
| `-fl <lines>` | 过滤响应行数 |
| `-mw <words>` | 匹配响应字数 |
| `-fw <words>` | 过滤响应字数 |
| `-ac` | 自动过滤相似响应（减少误报） |
| `-e <ext>` | 追加文件扩展名（如 `.php,.html,.txt`） |
| `-recursion` | 递归枚举 |
| `-recursion-depth <num>` | 递归深度 |
| `-maxtime <sec>` | 最大运行时间 |
| `-silent` | 静默模式 |

---

## 典型使用场景

### 1. 基础目录枚举（高并发）
```bash
/root/go/bin/ffuf -u https://target.com/FUZZ \
     -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
     -t 200 -c -v
```

### 2. 带扩展名的文件枚举
```bash
ffuf -u https://target.com/FUZZ \
     -w /opt/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt \
     -e .php,.html,.txt,.bak,.old,.zip \
     -c -v
```

### 3. 过滤无效响应（排除 404 和特定大小）
```bash
ffuf -u https://target.com/FUZZ \
     -w /opt/wordlists/seclists/Discovery/Web-Content/big.txt \
     -fc 404 -fs 1234 \
     -c -v -o dir_results.json -of json
```

### 4. 自动过滤相似响应（减少噪音）
```bash
ffuf -u https://target.com/FUZZ \
     -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
     -ac -c -v
```

### 5. POST 参数 Fuzz
```bash
ffuf -u https://target.com/login \
     -w /opt/wordlists/seclists/Usernames/Names/names.txt \
     -X POST \
     -d "username=FUZZ&password=test123" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -fc 200 -c
```

### 6. GET 参数值 Fuzz
```bash
ffuf -u "https://target.com/page?id=FUZZ" \
     -w /opt/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt \
     -c -v -fs 4242
```

### 7. 多参数 Fuzz（多个 FUZZ 关键字）
```bash
ffuf -u "https://target.com/?user=W1&pass=W2" \
     -w /opt/wordlists/usernames.txt:W1 \
     -w /opt/wordlists/passwords.txt:W2 \
     -fc 401 -c
```

### 8. 子域名枚举
```bash
ffuf -u https://FUZZ.target.com/ \
     -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.target.com" \
     -fc 404 -c
```

### 9. 虚拟主机发现（Host Header Fuzz）
```bash
ffuf -u https://target.com/ \
     -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -H "Host: FUZZ.target.com" \
     -fs <default_size> -c
```

### 10. API 端点枚举
```bash
ffuf -u https://target.com/api/FUZZ \
     -w /opt/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -mc 200,201,204,400,405 -c
```

### 11. 递归目录枚举
```bash
ffuf -u https://target.com/FUZZ \
     -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
     -recursion -recursion-depth 3 \
     -c -v -o recursive_results.json -of json
```

### 12. 速率限制（绕过 WAF / 避免封 IP）
```bash
ffuf -u https://target.com/FUZZ \
     -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
     -rate 50 -t 10 -p 0.1 \
     -c -v
```

### 13. 带认证的枚举
```bash
ffuf -u https://target.com/FUZZ \
     -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
     -b "session=YOUR_SESSION_ID; auth=token" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -c
```

---

## 常用字典路径速查

```bash
# 通用目录枚举
/opt/wordlists/seclists/Discovery/Web-Content/common.txt
/opt/wordlists/seclists/Discovery/Web-Content/big.txt
/opt/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt
/opt/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt

# 子域名
/opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/opt/wordlists/subdomains-top5000.txt

# SQL 注入
/opt/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt

# XSS Payload
/opt/wordlists/seclists/Fuzzing/XSS/XSS-Jhaddix.txt

# 用户名
/opt/wordlists/seclists/Usernames/Names/names.txt

# 密码
/opt/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt
/opt/wordlists/rockyou.txt
```

---

## 输出格式解读

```
:: Progress: [4681/4681] :: Job [1/1] :: 362 req/sec :: Duration: [0:00:12] :: Errors: 0 ::

GET    200     [    10 Words,    35 Lines,    248 Chars]  * FUZZ: admin
GET    301     [     0 Words,     0 Lines,       0 Chars]  * FUZZ: uploads
```

- 第一列：HTTP 方法
- 第二列：状态码
- 中间：字词数/行数/字节数
- 最后：发现的路径
