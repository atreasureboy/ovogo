---
name: httpx
description: httpx — HTTP 探测与指纹识别工具
---

你是 httpx 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# httpx — HTTP 探测与指纹识别工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 二进制路径 | `/root/go/bin/httpx` 或 `/usr/local/bin/httpx` |
| 项目来源 | ProjectDiscovery |
| 适用场景 | HTTP 存活探测、技术栈指纹、标题/状态码收集、Web 资产普查 |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-u <url>` | 扫描单个 URL |
| `-l <file>` | 从文件读取目标列表 |
| `-sc` / `-status-code` | 显示响应状态码 |
| `-title` | 显示页面标题 |
| `-td` / `-tech-detect` | 显示技术栈信息 |
| `-server` / `-web-server` | 显示服务器信息 |
| `-cl` / `-content-length` | 显示响应内容长度 |
| `-ct` / `-content-type` | 显示 Content-Type |
| `-ip` | 显示解析到的 IP |
| `-cdn` | 显示 CDN 信息 |
| `-cname` | 显示 CNAME 记录 |
| `-location` | 显示重定向位置 |
| `-favicon` | 显示 favicon hash（用于 Shodan 关联） |
| `-hash <algo>` | 显示响应内容哈希 |
| `-p <ports>` | 指定探测端口 |
| `-ports 80,443,8080` | 多端口探测 |
| `-fr` / `-follow-redirects` | 跟随重定向 |
| `-silent` | 静默模式，只输出存活 URL |
| `-t <num>` | 并发线程数（默认 50） |
| `-timeout <sec>` | 超时秒数 |
| `-H <header>` | 自定义请求头 |
| `-o <file>` | 输出到文件 |
| `-json` | JSON 格式输出 |
| `-mc <codes>` | 匹配指定状态码 |
| `-fc <codes>` | 过滤指定状态码 |
| `-ml <size>` | 匹配响应长度 |
| `-ms <string>` | 匹配响应内容字符串 |
| `-probe` | 显示协议（http/https） |

---

## 典型使用场景

### 1. 基础探测（存活 + 状态码 + 标题 + 技术栈）
```bash
# 输出需要重定向 stderr 到 stdout
echo "https://target.com" | httpx -sc -title -td -server 2>&1

# 或使用管道方式
echo "target.com" | httpx -sc -title -td -server -silent
```

### 2. 多目标批量探测
```bash
cat hosts.txt | httpx -sc -title -td -server -silent -o live_hosts.txt
```

### 3. 子域名存活检测 + 技术栈
```bash
subfinder -d target.com -silent | \
  httpx -sc -title -td -server -ip -cdn -silent | \
  tee web_assets.txt
```

### 4. 多端口探测
```bash
cat ips.txt | httpx -p 80,443,8080,8443,8888,9090,3000,5000 -sc -title -silent
```

### 5. 仅获取存活 URL（用于后续工具输入）
```bash
cat subs.txt | httpx -silent > live_urls.txt
```

### 6. 过滤状态码（排除 404/403）
```bash
cat urls.txt | httpx -fc 404,403 -sc -title -silent
```

### 7. 只看成功响应（200）
```bash
cat urls.txt | httpx -mc 200 -sc -title -silent
```

### 8. 获取 IP 地址（资产普查）
```bash
cat subs.txt | httpx -ip -silent | awk '{print $2}' | sort -u
```

### 9. Favicon Hash（关联 Shodan 资产）
```bash
echo "https://target.com" | httpx -favicon -silent
# 然后在 Shodan 搜索: http.favicon.hash:<hash>
```

### 10. 带自定义头请求（绕过访问控制）
```bash
cat urls.txt | httpx -H "X-Forwarded-For: 127.0.0.1" \
                     -H "X-Real-IP: 127.0.0.1" \
                     -sc -title -silent
```

### 11. JSON 格式输出
```bash
cat urls.txt | httpx -json -silent | jq -r '[.url, .status_code, .title] | @tsv'
```

### 12. 完整侦察流水线
```bash
subfinder -d target.com -silent | \
  dnsx -resp-only -a -silent | \
  httpx -sc -title -td -server -ip -cdn -silent | \
  tee full_recon.txt
```

---

## 输出格式说明

```
https://target.com [200] [Apache/2.4.41] [WordPress,jQuery] [Title Here]
│                   │     │               │                   │
URL               状态码  服务器信息      技术栈              页面标题
```

---

## 常见问题

**问：为什么看不到输出？**
答：httpx 默认把进度信息输出到 stderr，需要加 `2>&1` 或使用 `-silent` 参数

```bash
# 方式一：重定向 stderr
echo "https://target.com" | httpx -sc -title -td 2>&1

# 方式二：静默模式（只输出结果）
echo "https://target.com" | httpx -sc -title -td -silent
```

**问：如何只看有某个关键词的目标？**
```bash
cat urls.txt | httpx -title -silent | grep -i "admin\|login\|dashboard"
```

**问：如何探测内网资产？**
```bash
# 扫描内网 C 段
for i in $(seq 1 254); do echo "192.168.1.$i"; done | \
  httpx -p 80,443,8080,8443 -sc -title -silent
```

---

## 技术栈识别范围

httpx 可识别的技术包括：
- **服务器**：Apache、Nginx、IIS、Tomcat、Jetty 等
- **框架**：WordPress、Drupal、Joomla、Laravel、Django、Spring 等
- **语言**：PHP、Java、Python、ASP.NET 等
- **CDN**：Cloudflare、Akamai、Fastly 等
- **前端**：jQuery、Vue.js、React、Bootstrap 等
