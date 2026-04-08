---
name: nuclei
description: nuclei — 模板化漏洞扫描引擎
---

你是 nuclei 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# nuclei — 模板化漏洞扫描引擎

## 基本信息

| 项目 | 内容 |
|------|------|
| 二进制路径 | `/root/go/bin/nuclei` |
| 模板目录 | `/root/nuclei-templates/` |
| 项目来源 | ProjectDiscovery |
| 适用场景 | 漏洞扫描、CVE 检测、安全合规检查、指纹识别 |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-u <url>` | 扫描单个目标 URL |
| `-l <file>` | 从文件读取多个目标 |
| `-t <path>` | 指定模板路径（文件/目录） |
| `-tags <tag>` | 按标签筛选模板（如 `cve,rce,sqli`） |
| `-severity <level>` | 按严重等级过滤（`info,low,medium,high,critical`）⚠️ 全量扫描禁止使用 |
| `-o <file>` | 输出结果到文件 |
| `-silent` | 静默模式，只输出发现 |
| `-timeout <sec>` | 扫描超时（全量扫描建议 3600） |
| `-c <num>` | 并发模板数（默认 25） |
| `-rate-limit <num>` | 每秒请求数限制 |
| `-retries <num>` | 请求失败重试次数 |
| `-proxy <url>` | 使用代理 |
| `-json` | JSON 格式输出 |
| `-stats` | 显示实时统计信息 |
| `-update-templates` | 更新模板库 |
| `-nc` | 不使用颜色输出 |
| `-H <header>` | 添加自定义 HTTP 头 |
| `-var key=val` | 模板变量注入 |

---

## 典型使用场景

### 1. 全量扫描（推荐 — 捕获所有级别）
```bash
# ✅ 正确：不加 -severity，扫描全部模板
nuclei -u https://target.com -t /root/nuclei-templates/ -silent -timeout 3600 -o full_scan.txt
```

### 2. 按 CVE 标签扫描
```bash
nuclei -u https://target.com -t /root/nuclei-templates/ -tags cve -silent -o cve_results.txt
```

### 3. WordPress 专项扫描
```bash
# 技术识别
nuclei -u https://target.com -t /root/nuclei-templates/http/technologies/wordpress/ -silent

# WordPress 漏洞扫描
nuclei -u https://target.com -t /root/nuclei-templates/http/vulnerabilities/wordpress/ -silent
```

### 4. 多目标批量扫描
```bash
nuclei -l urls.txt -t /root/nuclei-templates/ -silent -timeout 1800 -o batch_results.txt
```

### 5. 子域名全覆盖扫描
```bash
for subdomain in $(cat subs.txt); do
    echo "[*] Scanning: $subdomain"
    nuclei -u "https://$subdomain" -t /root/nuclei-templates/ -silent \
           -timeout 1800 -o "${subdomain//\//_}_vulns.txt" 2>/dev/null
done
```

### 6. 指定特定漏洞类型
```bash
# RCE 扫描
nuclei -u https://target.com -t /root/nuclei-templates/ -tags rce -silent

# SQL 注入
nuclei -u https://target.com -t /root/nuclei-templates/ -tags sqli -silent

# XSS
nuclei -u https://target.com -t /root/nuclei-templates/ -tags xss -silent

# SSRF
nuclei -u https://target.com -t /root/nuclei-templates/ -tags ssrf -silent

# 信息泄露
nuclei -u https://target.com -t /root/nuclei-templates/ -tags exposure -silent
```

### 7. 加速扫描（调整并发）
```bash
nuclei -u https://target.com -t /root/nuclei-templates/ \
       -c 50 -rate-limit 200 -silent -timeout 3600
```

### 8. 与 httpx 联动（管道扫描）
```bash
cat hosts.txt | httpx -silent | nuclei -t /root/nuclei-templates/ -silent -o results.txt
```

### 9. JSON 格式输出（便于解析）
```bash
nuclei -u https://target.com -t /root/nuclei-templates/ -json -silent | \
  jq -r '[.info.severity, .info.name, .matched-at] | @tsv'
```

### 10. 添加自定义请求头（绕过 WAF / 认证）
```bash
nuclei -u https://target.com -t /root/nuclei-templates/ \
       -H "X-Forwarded-For: 127.0.0.1" \
       -H "Authorization: Bearer YOUR_TOKEN" \
       -silent
```

---

## 模板目录结构

```
/root/nuclei-templates/
├── http/
│   ├── vulnerabilities/          # 漏洞检测
│   │   ├── wordpress/            # WordPress 漏洞
│   │   ├── apache/               # Apache 漏洞
│   │   ├── nginx/                # Nginx 漏洞
│   │   └── ...
│   ├── technologies/             # 技术指纹识别
│   │   ├── wordpress/
│   │   └── ...
│   ├── exposures/                # 敏感信息暴露
│   ├── misconfiguration/         # 错误配置
│   └── cves/                     # CVE 模板
├── network/                      # 网络层模板
├── dns/                          # DNS 模板
└── ssl/                          # SSL/TLS 模板
```

---

## 模板更新

```bash
# 更新到最新模板
nuclei -update-templates

# 或手动 git pull
cd /root/nuclei-templates && git pull

# 查看模板数量
ls /root/nuclei-templates/http/vulnerabilities/ | wc -l
```

---

## 结果分析

```bash
# 按严重级别统计
grep -c '"severity":"critical"' results.json
grep -c '"severity":"high"' results.json

# 提取所有发现的 URL
cat results.txt | grep -oP 'https?://[^\s]+'

# 提取 CVE 编号
cat results.txt | grep -oP 'CVE-\d{4}-\d+'
```

---

## ⚠️ 重要原则

- **禁止使用 `-severity` 过滤**：`info/low` 级别的信息泄露同样有价值
- **全量模板优先**：始终使用 `-t /root/nuclei-templates/` 而非子目录
- **超时要足够长**：全量扫描至少设置 `-timeout 3600`
- **多资产覆盖**：主域名和每个子域名都需要独立扫描
