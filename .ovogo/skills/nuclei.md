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
| 二进制路径 | `nuclei` |
| 模板目录 | `~/nuclei-templates/` |
| 项目来源 | ProjectDiscovery |
| 适用场景 | 漏洞扫描、CVE 检测、安全合规检查、指纹识别 |

---

## 64核服务器推荐并发配置

```bash
# 单目标全量扫描（高性能）
NUCLEI=nuclei
$NUCLEI -u TARGET \
  -t ~/nuclei-templates/ \
  -c 100 -bs 25 -rl 500 \
  -timeout 3600 -silent \
  -o SESSION/nuclei_full.txt

# 多目标批量扫描（高性能）
$NUCLEI -l SESSION/web_assets.txt \
  -t ~/nuclei-templates/ \
  -c 100 -bs 50 -rl 500 \
  -timeout 3600 -silent \
  -o SESSION/nuclei_batch.txt
```

| 参数 | 默认值 | 64核推荐 | 说明 |
|------|--------|---------|------|
| `-c` | 25 | **100** | 模板并发数（同时跑多少模板） |
| `-bs` | 25 | **50** | 目标并发数（同时扫多少主机） |
| `-rl` | 150 | **500** | 每秒最大请求数（RPS） |
| `-timeout` | 10 | **3600** | 单模板超时（秒） |

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-u <url>` | 扫描单个目标 URL |
| `-l <file>` | 从文件读取多个目标 |
| `-t <path>` | 指定模板路径（文件/目录） |
| `-id <cve>` | 按 CVE ID 精准扫描（推荐替代相对路径）|
| `-tags <tag>` | 按标签筛选模板（如 `cve,rce,sqli`） |
| `-severity <level>` | 按严重等级过滤 ⚠️ 全量扫描禁止使用 |
| `-o <file>` | 输出结果到文件 |
| `-silent` | 静默模式，只输出发现 |
| `-c <num>` | 模板并发数（推荐 100） |
| `-bs <num>` | 目标并发数（推荐 50） |
| `-rl <num>` | 每秒请求数限制（推荐 500） |
| `-timeout <sec>` | 单模板超时（推荐 3600） |
| `-retries <num>` | 请求失败重试次数 |
| `-json` | JSON 格式输出 |
| `-stats` | 显示实时统计信息 |
| `-H <header>` | 添加自定义 HTTP 头 |
| `-var key=val` | 模板变量注入 |

---

## 典型使用场景

### 1. 全量扫描（推荐 — 高并发）
```bash
# ✅ 高性能全量扫描（64核服务器）
nuclei -u https://target.com \
  -t ~/nuclei-templates/ \
  -c 100 -bs 25 -rl 500 \
  -timeout 3600 -silent \
  -o /SESSION/nuclei_full.txt
```

### 2. 按 CVE ID 精准扫描（推荐）

```bash
# ✅ 用 -id 指定 CVE（最可靠，自动在全模板库中查找）
nuclei -u https://target.com -id CVE-2024-10915 -silent
nuclei -u https://target.com -id CVE-2023-50164,CVE-2024-4577 -silent

# ✅ 用绝对路径指定单个模板
nuclei -u https://target.com \
    -t ~/nuclei-templates/http/cves/2024/CVE-2024-10915.yaml -silent

# ❌ 禁止使用相对路径（会找不到模板，0s 完成 0B 输出）
# nuclei -u URL -t cves/2024/CVE-2024-10915.yaml   ← 错误
# nuclei -u URL -t http/cves/2024/CVE-2024-10915.yaml  ← 错误
```

### 3. 按 CVE 标签批量扫描
```bash
nuclei -u https://target.com -t ~/nuclei-templates/ -tags cve -silent -o cve_results.txt
```

### 4. WordPress 专项扫描
```bash
# 技术识别
nuclei -u https://target.com -t ~/nuclei-templates/http/technologies/wordpress/ -silent

# WordPress 漏洞扫描
nuclei -u https://target.com -t ~/nuclei-templates/http/vulnerabilities/wordpress/ -silent
```

### 5. 多目标批量扫描
```bash
nuclei -l urls.txt -t ~/nuclei-templates/ -silent -timeout 1800 -o batch_results.txt
```

### 6. 子域名全覆盖扫描
```bash
for subdomain in $(cat subs.txt); do
    echo "[*] Scanning: $subdomain"
    nuclei -u "https://$subdomain" -t ~/nuclei-templates/ -silent \
           -timeout 1800 -o "${subdomain//\//_}_vulns.txt" 2>/dev/null
done
```

### 7. 指定特定漏洞类型
```bash
# RCE 扫描
nuclei -u https://target.com -t ~/nuclei-templates/ -tags rce -silent

# SQL 注入
nuclei -u https://target.com -t ~/nuclei-templates/ -tags sqli -silent

# XSS
nuclei -u https://target.com -t ~/nuclei-templates/ -tags xss -silent

# SSRF
nuclei -u https://target.com -t ~/nuclei-templates/ -tags ssrf -silent

# 信息泄露
nuclei -u https://target.com -t ~/nuclei-templates/ -tags exposure -silent
```

### 8. 加速扫描（64核推荐配置）
```bash
nuclei -u https://target.com \
  -t ~/nuclei-templates/ \
  -c 100 -bs 50 -rl 500 \
  -timeout 3600 -silent
```

### 9. 与 httpx 联动（管道扫描）
```bash
cat hosts.txt | httpx -silent | nuclei -t ~/nuclei-templates/ -silent -o results.txt
```

### 10. JSON 格式输出（便于解析）
```bash
nuclei -u https://target.com -t ~/nuclei-templates/ -json -silent | \
  jq -r '[.info.severity, .info.name, .matched-at] | @tsv'
```

### 11. 添加自定义请求头（绕过 WAF / 认证）
```bash
nuclei -u https://target.com -t ~/nuclei-templates/ \
       -H "X-Forwarded-For: 127.0.0.1" \
       -H "Authorization: Bearer YOUR_TOKEN" \
       -silent
```

---

## 模板目录结构

```
~/nuclei-templates/
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
cd ~/nuclei-templates && git pull

# 查看模板数量
ls ~/nuclei-templates/http/vulnerabilities/ | wc -l
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
- **全量模板优先**：始终使用 `-t ~/nuclei-templates/` 而非子目录
- **超时要足够长**：全量扫描至少设置 `-timeout 3600`
- **多资产覆盖**：主域名和每个子域名都需要独立扫描
