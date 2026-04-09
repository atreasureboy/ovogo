---
name: katana
description: katana — 智能 Web 爬虫
---

你是 katana 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# katana — 智能 Web 爬虫

## 基本信息

| 项目 | 内容 |
|------|------|
| 二进制路径 | `/root/go/bin/katana` |
| 项目来源 | ProjectDiscovery |
| 适用场景 | Web 目录爬取、URL 发现、参数收集、JS 文件分析 |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-u <url>` | 指定目标 URL |
| `-list <file>` | 从文件读取多个目标 |
| `-d <depth>` | 爬取深度（默认 3） |
| `-jc` | 解析 JavaScript 文件（发现更多 URL） |
| `-silent` | 静默模式，只输出 URL |
| `-o <file>` | 输出到文件 |
| `-json` | JSON 格式输出 |
| `-c <num>` | 并发数 |
| `-p <num>` | 并行任务数 |
| `-timeout <sec>` | 超时秒数 |
| `-rl <num>` | 请求速率限制 |
| `-H <header>` | 自定义请求头 |
| `-ef <ext>` | 排除特定文件扩展名 |
| `-em <ext>` | 只匹配特定扩展名 |
| `-kf` | 保留爬取的文件 |
| `-nc` | 不使用颜色 |
| `-headless` | 无头浏览器模式（处理 JS 渲染页面） |
| `-system-chrome` | 使用系统 Chrome |
| `-xhr` | 捕获 XHR 请求 |
| `-form` | 爬取表单内容 |
| `-field <field>` | 只输出特定字段（url/path/method/body/header等） |
| `-filter-regex <regex>` | 过滤 URL |
| `-match-regex <regex>` | 只匹配特定 URL |
| `-dr` | 禁止重定向跟随 |
| `-proxy <url>` | 使用代理 |

---

## 典型使用场景

### 1. 基础爬取（推荐参数）

```bash
# ✅ 标准爬取：深度 2，超时 30s，避免卡死
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -silent -o /SESSION/katana_urls.txt

# 带 JS 解析（发现更多 API 端点，稍慢）
/root/go/bin/katana -u https://target.com -d 2 -jc -timeout 30 -silent -o /SESSION/katana_js.txt
```

### 2. 多目标批量爬取

```bash
/root/go/bin/katana -list /SESSION/live_urls.txt -d 2 -timeout 30 -silent -o /SESSION/katana_all.txt
```

### 3. 无头浏览器模式（处理 SPA 应用）

```bash
/root/go/bin/katana -u https://target.com -headless -d 2 -timeout 60 -silent -o /SESSION/katana_spa.txt
```

### 4. 收集所有 JS 文件

```bash
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -em js -silent -o /SESSION/katana_js_files.txt
```

### 5. 收集带参数的 URL（用于漏洞测试）

```bash
/root/go/bin/katana -u https://target.com -d 2 -jc -timeout 30 -silent | \
  grep '?' | sort -u > /SESSION/katana_params.txt
```

### 6. 联动 gf 过滤感兴趣的 URL

```bash
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -silent | gf xss
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -silent | gf sqli
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -silent | gf redirect
```

### 7. 联动 dalfox 进行 XSS 扫描

```bash
/root/go/bin/katana -u https://target.com -d 2 -jc -timeout 30 -silent | \
  grep '=' | dalfox pipe -o /SESSION/xss_results.txt
```

### 8. 联动 sqlmap 进行 SQL 注入测试

```bash
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -silent | \
  grep '=' | head -20 | \
  while read url; do
    sqlmap -u "$url" --batch --level 2 --quiet
  done
```

### 9. 只输出路径 / API 端点

```bash
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -silent -field path | sort -u
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -xhr -silent | grep 'api/'
```

### 10. 使用 Cookie 进行认证后爬取

```bash
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 \
    -H "Cookie: session=YOUR_SESSION_TOKEN" \
    -jc -silent -o /SESSION/katana_auth.txt
```

---

## 输出过滤技巧

```bash
# 提取所有唯一域名
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -silent | \
  awk -F/ '{print $1"//"$3}' | sort -u

# 提取所有带参数 URL
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -silent | grep -E '\?[^=]+=.'

# 过滤静态资源（图片/CSS等）
/root/go/bin/katana -u https://target.com -d 2 -timeout 30 -silent | \
  grep -vE '\.(png|jpg|gif|css|ico|svg|woff|ttf)$'

# 提取所有 API 端点
/root/go/bin/katana -u https://target.com -d 2 -jc -timeout 30 -silent | \
  grep -E '/api/|/v[0-9]+/'
```

---

## 与其他爬虫对比

| 工具 | 特点 | 适用场景 |
|------|------|---------|
| `katana` | 智能 JS 解析、速度快 | 现代 Web 应用 |
| `gospider` | 功能全面，多格式 | 传统 Web 站点 |
| `hakrawler` | 极简快速 | 快速 URL 收集 |
| `waybackurls` | 历史 URL | 挖掘历史端点 |
| `gau` | 多数据源聚合 | OSINT 结合 |

---

## 注意事项

- JS 解析模式（`-jc`）会显著增加运行时间，但能发现更多端点
- 无头浏览器模式需要 Chrome/Chromium，但能处理 JS 渲染的动态内容
- **必须设置 `-timeout`**：默认无超时，爬大型站点会卡死。普通站用 30s，认证后爬取用 60s
- 深度设置不宜太深（>3），容易陷入无限循环；**推荐 `-d 2`**
- 对于需要登录的目标，通过 `-H "Cookie: ..."` 传入认证信息
