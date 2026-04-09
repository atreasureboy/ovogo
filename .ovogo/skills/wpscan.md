---
name: wpscan
description: wpscan — WordPress 安全扫描工具
---

你是 wpscan 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# wpscan — WordPress 安全扫描工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 命令 | `wpscan` |
| 路径 | 系统 PATH 直接可用 |
| 适用场景 | WordPress 漏洞扫描、插件/主题枚举、用户枚举、暴力破解 |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `--url <url>` | 目标 WordPress URL |
| `--enumerate <what>` | 枚举选项（见下方枚举类型） |
| `--usernames <user>` | 指定用户名（暴破用） |
| `--passwords <file>` | 密码字典（暴破用） |
| `--api-token <token>` | WPScan API Token（获取更多漏洞数据） |
| `--proxy <url>` | 使用代理 |
| `--random-user-agent` | 随机 UA |
| `--user-agent <ua>` | 自定义 UA |
| `--cookie <cookie>` | 指定 Cookie |
| `--http-auth <user:pass>` | HTTP 基础认证 |
| `-t <num>` | 线程数 |
| `--request-timeout <sec>` | 请求超时 |
| `--max-threads <num>` | 最大线程数 |
| `--throttle <msec>` | 请求间隔（毫秒） |
| `--disable-tls-checks` | 禁用 TLS 证书验证 |
| `--detection-mode <mode>` | 检测模式（passive/aggressive/mixed） |
| `-o <file>` | 输出到文件 |
| `-f <format>` | 输出格式（cli/json/cli-no-colour） |
| `--no-banner` | 不显示 banner |
| `-v` | 详细输出 |

---

## 枚举类型（--enumerate）

| 选项 | 说明 |
|------|------|
| `p` | 插件（plugins） |
| `vp` | 存在漏洞的插件（vulnerable plugins） |
| `ap` | 所有插件（aggressive，耗时） |
| `t` | 主题（themes） |
| `vt` | 存在漏洞的主题 |
| `at` | 所有主题 |
| `u` | 用户（users） |
| `m` | 媒体文件 |
| `cb` | 配置备份文件 |
| `dbe` | 数据库导出文件 |
| `tt` | Timthumbs |

---

## 典型使用场景

### 1. 基础扫描（版本 + 常见漏洞）
```bash
wpscan --url https://target.com --no-banner
```

### 2. 枚举插件 + 用户（标准侦察）
```bash
wpscan --url https://target.com \
       --enumerate p,u \
       --no-banner
```

### 3. 存在漏洞的插件（快速）
```bash
wpscan --url https://target.com \
       --enumerate vp,vt \
       --no-banner
```

### 4. 全面枚举（插件 + 主题 + 用户 + 备份）
```bash
wpscan --url https://target.com \
       --enumerate p,t,u,cb,dbe \
       --no-banner -v
```

### 5. 激进模式（发现更多但请求量大）
```bash
wpscan --url https://target.com \
       --enumerate ap,at,u \
       --detection-mode aggressive \
       --no-banner
```

### 6. 用户暴力破解
```bash
# 指定用户名
wpscan --url https://target.com \
       --usernames admin \
       --passwords /opt/wordlists/rockyou.txt \
       -t 20 --no-banner

# 先枚举用户，再爆破
wpscan --url https://target.com --enumerate u --no-banner
wpscan --url https://target.com \
       --usernames found_users.txt \
       --passwords /opt/wordlists/rockyou.txt \
       -t 20 --no-banner
```

### 7. 使用 API Token（获取详细 CVE 信息）
```bash
wpscan --url https://target.com \
       --enumerate vp,vt,u \
       --api-token YOUR_API_TOKEN \
       --no-banner
```

### 8. 禁用 SSL 验证（自签名证书）
```bash
wpscan --url https://target.com \
       --enumerate p,u \
       --disable-tls-checks \
       --no-banner
```

### 9. 带认证 Cookie 扫描（登录后扫描）
```bash
wpscan --url https://target.com \
       --enumerate p,u \
       --cookie "wordpress_logged_in_xxx=value" \
       --no-banner
```

### 10. 输出 JSON 格式
```bash
wpscan --url https://target.com \
       --enumerate p,u \
       -f json -o wpscan_result.json \
       --no-banner
```

### 11. 速率限制（避免触发 WAF）
```bash
wpscan --url https://target.com \
       --enumerate p,u \
       --throttle 500 -t 5 \
       --random-user-agent \
       --no-banner
```

---

## 结果解读

### 版本信息
```
[+] WordPress version 5.9.3 identified (Insecure, released on 2022-04-05)
 | Found By: Readme File (Aggressive Detection)
 | Confirmed By: ...
```

### 插件漏洞
```
[!] Plugin: contact-form-7 4.9 - Cross-Site Scripting (CVE-2018-xxxx)
 | Fixed in: 5.0
 | References: https://www.exploit-db.com/exploits/xxxxx
```

### 用户枚举
```
[i] User(s) Identified:
[+] admin
 | Found By: Author Posts - Display Name (Passive Detection)
```

---

## 配合 nuclei 的 WordPress 扫描流程

```bash
# 第一步：wpscan 枚举信息
wpscan --url https://target.com --enumerate p,u -f json -o wp_info.json

# 第二步：nuclei 漏洞扫描
nuclei -u https://target.com \
       -t ~/nuclei-templates/http/technologies/wordpress/ \
       -t ~/nuclei-templates/http/vulnerabilities/wordpress/ \
       -silent

# 第三步：全量 nuclei 扫描（不过滤）
nuclei -u https://target.com \
       -t ~/nuclei-templates/ \
       -silent -timeout 3600 -o wp_vulns.txt
```

---

## 获取 WPScan API Token

1. 注册：https://wpscan.com/register
2. 免费账号每天 75 次 API 请求
3. 配置：`wpscan --api-token YOUR_TOKEN` 或写入 `~/.wpscan/scan.yml`

```yaml
# ~/.wpscan/scan.yml
cli_options:
  api_token: YOUR_TOKEN
```
