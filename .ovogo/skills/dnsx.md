---
name: dnsx
description: dnsx — DNS 查询与解析工具
---

你是 dnsx 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# dnsx — DNS 查询与解析工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 二进制路径 | `/root/go/bin/dnsx` |
| 项目来源 | ProjectDiscovery |
| 适用场景 | DNS 批量解析、子域名过滤、DNS 记录枚举 |

> **注意**：当前环境中 dnsx 可能存在输出问题，可用系统 `dig` 命令替代。

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-l <file>` | 从文件读取域名列表 |
| `-d <domain>` | 指定单个域名 |
| `-w <wordlist>` | 字典爆破子域名 |
| `-a` | 查询 A 记录 |
| `-aaaa` | 查询 AAAA 记录（IPv6） |
| `-cname` | 查询 CNAME 记录 |
| `-mx` | 查询 MX 记录 |
| `-ns` | 查询 NS 记录 |
| `-txt` | 查询 TXT 记录 |
| `-ptr` | 查询 PTR 记录（反向解析） |
| `-soa` | 查询 SOA 记录 |
| `-resp` | 显示完整响应 |
| `-resp-only` | 只显示响应 IP（不显示域名） |
| `-silent` | 静默模式 |
| `-r <resolver>` | 指定 DNS 服务器 |
| `-rL <file>` | 从文件读取 DNS 服务器列表 |
| `-t <num>` | 并发线程数（64核推荐 **200**） |
| `-timeout <sec>` | 超时秒数 |
| `-retry <num>` | 重试次数 |
| `-o <file>` | 输出到文件 |
| `-json` | JSON 格式输出 |
| `-rc` | 显示 DNS 响应码 |
| `-cdn` | 显示 CDN 信息 |
| `-asn` | 显示 ASN 信息 |

---

## 典型使用场景

### 1. 解析子域名列表（过滤存活）
```bash
cat subs.txt | dnsx -a -resp-only -silent
```

### 2. 获取子域名 + 对应 IP
```bash
cat subs.txt | dnsx -a -resp -silent
```

### 3. 查询指定记录类型
```bash
# A 记录
echo "target.com" | dnsx -a -silent

# MX 记录
echo "target.com" | dnsx -mx -silent

# TXT 记录（SPF/DKIM 等）
echo "target.com" | dnsx -txt -silent

# NS 记录
echo "target.com" | dnsx -ns -silent

# 所有常用记录
echo "target.com" | dnsx -a -aaaa -cname -mx -txt -ns -silent
```

### 4. 子域名批量解析 + httpx 探测
```bash
subfinder -d target.com -silent | \
  dnsx -a -resp-only -silent | \
  httpx -sc -title -silent
```

### 5. 指定 DNS 服务器
```bash
cat subs.txt | dnsx -a -r 8.8.8.8,1.1.1.1 -silent
```

### 6. 反向 DNS 解析（IP → 域名）
```bash
echo "1.2.3.4" | dnsx -ptr -silent
```

### 7. JSON 格式输出
```bash
cat subs.txt | dnsx -a -json -silent | jq '{host: .host, a: .a}'
```

---

## dig 替代命令（当 dnsx 出问题时）

```bash
# A 记录
dig target.com A +short

# AAAA 记录
dig target.com AAAA +short

# MX 记录
dig target.com MX +short

# TXT 记录（SPF/DKIM）
dig target.com TXT +short

# NS 记录
dig target.com NS +short

# CNAME 记录
dig sub.target.com CNAME +short

# SOA 记录
dig target.com SOA +short

# 反向解析
dig -x 1.2.3.4 +short

# 指定 DNS 服务器查询
dig @8.8.8.8 target.com A +short

# 查询任意记录
dig target.com ANY +short

# 批量查询（配合 xargs）
cat subs.txt | xargs -I{} dig {} A +short
```

---

## DNS 信息收集完整流程

```bash
# 1. 基础 DNS 侦察
dig target.com ANY +short
dig target.com TXT +short      # SPF / DMARC / 验证记录
dig _dmarc.target.com TXT +short  # DMARC 策略

# 2. 子域名枚举 + 解析过滤
subfinder -d target.com -silent | dnsx -a -resp-only -silent > live_ips.txt

# 3. 区域传送尝试（zone transfer）
dig @ns1.target.com target.com AXFR

# 4. 反向解析 IP 段
for i in $(seq 1 255); do
    echo "1.2.3.$i" | dnsx -ptr -silent 2>/dev/null
done

# 5. 收集所有 IP 然后进行反向解析
cat live_ips.txt | dnsx -ptr -silent
```

---

## 常见 DNS 记录解读

| 记录类型 | 用途 | 安全意义 |
|---------|------|---------|
| `A` | 域名 → IPv4 | 确认服务器 IP |
| `AAAA` | 域名 → IPv6 | IPv6 地址 |
| `CNAME` | 别名指向 | 可能暴露内部服务名、接管漏洞 |
| `MX` | 邮件服务器 | 邮件安全配置 |
| `TXT` | 文本信息 | SPF/DKIM/DMARC/验证码 |
| `NS` | DNS 服务器 | 可尝试区域传送 |
| `PTR` | IP → 域名 | 反向解析，发现隐藏主机 |
| `SOA` | 区域授权 | 主 DNS 服务器信息 |

---

## DNS 安全检测

```bash
# 检查 SPF 配置
dig target.com TXT +short | grep spf

# 检查 DMARC 配置
dig _dmarc.target.com TXT +short

# 检查 DNSSEC
dig target.com DNSKEY +short

# 尝试区域传送
dig axfr @ns1.target.com target.com

# 检查 DNS 劫持（对比多个 DNS 服务器结果）
dig @8.8.8.8 target.com A +short
dig @1.1.1.1 target.com A +short
dig @9.9.9.9 target.com A +short
```
