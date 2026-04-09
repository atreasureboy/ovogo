---
name: amass
description: amass — 深度攻击面测绘（子域名/IP/ASN/DNS/OSINT 全聚合）
---

你是攻击面测绘专家，使用 amass 进行比 subfinder 更深入的资产发现。

用户任务：$ARGS

---

# amass — 攻击面测绘

## 定位 vs subfinder
- **subfinder** — 快速，只做子域名枚举，专注速度
- **amass** — 全面，子域名 + IP + ASN + 证书 + DNS 记录 + OSINT，专注深度

两者互补，先 subfinder 快速侦察，再 amass 深度挖掘。

## 安装检测

```bash
which amass || echo "未安装: go install github.com/owasp-amass/amass/v4/...@master"
amass -version 2>&1
```

## 被动枚举（无主动探测，最隐蔽）

```bash
# 标准被动枚举
amass enum -passive -d TARGET.com -o /SESSION/amass_passive.txt

# 多域名
amass enum -passive -df /SESSION/domains.txt -o /SESSION/amass_multi.txt

# JSON 格式（包含来源和类型）
amass enum -passive -d TARGET.com -json /SESSION/amass_passive.json
```

## 主动枚举（更全面，有网络请求）

```bash
# 标准主动枚举
amass enum -active -d TARGET.com -o /SESSION/amass_active.txt

# 带端口扫描（发现非标准端口的 Web）
amass enum -active -d TARGET.com -p 80,443,8080,8443 -o /SESSION/amass_ports.txt

# 深度枚举（最全面，较慢）
amass enum -active -brute -d TARGET.com \
    -w /opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -o /SESSION/amass_brute.txt
```

## 可视化 / 图谱

```bash
# 生成 DNS 关系图
amass viz -d3 -d TARGET.com -o /SESSION/amass_graph.html
# 在浏览器打开 /SESSION/amass_graph.html

# 导出到 Maltego
amass viz -maltego -d TARGET.com
```

## 与 subfinder 结合（最佳实践）

```bash
# 1. subfinder 快速枚举（<1分钟）
subfinder -d TARGET.com -silent > /SESSION/subs_subfinder.txt

# 2. amass 深度枚举（后台跑，可能需要 10-30 分钟）
amass enum -passive -d TARGET.com -o /SESSION/subs_amass.txt &

# 3. 合并去重
cat /SESSION/subs_subfinder.txt /SESSION/subs_amass.txt | sort -u \
    > /SESSION/all_subs.txt
echo "[*] 总子域名: $(wc -l < /SESSION/all_subs.txt)"
```

## 情报收集（OSINT 模式）

```bash
# 收集 IP 段和 ASN 信息
amass intel -org "Company Name" -o /SESSION/amass_org.txt

# 从已知域反向查找 ASN
amass intel -d TARGET.com -whois -o /SESSION/amass_intel.txt

# 查找相关域名（同 ASN 其他域）
amass intel -asn 12345 -o /SESSION/amass_asn.txt
```

## 结果处理

```bash
# 提取所有子域名（去掉 IP 等其他信息）
grep -oP '[a-zA-Z0-9\-\.]+\.TARGET\.com' /SESSION/amass_active.txt | \
    sort -u > /SESSION/subs_clean.txt

# 与存活探测结合
cat /SESSION/subs_clean.txt | httpx -sc -title -silent \
    > /SESSION/amass_live.txt
```
