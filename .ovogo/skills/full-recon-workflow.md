---
name: full-recon-workflow
description: 完整渗透测试侦察流程
---

你是 full-recon-workflow 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# 完整渗透测试侦察流程

> 本文档整合所有工具，提供从信息收集到漏洞扫描的完整流水线。

---

## 环境变量初始化

```bash
# 设置工具路径（必须用绝对路径，避免同名冲突）
export PATH=$PATH:/root/go/bin:/root/.pdtm/go/bin:/root/.local/bin

# Go 工具绝对路径（防止 Python 同名工具覆盖）
HTTPX=httpx
SUBFINDER=subfinder
DNSX=dnsx
NUCLEI=nuclei
NAABU=naabu
KATANA=katana
FFUF=ffuf

# 验证关键工具（任何路径找不到时有备选方案）
for tool in $HTTPX $SUBFINDER $NUCLEI; do
    [ -x "$tool" ] || echo "[!] 未找到: $tool"
done

# 设置目标（替换为实际目标）
TARGET="target.com"
TARGET_IP="1.2.3.4"

# OUTPUT_DIR 使用 session 目录（已由 ovogogogo 在 prompt 中注入）
OUTPUT_DIR="${SESSION_DIR:-./sessions/manual_$(date +%Y%m%d_%H%M%S)}"
mkdir -p $OUTPUT_DIR
```

---

## 阶段一：被动信息收集

```bash
# 1. 子域名枚举（多数据源聚合）
subfinder -d $TARGET -all -silent -o $OUTPUT_DIR/subs.txt
echo "[*] Found $(wc -l < $OUTPUT_DIR/subs.txt) subdomains"

# 2. DNS 记录收集
dig $TARGET ANY +short | tee $OUTPUT_DIR/dns_records.txt
dig $TARGET TXT +short   # SPF/DMARC
dig $TARGET MX +short    # 邮件服务器
dig _dmarc.$TARGET TXT +short  # DMARC 策略

# 3. 历史 URL 收集
echo $TARGET | waybackurls | sort -u | tee $OUTPUT_DIR/wayback_urls.txt
gau $TARGET | sort -u >> $OUTPUT_DIR/wayback_urls.txt
sort -u $OUTPUT_DIR/wayback_urls.txt > $OUTPUT_DIR/all_history_urls.txt
```

---

## 阶段二：主动信息收集

```bash
# 4. DNS 解析过滤存活子域名
cat $OUTPUT_DIR/subs.txt | \
    $DNSX -a -resp-only -silent | \
    sort -u | \
    tee $OUTPUT_DIR/live_ips.txt

# 5. HTTP 存活探测 + 指纹识别
cat $OUTPUT_DIR/subs.txt | \
    $HTTPX -sc -title -td -server -ip -cdn -silent | \
    tee $OUTPUT_DIR/web_assets.txt

# 只保留存活 URL
cat $OUTPUT_DIR/subs.txt | $HTTPX -silent > $OUTPUT_DIR/live_urls.txt
echo "[*] Found $(wc -l < $OUTPUT_DIR/live_urls.txt) live web targets"

# 6. 端口扫描（主域名）
nmap -Pn -n -T4 --min-rate 5000 --top-ports 1000 \
     $TARGET_IP \
     -oA $OUTPUT_DIR/nmap_top1000

# 全端口扫描（后台）
nmap -Pn -n -T4 --min-rate 5000 -p- \
     $TARGET_IP \
     -oN $OUTPUT_DIR/nmap_all_ports.txt &
```

---

## 阶段三：Web 内容发现

```bash
# 7. 目录枚举（主域名）
ffuf -u https://$TARGET/FUZZ \
     -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
     -e .php,.html,.txt,.bak,.zip \
     -ac -silent \
     -o $OUTPUT_DIR/dirs_main.json -of json

# 8. 深度爬取 + JS 文件分析
katana -u https://$TARGET -d 3 -jc -silent | \
    tee $OUTPUT_DIR/crawled_urls.txt

# 9. 提取带参数 URL（用于漏洞测试）
cat $OUTPUT_DIR/crawled_urls.txt | \
    grep '=' | sort -u > $OUTPUT_DIR/parameterized_urls.txt

# 10. 提取 JS 文件
cat $OUTPUT_DIR/crawled_urls.txt | \
    grep '\.js$' | sort -u > $OUTPUT_DIR/js_files.txt
```

---

## 阶段四：全量漏洞扫描（核心）

```bash
# 11. 主域名全量 nuclei 扫描
# ⚠️ 不使用 -severity 过滤，扫描所有级别
nuclei -u https://$TARGET \
       -t ~/nuclei-templates/ \
       -silent \
       -timeout 3600 \
       -o $OUTPUT_DIR/nuclei_main.txt &

# 12. 对所有存活子域名进行独立全量扫描
while read url; do
    domain=$(echo $url | sed 's|https\?://||')
    nuclei -u $url \
           -t ~/nuclei-templates/ \
           -silent \
           -timeout 1800 \
           -o "$OUTPUT_DIR/nuclei_${domain//[\/:]/_}.txt" &
done < $OUTPUT_DIR/live_urls.txt

# 等待所有后台扫描完成（可选，可以继续其他工作）
wait
echo "[*] Nuclei scans completed"
```

---

## 阶段五：专项漏洞测试

```bash
# 13. XSS 扫描
cat $OUTPUT_DIR/parameterized_urls.txt | \
    dalfox pipe --worker 20 \
    -o $OUTPUT_DIR/xss_results.txt

# 14. SQL 注入快速检测
cat $OUTPUT_DIR/parameterized_urls.txt | head -50 | \
    while read url; do
        sqlmap -u "$url" --batch --level 2 --quiet \
               --output-dir $OUTPUT_DIR/sqlmap/ 2>/dev/null
    done

# 15. WordPress 专项（如果检测到 WP）
if grep -q "WordPress" $OUTPUT_DIR/web_assets.txt; then
    echo "[*] WordPress detected, running wpscan"
    wpscan --url https://$TARGET \
           --enumerate p,t,u,cb,dbe \
           --no-banner \
           -o $OUTPUT_DIR/wpscan_result.txt
fi

# 16. WAF 行为测试
echo "[*] Testing WAF responses"
curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/?id=1' OR '1'='1"
curl -s -o /dev/null -w "%{http_code}" "https://$TARGET/?q=<script>alert(1)</script>"
```

---

## 阶段六：目录暴力破解（补充）

```bash
# 17. 针对每个存活 URL 进行目录枚举
while read url; do
    domain=$(echo $url | sed 's|https\?://||' | tr '/' '_')
    gobuster dir \
        -u $url \
        -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt \
        -q -t 30 \
        -o "$OUTPUT_DIR/gobuster_${domain}.txt" 2>/dev/null &
done < $OUTPUT_DIR/live_urls.txt
wait
```

---

## 阶段七：结果汇总

```bash
# 18. 汇总所有 nuclei 发现
cat $OUTPUT_DIR/nuclei_*.txt 2>/dev/null | \
    grep -v "^$" | sort -u > $OUTPUT_DIR/all_vulns.txt

# 按严重级别统计
echo "=== 漏洞统计 ==="
echo "Critical: $(grep -c '\[critical\]' $OUTPUT_DIR/all_vulns.txt 2>/dev/null || echo 0)"
echo "High:     $(grep -c '\[high\]' $OUTPUT_DIR/all_vulns.txt 2>/dev/null || echo 0)"
echo "Medium:   $(grep -c '\[medium\]' $OUTPUT_DIR/all_vulns.txt 2>/dev/null || echo 0)"
echo "Low:      $(grep -c '\[low\]' $OUTPUT_DIR/all_vulns.txt 2>/dev/null || echo 0)"
echo "Info:     $(grep -c '\[info\]' $OUTPUT_DIR/all_vulns.txt 2>/dev/null || echo 0)"

# 19. 生成简报
echo "=== 侦察结果概要 ===" | tee $OUTPUT_DIR/summary.txt
echo "目标: $TARGET / $TARGET_IP" | tee -a $OUTPUT_DIR/summary.txt
echo "子域名: $(wc -l < $OUTPUT_DIR/subs.txt)" | tee -a $OUTPUT_DIR/summary.txt
echo "存活 Web 目标: $(wc -l < $OUTPUT_DIR/live_urls.txt)" | tee -a $OUTPUT_DIR/summary.txt
echo "带参数 URL: $(wc -l < $OUTPUT_DIR/parameterized_urls.txt)" | tee -a $OUTPUT_DIR/summary.txt
echo "发现漏洞总数: $(wc -l < $OUTPUT_DIR/all_vulns.txt)" | tee -a $OUTPUT_DIR/summary.txt
echo "扫描完成时间: $(date)" | tee -a $OUTPUT_DIR/summary.txt
```

---

## 快速命令备忘

```bash
# 单行完整侦察
subfinder -d target.com -silent | dnsx -resp-only -a -silent | httpx -title -tech-detect -status-code -silent | tee recon.txt

# 快速漏洞扫描
nuclei -u https://target.com -t ~/nuclei-templates/ -silent -timeout 3600

# 快速目录 + XSS
ffuf -u https://target.com/FUZZ -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt -ac -silent
katana -u https://target.com -d 3 -silent | grep '=' | dalfox pipe
```

---

## 工具路径速查表

| 工具 | 路径 |
|------|------|
| subfinder | `subfinder` |
| dnsx | `dnsx` |
| httpx | `httpx` 或 `/usr/local/bin/httpx` |
| naabu | `naabu` |
| katana | `katana` |
| nuclei | `nuclei` |
| ffuf | `ffuf` |
| dalfox | dalfox |
| cvemap | cvemap |
| nmap | `/usr/bin/nmap` |
| sqlmap | 系统 PATH |
| gobuster | 系统 PATH |
| hydra | 系统 PATH |
| wpscan | 系统 PATH |
| nuclei 模板 | `~/nuclei-templates/` |
| 字典 | `/opt/wordlists/` |
| SecLists | `/opt/wordlists/seclists/` |
