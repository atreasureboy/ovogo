---
name: httpx
description: httpx (ProjectDiscovery) — HTTP 批量探测与指纹识别
---

你是 httpx 专家。注意：系统中可能存在两个同名工具，使用前必须先检测。

用户任务：$ARGS

---

# httpx — HTTP 探测与指纹识别

## ⚠️ 首先：检测正确的 httpx 路径

系统中 `httpx` 可能是 Python HTTP 客户端（不是渗透工具），**必须先确认路径**：

```bash
# 检测 ProjectDiscovery httpx 的正确路径
PD_HTTPX=""
for p in /root/go/bin/httpx /root/.pdtm/go/bin/httpx /usr/local/bin/httpx-pd /home/$(whoami)/go/bin/httpx; do
    if [ -x "$p" ] && $p -version 2>&1 | grep -qi "projectdiscovery\|httpx v"; then
        PD_HTTPX="$p"
        break
    fi
done

# 检查 PATH 中的 httpx 是否是 PD 版本
if [ -z "$PD_HTTPX" ] && httpx -version 2>&1 | grep -qi "projectdiscovery\|httpx v"; then
    PD_HTTPX="httpx"
fi

echo "ProjectDiscovery httpx: ${PD_HTTPX:-未找到}"
```

**之后所有命令用 `$PD_HTTPX` 代替 `httpx`**

---

## 核心参数（ProjectDiscovery httpx）

| 参数 | 说明 |
|------|------|
| `-l <file>` | 从文件读取目标列表 |
| `-sc` | 显示状态码 |
| `-title` | 显示页面标题 |
| `-td` | 技术栈指纹 |
| `-server` | 显示服务器信息 |
| `-ip` | 显示解析 IP |
| `-cdn` | CDN 检测 |
| `-silent` | 只输出结果 |
| `-t <n>` | 并发线程（默认50，64核推荐 **300**） |
| `-o <file>` | 输出文件 |
| `-json` | JSON 格式 |
| `-mc <codes>` | 匹配状态码 |
| `-fc <codes>` | 过滤状态码 |
| `-follow-redirects` | 跟随重定向 |
| `-H <header>` | 自定义 Header |

---

## 正确用法（必须用检测到的路径）

```bash
# 先设置变量
PD_HTTPX=/root/go/bin/httpx   # 或检测到的路径

# 单目标探测
echo "https://TARGET" | $PD_HTTPX -sc -title -td -server -silent

# 多目标批量（从文件，高并发）
$PD_HTTPX -l /SESSION/subs.txt -sc -title -td -server -ip -cdn -silent \
    -t 300 -o /SESSION/httpx_results.txt

# 管道方式（与 subfinder 配合）
subfinder -d TARGET -silent | $PD_HTTPX -sc -title -td -server -ip -silent \
    -o /SESSION/web_assets.txt

# 只获取存活 URL
$PD_HTTPX -l /SESSION/subs.txt -silent > /SESSION/live_urls.txt

# 多端口探测
$PD_HTTPX -l /SESSION/ips.txt -p 80,443,8080,8443,8888,9090,3000,5000 \
    -sc -title -silent -o /SESSION/multi_port.txt

# JSON 输出（详细信息）
echo "https://TARGET" | $PD_HTTPX -json -silent | jq -r '[.url,.status_code,.title,.tech] | @tsv'
```

---

## 如果 ProjectDiscovery httpx 未安装

```bash
# 用 curl 替代单目标探测
curl -sI https://TARGET | head -20

# 用 curl 批量（较慢，无技术栈识别）
while read url; do
    code=$(curl -so /dev/null -w "%{http_code}" --max-time 5 "$url")
    title=$(curl -s --max-time 5 "$url" | grep -oP '(?<=<title>)[^<]+' | head -1)
    server=$(curl -sI --max-time 5 "$url" | grep -i "^server:" | cut -d' ' -f2-)
    echo "$code | $url | $title | $server"
done < /SESSION/subs.txt | tee /SESSION/curl_probe.txt

# 安装 ProjectDiscovery httpx
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
# 或
curl -sL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip -o /tmp/httpx.zip
unzip /tmp/httpx.zip -d /usr/local/bin/
```

---

## 与其他工具配合

```bash
# 完整侦察流水线
PD_HTTPX=/root/go/bin/httpx
subfinder -d TARGET -silent | \
    /root/go/bin/dnsx -a -resp-only -silent | \
    $PD_HTTPX -sc -title -td -server -ip -cdn -silent | \
    tee /SESSION/full_web_assets.txt

# 过滤有趣目标
cat /SESSION/web_assets.txt | grep -i "admin\|login\|manage\|api\|dev\|test\|stage"
```
