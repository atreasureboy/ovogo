---
name: subfinder
description: subfinder — 子域名枚举工具
---

你是 subfinder 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# subfinder — 子域名枚举工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 二进制路径 | `/root/go/bin/subfinder` |
| 项目来源 | ProjectDiscovery |
| 适用场景 | 子域名发现、资产测绘、信息收集阶段 |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-d <domain>` | 指定目标主域名 |
| `-dL <file>` | 从文件读取多个域名 |
| `-o <file>` | 输出结果到文件 |
| `-oJ` | 输出 JSON 格式 |
| `-silent` | 静默模式，只输出结果 |
| `-t <num>` | 并发线程数（默认 10） |
| `-timeout <sec>` | 超时秒数（默认 30） |
| `-recursive` | 递归枚举子域名 |
| `-all` | 使用所有数据源（更慢但更全） |
| `-v` | 详细输出（调试用） |
| `-cs` | 显示找到该子域的数据源 |
| `-exclude-sources` | 排除指定数据源 |
| `-rate-limit <num>` | 每秒请求速率限制 |

---

## 典型使用场景

### 1. 基础单域名枚举
```bash
subfinder -d target.com -silent -o subs.txt
```

### 2. 显示来源数据
```bash
subfinder -d target.com -cs -silent
```

### 3. 多域名批量枚举
```bash
subfinder -dL domains.txt -silent -o all_subs.txt
```

### 4. 递归子域枚举（更全面）
```bash
subfinder -d target.com -recursive -silent -o subs_recursive.txt
```

### 5. 使用全部数据源（最全，最慢）
```bash
subfinder -d target.com -all -silent -o subs_all.txt
```

### 6. 输出 JSON 便于后续处理
```bash
subfinder -d target.com -oJ -silent | jq '.host'
```

### 7. 管道联动 dnsx 过滤存活域名
```bash
subfinder -d target.com -silent | dnsx -resp-only -a -silent
```

### 8. 联动 httpx 进行 Web 探测（完整侦察流水线）
```bash
subfinder -d target.com -silent | \
  dnsx -resp-only -a -silent | \
  httpx -title -tech-detect -status-code -silent
```

### 9. 联动 nuclei 直接漏洞扫描
```bash
subfinder -d target.com -silent | \
  httpx -silent | \
  nuclei -t /root/nuclei-templates/ -silent -o vulns.txt
```

---

## 数据源说明

subfinder 默认聚合多个公开数据源，包括：
- `crtsh` — SSL 证书透明度日志（无需 Key）
- `hackertarget` — 搜索引擎
- `alienvault` — OTX 威胁情报
- `rapiddns` — DNS 数据库
- `bufferover` — DNS 聚合
- `shodan`、`censys`、`virustotal` 等（需 API Key）

配置文件路径：`~/.config/subfinder/provider-config.yaml`

```yaml
# 配置 API Key 示例
shodan:
  - YOUR_SHODAN_KEY
virustotal:
  - YOUR_VT_KEY
censys:
  - YOUR_CENSYS_ID:YOUR_CENSYS_SECRET
```

---

## 结果处理技巧

```bash
# 去重排序
subfinder -d target.com -silent | sort -u > subs_unique.txt

# 统计找到多少个子域名
subfinder -d target.com -silent | wc -l

# 过滤特定关键字（如 dev/test 环境）
subfinder -d target.com -silent | grep -E "dev|test|staging|admin"

# 快速验证哪些子域有 Web 服务
subfinder -d target.com -silent | httpx -silent -ports 80,443,8080,8443
```

---

## 注意事项

- 静默模式 (`-silent`) 下只输出域名，去掉此参数可看到进度和版本信息
- 免费数据源不需要配置 Key，配置 Key 后数据量大幅增加
- 结合 `-recursive` 可发现多级子域名，如 `api.v1.target.com`
- 网络受限环境下部分数据源可能超时，用 `-timeout` 调整
