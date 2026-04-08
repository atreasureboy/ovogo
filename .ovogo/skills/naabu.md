---
name: naabu
description: naabu — 高速端口扫描工具
---

你是 naabu 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# naabu — 高速端口扫描工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 二进制路径 | `/root/go/bin/naabu` |
| 项目来源 | ProjectDiscovery |
| 适用场景 | 快速端口发现、资产端口普查、为 nmap 提供预扫描 |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-host <target>` | 指定目标主机/IP |
| `-l <file>` | 从文件读取目标列表 |
| `-p <ports>` | 指定端口（`80,443`、`1-1000`、`-`全端口） |
| `-top-ports <num>` | 扫描 Top N 端口 |
| `-o <file>` | 输出结果到文件 |
| `-silent` | 静默模式 |
| `-c <num>` | 并发数（默认 25） |
| `-rate <num>` | 每秒发包速率 |
| `-timeout <msec>` | 超时（毫秒） |
| `-retries <num>` | 重试次数 |
| `-Pn` | 跳过 ping 探测 |
| `-nmap` | 发现端口后自动调用 nmap |
| `-nmap-cli <args>` | 传递给 nmap 的参数 |
| `-json` | JSON 格式输出 |
| `-v` | 详细输出 |
| `-exclude-ports <ports>` | 排除特定端口 |
| `-exclude-hosts <hosts>` | 排除特定主机 |
| `-interface <iface>` | 指定网络接口 |
| `-source-ip <ip>` | 指定源 IP |

---

## 典型使用场景

### 1. 基础端口扫描（常用端口）
```bash
naabu -host target.com -p 80,443,8080,8443,22,21,25,53 -silent
```

### 2. 全端口扫描
```bash
naabu -host target.com -p - -silent -o all_ports.txt
```

### 3. Top 1000 端口
```bash
naabu -host target.com -top-ports 1000 -silent
```

### 4. 批量目标扫描
```bash
naabu -l targets.txt -p 80,443,8080,8443 -silent -o web_ports.txt
```

### 5. 子域名端口扫描（联动 subfinder）
```bash
subfinder -d target.com -silent | naabu -p 80,443,8080 -silent
```

### 6. 高速扫描
```bash
naabu -host target.com -p - -rate 10000 -c 50 -silent -o fast_scan.txt
```

### 7. 发现端口后自动 nmap 深度扫描
```bash
naabu -host target.com -top-ports 1000 -silent \
      -nmap -nmap-cli "nmap -sV -sC" -o naabu_nmap.txt
```

### 8. 内网 C 段扫描
```bash
naabu -host 192.168.1.0/24 -p 80,443,22,3389,445 -silent -o internal.txt
```

### 9. 完整侦察流水线
```bash
subfinder -d target.com -silent | \
  naabu -p 80,443,8080,8443 -silent | \
  httpx -sc -title -td -silent | \
  tee recon_result.txt
```

---

## 与 nmap 对比

| 维度 | naabu | nmap |
|------|-------|------|
| 速度 | 极快（SYN + Go并发） | 较慢 |
| 精度 | 端口发现（基础） | 服务识别（详细） |
| 脚本支持 | 无 | 丰富的 NSE 脚本 |
| 推荐场景 | 快速普查开放端口 | 深度服务版本/漏洞检测 |
| 典型组合 | naabu 先找端口 → nmap 深度扫描 | |

---

## 推荐工作流

```bash
# 第一步：naabu 快速发现开放端口（秒级）
naabu -host target.com -p - -rate 5000 -silent -o open_ports.txt

# 第二步：提取端口列表
ports=$(cat open_ports.txt | awk -F: '{print $2}' | tr '\n' ',' | sed 's/,$//')

# 第三步：nmap 精细识别服务
nmap -sV -sC -p "$ports" target.com -oA deep_scan
```

---

## 注意事项

- 需要 root 权限才能执行 SYN 扫描（更快）
- 高速率扫描可能触发防火墙限速，酌情降低 `-rate`
- 全端口扫描（`-p -`）在大目标上耗时较长，建议先用 `top-ports 1000`
- 环境变量设置：`export PATH=$PATH:/root/go/bin`
