---
name: hashcat
description: hashcat — GPU 加速密码破解工具
---

你是 hashcat 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# hashcat — GPU 加速密码破解工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 命令 | `hashcat` |
| 路径 | 系统 PATH 直接可用 |
| 适用场景 | 哈希离线破解、密码恢复、规则攻击 |
| 字典目录 | `/opt/wordlists/` |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-m <mode>` | 哈希类型（见下方速查表） |
| `-a <mode>` | 攻击模式（0=字典，1=组合，3=掩码，6/7=混合） |
| `-o <file>` | 输出破解成功的结果 |
| `-w <level>` | 工作负载级别（1=低，4=噩梦级） |
| `-r <file>` | 规则文件 |
| `--show` | 显示已破解的哈希 |
| `--left` | 显示未破解的哈希 |
| `--force` | 强制运行（忽略警告） |
| `--status` | 运行时显示状态 |
| `--status-timer <sec>` | 状态更新间隔 |
| `--session <name>` | 会话名称（支持断点续传） |
| `--restore` | 恢复上次会话 |
| `--increment` | 掩码渐进模式 |
| `--increment-min <n>` | 最小长度 |
| `--increment-max <n>` | 最大长度 |
| `-O` | 优化内核（加速，限制密码长度≤32） |
| `-S` | 慢候选模式（更准确） |
| `--username` | 哈希文件包含用户名（user:hash 格式） |
| `--potfile-disable` | 不使用 potfile 缓存 |
| `-n <num>` | 加速（Accel）值 |

---

## 哈希类型速查（-m）

| 编号 | 哈希类型 | 常见来源 |
|------|---------|---------|
| `0` | MD5 | 通用 |
| `100` | SHA1 | 通用 |
| `1400` | SHA-256 | 通用 |
| `1000` | NTLM | Windows 本地账户 |
| `5600` | NetNTLMv2 | Responder 捕获 |
| `5500` | NetNTLMv1 | Responder 捕获（旧版） |
| `13100` | Kerberos 5 TGS（Kerberoasting） | GetUserSPNs |
| `18200` | Kerberos 5 AS-REP（AS-REP Roasting） | GetNPUsers |
| `3200` | bcrypt | Web 应用 |
| `1800` | sha512crypt | Linux /etc/shadow |
| `500` | md5crypt | Linux /etc/shadow（旧） |
| `1500` | DES（crypt） | 旧版 Unix |
| `400` | phpBB3/MD5（WordPress 等） | WordPress |
| `2611` | vBulletin < 3.8.5 | 论坛 |
| `11` | Joomla < 2.5.18 | Joomla |
| `2811` | IPB 2.x+ | 论坛 |
| `7400` | sha256crypt | Linux |
| `10800` | SHA-384 | 通用 |
| `1100` | DCC（Domain Cached Credentials） | Windows 域缓存 |
| `2100` | DCC2（mscache2） | Windows 域缓存 v2 |
| `3000` | LM | 老版 Windows |
| `9200` | WPA-PBKDF2-PMKID | WiFi 握手包 |
| `22000` | WPA-PBKDF2-PMKID+EAPOL | WiFi（推荐） |

---

## 攻击模式（-a）

| 编号 | 模式 | 说明 |
|------|------|------|
| `0` | 字典攻击 | 直接使用字典 |
| `1` | 组合攻击 | 两个字典拼接 |
| `3` | 掩码攻击 | 自定义字符集 |
| `6` | 混合（字典+掩码） | 字典后追加掩码 |
| `7` | 混合（掩码+字典） | 掩码前添加字典 |

---

## 典型使用场景

### 1. NTLM 哈希破解（Windows 密码）
```bash
# hashcat 破解 NTLM
hashcat -m 1000 ntlm_hashes.txt /opt/wordlists/rockyou.txt

# 带规则（提高成功率）
hashcat -m 1000 ntlm_hashes.txt /opt/wordlists/rockyou.txt \
        -r /usr/share/hashcat/rules/best64.rule

# 高性能模式
hashcat -m 1000 ntlm_hashes.txt /opt/wordlists/rockyou.txt -w 3 -O
```

### 2. NTLMv2 破解（Responder 捕获）
```bash
hashcat -m 5600 netntlmv2_hashes.txt /opt/wordlists/rockyou.txt

# 带规则
hashcat -m 5600 netntlmv2_hashes.txt /opt/wordlists/rockyou.txt \
        -r /usr/share/hashcat/rules/best64.rule \
        -r /usr/share/hashcat/rules/toggles1.rule
```

### 3. Kerberoasting 破解
```bash
hashcat -m 13100 kerberoast_hashes.txt /opt/wordlists/rockyou.txt
```

### 4. AS-REP Roasting 破解
```bash
hashcat -m 18200 asrep_hashes.txt /opt/wordlists/rockyou.txt
```

### 5. MD5 破解
```bash
hashcat -m 0 md5_hashes.txt /opt/wordlists/rockyou.txt
```

### 6. bcrypt 破解（慢，需要 GPU）
```bash
hashcat -m 3200 bcrypt_hashes.txt /opt/wordlists/rockyou.txt -w 3
```

### 7. Linux shadow 文件破解
```bash
# sha512crypt（现代 Linux）
hashcat -m 1800 shadow_hashes.txt /opt/wordlists/rockyou.txt

# md5crypt（旧版）
hashcat -m 500 shadow_hashes.txt /opt/wordlists/rockyou.txt
```

### 8. WordPress 哈希破解
```bash
hashcat -m 400 wp_hashes.txt /opt/wordlists/rockyou.txt
```

### 9. 掩码攻击（已知密码格式）
```bash
# 8位，大写+数字
hashcat -m 0 hash.txt -a 3 ?u?u?u?u?d?d?d?d

# 大写字母+小写字母+数字，长度6-8
hashcat -m 0 hash.txt -a 3 --increment --increment-min 6 --increment-max 8 ?l?l?l?l?d?d

# 常见密码模式：Password123!
hashcat -m 0 hash.txt -a 3 ?u?l?l?l?l?l?l?d?d?d!
```

**掩码字符集：**
```
?l = 小写字母 (a-z)
?u = 大写字母 (A-Z)
?d = 数字 (0-9)
?s = 特殊字符
?a = 所有字符
?1~?4 = 自定义字符集
```

### 10. 规则攻击（增变体）
```bash
# 单规则文件
hashcat -m 1000 hashes.txt /opt/wordlists/rockyou.txt \
        -r /usr/share/hashcat/rules/best64.rule

# 多规则文件组合
hashcat -m 1000 hashes.txt /opt/wordlists/rockyou.txt \
        -r /usr/share/hashcat/rules/best64.rule \
        -r /usr/share/hashcat/rules/d3ad0ne.rule

# 查看所有可用规则
ls /usr/share/hashcat/rules/
```

### 11. 组合攻击
```bash
hashcat -m 1000 hashes.txt -a 1 \
        /opt/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt \
        /opt/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt
```

### 12. 查看破解结果
```bash
# 显示已破解
hashcat -m 1000 hashes.txt --show

# 输出到文件
hashcat -m 1000 hashes.txt /opt/wordlists/rockyou.txt -o cracked.txt

# 只输出明文密码
hashcat -m 1000 hashes.txt --show --outfile-format 2
```

---

## 常用规则文件

| 规则文件 | 说明 |
|---------|------|
| `best64.rule` | 最佳 64 条规则（推荐首选） |
| `d3ad0ne.rule` | 34000+ 规则（全面） |
| `dive.rule` | 99000+ 规则（耗时） |
| `rockyou-30000.rule` | rockyou 衍生规则 |
| `toggles1.rule` | 大小写变换 |
| `leetspeak.rule` | leet 替换（a→4, e→3 等） |

```bash
# 规则目录
ls /usr/share/hashcat/rules/
```

---

## 哈希识别

```bash
# 使用 hashid 识别哈希类型
hashid hash_value

# 使用 hash-identifier
hash-identifier

# name-that-hash
nth -t 'HASH_VALUE'
```
