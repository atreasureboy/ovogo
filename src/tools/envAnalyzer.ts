/**
 * EnvAnalyzerTool — environment analysis for authorized security assessments
 *
 * Probes target for WAF/EDR/AV/IDS/Sandbox/CDN/LB protections and returns
 * structured reports with evasion recommendations. Used in CTF/authorized
 * penetration testing to understand the defensive posture of the target.
 */

import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import type { Tool, ToolContext, ToolDefinition, ToolResult } from '../core/types.js'
import { executeCommand } from './shellSession.js'

const exec = promisify(execCb)

// ── WAF signatures — 35+ vendors (response pattern → vendor) ────────────────

const WAF_SIGNATURES: Array<{ name: string; patterns: RegExp[]; confidence: number }> = [
  // ── Tier 1: Global cloud WAFs/CDNs (very common) ───────────────────────────
  { name: 'Cloudflare', patterns: [/cf-ray/i, /cloudflare-nginx/i, /cf-cache-status/i, /server:\s*cloudflare/i, /__cf_bm/i, /cf-worker/i], confidence: 0.95 },
  { name: 'AWS CloudFront', patterns: [/x-amz-cf-id/i, /x-amz-cf-pop/i, /x-cache.*cloudfront/i, /via.*cloudfront/i, /server:\s*CloudFront/i], confidence: 0.95 },
  { name: 'AWS WAF', patterns: [/x-amzn-waf/i, /AWS.*WAF/i, /blocked.*aws/i], confidence: 0.9 },
  { name: 'Azure WAF / Front Door', patterns: [/x-azure-ref/i, /x-fd-healthprobe/i, /x-ms-request-id/i, /azure-afd/i, /server:\s*AzureFD/i], confidence: 0.9 },
  { name: 'Akamai', patterns: [/akamai/i, /x-akamai/i, /akamai-ghost/i, /akamai-x-feo/i, /x-akamai-request-id/i], confidence: 0.85 },
  { name: 'Imperva/Incapsula', patterns: [/incapsula/i, /imperva/i, /x-iinfo/i, /visid_incap/i, /incap_ses/i, /_Incapsula_/i], confidence: 0.9 },
  { name: 'Fastly', patterns: [/x-fastly-request-id/i, /fastly-ssl/i, /server:\s*Varnish/i, /x-served-by.*cache/i, /x-fastly/i], confidence: 0.9 },
  { name: 'StackPath', patterns: [/server:\s*StackPath/i, /x-sp-url/i, /sp-edge/i], confidence: 0.85 },
  { name: 'Sucuri', patterns: [/sucuri/i, /x-sucuri/i, /cloudproxy/i, /x-sucuri-id/i], confidence: 0.9 },
  { name: 'KeyCDN', patterns: [/server:\s*KeyCDN/i, /keycdn/i], confidence: 0.85 },
  { name: 'GoDaddy WAF', patterns: [/x-godaddy/i, /server:\s*GoDaddy/i], confidence: 0.8 },

  // ── Tier 1: Enterprise on-prem WAFs (very common in pentest) ──────────────
  { name: 'F5 BIG-IP / Advanced WAF', patterns: [/BigIP/i, /F5-TrafficShield/i, /x-wa-info/i, /X-Cnection/i, /TS\d{8}_/, /BIGipServer/i, /F5_ST/i, /server:\s*F5/i, /BIG-IP/i], confidence: 0.95 },
  { name: 'Fortinet FortiWeb', patterns: [/FortiWeb/i, /fortiwaf/i, /fortiweb/i, /FORTIWAFSID/i, /server:\s*FortiWeb/i], confidence: 0.95 },
  { name: 'Citrix NetScaler / ADC', patterns: [/ns_af/i, /citrix_ns_id/i, /NSC_/i, /set-cookie:.*NSC_/i, /via:\s*NS-CACHE/i, /NetScaler/i], confidence: 0.9 },
  { name: 'Palo Alto Networks', patterns: [/\bPA-VMA\b/i, /hasHikvision-/i, /X-PAN-Auth/i, /PaloAlto/i, /server:\s*PaloAlto/i], confidence: 0.85 },
  { name: 'Barracuda WAF', patterns: [/BNI__BPS/i, /barracuda_/i, /server:\s*BarracudaWAF/i, /barra_counter_session/i], confidence: 0.9 },
  { name: 'Radware AppWall / WAF', patterns: [/X-Radware-/i, /Radware/i, /x-rdwr-/i, /radware_bot/i], confidence: 0.9 },
  { name: 'Wallarm', patterns: [/wallarm/i, /server:\s*wallarm/i, /x-wallarm-/i], confidence: 0.85 },

  // ── ModSecurity & derivatives ───────────────────────────────────────────────
  { name: 'ModSecurity', patterns: [/ModSecurity/i, /mod_security/i, /blocked.*modsecurity/i, /Not Acceptable.*ModSecurity/i, /NOYB/i], confidence: 0.9 },

  // ── Chinese WAF/CDN vendors (high prevalence in APAC) ──────────────────────
  { name: '宝塔 (BT Panel)', patterns: [/宝塔/i, /btwaf/i, /panel\.btpanel\.cn/i, /__jsl_clearance/i], confidence: 0.95 },
  { name: '360 WAF', patterns: [/360wzws/i, /360.*waf/i], confidence: 0.9 },
  { name: '安全狗 (SafeDog)', patterns: [/safedog/i, /safedog.*waf/i], confidence: 0.9 },
  { name: '长亭 (Chaitin)', patterns: [/chaitin.*waf/i, /x-chaitin-waf/i], confidence: 0.85 },
  { name: '安全宝 (Anquanbao)', patterns: [/aqb_cc/i, /server:\s*aqb_cc/i, /anquanbao/i], confidence: 0.9 },
  { name: '云盾 (Yundun)', patterns: [/yundun/i, /server:\s*yundun/i, /YD-Cookie/i], confidence: 0.9 },
  { name: '亿速云 (Yisuo)', patterns: [/yisuo/i, /server:\s*yisuo/i], confidence: 0.85 },
  { name: 'NSFOCUS (绿盟)', patterns: [/nsfocus/i, /server:\s*NSFOCUS/i, /NSFOCUS WAF/i], confidence: 0.9 },
  { name: '启明星辰 (Venustech)', patterns: [/venustech/i, /server:\s*Venustech/i], confidence: 0.85 },
  { name: '天融信 (Topsec)', patterns: [/topsec/i, /server:\s*Topsec/i, /TopsecWAF/i], confidence: 0.85 },
  { name: '知道创宇 (Knownsec)', patterns: [/knownsec/i, /KS-WAF/i, /ali_anti_/i, /JSESSIONID=.*KS_/i], confidence: 0.9 },
  { name: '深信服 (Sangfor)', patterns: [/Sangfor/i, /x-saf-dog/i, /server:\s*Sangfor/i], confidence: 0.9 },
  { name: '华为云 WAF', patterns: [/HuaweiCloudWAF/i, /server:\s*HuaweiCloudWAF/i], confidence: 0.9 },
  { name: '阿里云 WAF / Anti-Bot', patterns: [/x-ali-/i, /Tengine.*waf/i, /slb-id.*waf/i, /ali_/i], confidence: 0.85 },
  { name: '腾讯云 WAF', patterns: [/tencentyun/i, /x-nws-/i, /server:\s*NWSs/i, /x-nws-log-/i], confidence: 0.85 },
  { name: '网宿 CDN (Wangsu)', patterns: [/Server:\s*Wangsu/i, /cdn-cache/i, /Cdn-Cache/i, /wscdn/i], confidence: 0.85 },
  { name: 'ChinaCache', patterns: [/ChinaCache/i, /CCDLB/i, /server:\s*ChinaCache/i], confidence: 0.9 },
  { name: 'CDNetworks', patterns: [/CDNetworks/i, /X-CDN/i, /server:\s*CDNetworks/i], confidence: 0.85 },

  // ── Misc ────────────────────────────────────────────────────────────────────
  { name: 'Verizon EdgeCast / WAF', patterns: [/ECD \(.*\)/i, /X-EC-Debug/i, /server:\s*ECD/i], confidence: 0.85 },
]

// ── EDR/AV process/service/driver names — 25+ products ──────────────────────

interface ProductIndicators {
  product: string
  processes: RegExp[]
  services: RegExp[]
  drivers: RegExp[]
}

const EDR_INDICATORS: ProductIndicators[] = [
  // ── Microsoft ───────────────────────────────────────────────────────────────
  {
    product: 'Windows Defender',
    processes: [/MsMpEng/i, /MpCmdRun/i, /NisSrv/i, /SecurityHealth/i],
    services: [/WinDefend/i, /wscsvc/i, /SecurityHealth/i],
    drivers: [/WdFilter/i, /MpKsl/i, /WdBoot/i],
  },
  {
    product: 'Microsoft Defender for Endpoint',
    processes: [/MsSense/i, /SenseIR/i, /SenseNdr/i, /SenseCnc/i, /MsMpEng/i],
    services: [/Sense/i, /Mdatp/i],
    drivers: [/WdBoot/i, /WdDev/i, /WdFilter/i],
  },

  // ── CrowdStrike / SentinelOne / Carbon Black ────────────────────────────────
  {
    product: 'CrowdStrike Falcon',
    processes: [/CSFalcon/i, /CSAgent/i, /csfalconservice/i, /CSFirmwareAnalysis/i],
    services: [/CrowdStrike/i, /CSFalconService/i, /csfalconservice/i],
    drivers: [/CsDeviceControl/i, /CSAgent/i],
  },
  {
    product: 'SentinelOne',
    processes: [/SentinelAgent/i, /SentinelAgentWorker/i, /LogCollector/i, /SentinelUI/i, /SentinelStaticEngine/i, /sentinelagent/i],
    services: [/SentinelAgent/i, /SentinelStatic/i, /sentinelone/i],
    drivers: [/Sentinel/i, /SentinelDriver/i],
  },
  {
    product: 'Carbon Black',
    processes: [/cb.exe/i, /RepMgr/i, /CbDefense/i, /CbOsSensor/i],
    services: [/CbDefense/i, /CarbonBlack/i, /cbagent/i],
    drivers: [/CbDefense/i, /carbonblack/i],
  },
  {
    product: 'Tanium',
    processes: [/TaniumClient/i, /TaniumCX/i, /TaniumDetect/i, /TaniumIndex/i, /TaniumTrace/i],
    services: [/TaniumClient/i, /TaniumDetect/i],
    drivers: [/TaniumApiDrv/i, /TaniumNDIS/i],
  },

  // ── Symantec / Trellix ──────────────────────────────────────────────────────
  {
    product: 'Symantec Endpoint Protection',
    processes: [/ccSvc/i, /SmcGui/i, /RTVscan/i, /SepMasterService/i],
    services: [/SepMasterService/i, /Symantec/i, /ccEvtMgr/i],
    drivers: [/SRTSP/i, /SymEFASI/i, /Sysplant/i],
  },
  {
    product: 'Trellix (FireEye successor)',
    processes: [/Trellix/i, /FireEye/i, /xagt.exe/i, /MfeEpe/i],
    services: [/FireEye/i, /xagt/i, /Trellix/i],
    drivers: [/fe_kern/i, /mfe/i],
  },

  // ── ESET / Bitdefender / Sophos / Avast / Malwarebytes ─────────────────────
  {
    product: 'ESET',
    processes: [/ekrn/i, /egui/i, /ehtrjr/i, /ehdrv/i, /eamonm/i, /eset/i],
    services: [/ekrn/i, /ESET/i, /eamonm/i, /ehdrv/i],
    drivers: [/ehdrv/i, /eamonm/i, /ekrn/i],
  },
  {
    product: 'Bitdefender',
    processes: [/bdagent/i, /vsserv/i, /bdredline/i, /updatesrv/i, /bdservicehost/i],
    services: [/bdredline/i, /VSSERV/i, /bdagent/i],
    drivers: [/bdfndisf/i, /bdselfpr/i, /bdfsfltr/i],
  },
  {
    product: 'Sophos Intercept X',
    processes: [/SophosHealth/i, /SophosUI/i, /SAVOnAccess/i, /swi_service/i, /SophosFileScanner/i, /SAVAdminService/i],
    services: [/Sophos/i, /SAVService/i, /swi_service/i],
    drivers: [/Sophos/i, /SophosElam/i],
  },
  {
    product: 'Avast / AVG',
    processes: [/avastsvc/i, /avastui/i, /aswEngSrv/i, /avgui/i, /avastnm/i, /avgsvc/i],
    services: [/avast/i, /AVG/i, /aswBcc/i],
    drivers: [/aswSnx/i, /aswVmm/i, /avgArPot/i],
  },
  {
    product: 'Malwarebytes',
    processes: [/mbam/i, /mbamservice/i, /mbamtray/i, /Malwarebytes/i],
    services: [/MBAMService/i, /Malwarebytes/i],
    drivers: [/mbamwatchdog/i, /mbamchameleon/i],
  },
  {
    product: 'Webroot',
    processes: [/WRSA/i, /WRSVC/i, /WRCore/i, /Webroot/i],
    services: [/WRSVC/i, /Webroot/i],
    drivers: [/WRCore/i, /WRKrn/i],
  },

  // ── Palo Alto Cortex XDR / Cybereason / DeepInstinct / Cylance ──────────────
  {
    product: 'Palo Alto Cortex XDR',
    processes: [/cyserver/i, /cytray/i, /Cyvera/i, /Cybereason/i, /cysandbox/i],
    services: [/cyserver/i, /CyveraService/i, /cortex/i],
    drivers: [/CyverDrv/i, /cyvrmtgn/i],
  },
  {
    product: 'Cybereason',
    processes: [/CybereasonSensor/i, /CybereasonAV/i, /CybereasonRansomwareProtection/i, /minionhost/i],
    services: [/CybereasonSensor/i, /minion/i],
    drivers: [/Cybereason/i, /CRExec/i],
  },
  {
    product: 'DeepInstinct',
    processes: [/DeepInstinctService/i, /DeepInstinct/i, /DI-Agent/i],
    services: [/DeepInstinct/i, /DI-Service/i],
    drivers: [/DeepInstinctDrv/i, /DInsmflt/i],
  },
  {
    product: 'Cylance',
    processes: [/CylanceSvc/i, /CylanceUI/i, /CylanceProtect/i],
    services: [/CylanceSvc/i, /Cylance/i],
    drivers: [/CylanceDrv/i, /CyProtectDrv/i],
  },

  // ── FireEye / McAfee / Trend / Kaspersky ────────────────────────────────────
  {
    product: 'FireEye/Mandiant',
    processes: [/xagt/i, /xfm/i, /FireEye/i],
    services: [/Xagt/i, /XpfAgent/i, /FireEye/i],
    drivers: [/fe_kern/i, /xfeXfa/i],
  },
  {
    product: 'McAfee ENS / Trellix',
    processes: [/McAfee/i, /masvc/i, /mfeesp/i, /mfemms/i, /MfeEpe/i],
    services: [/McAfee/i, /masvc/i, /MfeEpe/i],
    drivers: [/mfe/i, /mfenc/i, /mfewfpk/i],
  },
  {
    product: 'Trend Micro Vision One',
    processes: [/TmListen/i, /ntrtscan/i, /tmlisten/i, /PccNTMon/i, /ds_agent/i, /dsa/i],
    services: [/Trend/i, /ntrtscan/i, /ds_agent/i, /AEGIS/i],
    drivers: [/tmtdi/i, /tmpre/i, /tmcomm/i, /TMEBC/i],
  },
  {
    product: 'Kaspersky',
    processes: [/avp/i, /klnagent/i, /ksweb/i, /avpui/i],
    services: [/klnagent/i, /AVP/i, /Kaspersky/i],
    drivers: [/klif/i, /kl1/i, /klim6/i, /klhk/i],
  },
  {
    product: 'Elastic EDR / Endpoint Security',
    processes: [/winlogbeat/i, /elastic-agent/i, /EndpointSecurity/i, /elastic-endpoint/i],
    services: [/ElasticEndpoint/i, /winlogbeat/i, /elastic-agent/i],
    drivers: [/elastic-endpoint-driver/i, /elastic-endpoint/i],
  },
]

// ── IDS/IPS process indicators (network-level detection) ────────────────────

interface NetworkSensorIndicators {
  product: string
  processes: RegExp[]
  configPaths: RegExp[]
}

const IDS_INDICATORS: NetworkSensorIndicators[] = [
  {
    product: 'Snort',
    processes: [/snort(?:\.exe|-)?/i],
    configPaths: [/\/etc\/snort\//i, /\/etc\/snort\.conf/i, /snort\.lua/i, /var\/log\/snort/i],
  },
  {
    product: 'Suricata',
    processes: [/suricata(?:\.exe)?/i],
    configPaths: [/\/etc\/suricata\//i, /suricata\.yaml/i, /var\/log\/suricata/i],
  },
  {
    product: 'Zeek (formerly Bro)',
    processes: [/zeek(?:\.exe)?/i, /\b bro /i],
    configPaths: [/\/opt\/zeek\//i, /\/etc\/zeek\//i, /zeek\.ctl/i],
  },
  {
    product: 'OSSEC',
    processes: [/ossec-agent/i, /ossec-rootcheck/i, /ossec-logcollector/i, /ossec-syscheckd/i, /ossec-execd/i],
    configPaths: [/\/var\/ossec\//i, /ossec\.conf/i],
  },
  {
    product: 'Wazuh',
    processes: [/wazuh-agent/i, /wazuh-modulesd/i, /wazuh-monitord/i, /wazuh-logcollector/i],
    configPaths: [/\/var\/ossec\/etc\//i, /\/etc\/wazuh\//i],
  },
  {
    product: 'Fail2ban',
    processes: [/fail2ban-server/i, /fail2ban-client/i],
    configPaths: [/\/etc\/fail2ban\//i, /fail2ban\.local/i, /var\/log\/fail2ban\.log/i],
  },
  {
    product: 'Cisco Firepower / Sourcefire',
    processes: [/Sourcefire/i, /\bsfmgmt/i, /\bsfmbean/i, /\bsfmon/i],
    configPaths: [/\/etc\/sf\//i, /sf\.conf/i],
  },
  {
    product: 'FortiGate IPS',
    processes: [/fortigate/i, /fgfmd/i, /fnbamd/i],
    configPaths: [/\/data\/etc\//i, /fortigate\.conf/i],
  },
  {
    product: 'Check Point IPS',
    processes: [/checkpoint/i, /\bfwd/i, /\bfwm/i, /\bcpd/i],
    configPaths: [/\$FWDIR\//i, /\/etc\/cp\//i, /objects\.C$/i],
  },
  {
    product: 'pfSense / OPNsense IDS',
    processes: [/pfSense/i, /OPNsense/i, /snort\.sh/i],
    configPaths: [/\/conf\/config\.xml/i, /\/cf\/conf\//i],
  },
]

// ── Sandbox indicators (analysis environments) ──────────────────────────────

interface SandboxIndicator {
  product: string
  files: RegExp[]
  registry?: RegExp[]
  processes?: RegExp[]
}

const SANDBOX_INDICATORS: SandboxIndicator[] = [
  { product: 'Cuckoo Sandbox', files: [/\/usr\/share\/cuckoo\//i, /cuckoo\.log/i, /cuckoo\.db/i, /agent\.py/i], processes: [/python.*cuckoo/i, /cuckoo\.py/i] },
  { product: 'Joe Sandbox', files: [/joebox/i, /joeboxcontrol/i, /JoeSandbox/i], processes: [/joebox/i, /JoeSandbox/i] },
  { product: 'Hybrid Analysis', files: [/hybrid-analysis/i], processes: [/falcon-sandbox\.exe/i] },
  { product: 'Any.run', files: [/any\.run/i, /anyrun/i], processes: [/anyrun/i] },
  { product: 'VMRay', files: [/vmray/i, /VMRay/i], registry: [/VMRay/i], processes: [/vmray/i] },
  { product: 'CrowdStrike Falcon Sandbox', files: [/falconsandbox/i], processes: [/CSAgent/i] },
  { product: 'Intezer Analyze', files: [/intezer/i], processes: [/intezer/i] },
  { product: 'Cisco Threat Grid', files: [/threatgrid/i, /TGClient/i], processes: [/tgwatch/i] },
  { product: 'FireEye MVX / AX', files: [/fireeye.*mvx/i, /mvx\.conf/i], processes: [/xagt/i] },
  { product: 'OPSWAT MetaDefender', files: [/metadefender/i, /opswat/i], processes: [/opswat/i] },
  { product: 'VirusTotal (cuckoo fork)', files: [/virustotal/i, /cuckoo-vt/i], processes: [/cuckoo/i] },
]

// ── VM/Sandbox generic indicators ───────────────────────────────────────────

const VM_MAC_PREFIXES = [
  '00:0c:29', '00:50:56', '00:05:69', '08:00:27', '00:1c:14', // VMware
  '00:15:5d',                                                   // Hyper-V
  '52:54:00',                                                   // QEMU/KVM
  '00:16:3e',                                                   // Xen
  '00:1c:42',                                                   // Parallels
  '0a:00:27',                                                   // VirtualBox (rare)
  '00:0a:95',                                                   // QEMU (rare)
  '00:e0:4c',                                                   // Realtek (often VirtualBox variant)
]

const VM_HYPERVISOR_STRINGS = [
  /VMware/i, /VirtualBox/i, /QEMU/i, /KVM/i, /Hyper-V/i, /Microsoft Hv/i, /Xen/i, /Parallels/i, /bhyve/i,
]

const VM_DEVICES = [
  /VMware Virtual.*Disk/i, /QEMU.*Harddisk/i, /VBOX HARDDISK/i, /Virtual HD/i,
]

const SANDBOX_USERNAMES = [
  'sandbox', 'malware', 'virus', 'test', 'av', 'vm', 'debug',
  'snort', 'honey', 'cuckoo', 'analyst', 'curlsandbox', 'user',
  'admin', 'administrator', 'john', 'jane', 'miller', 'maltest',
]

const SANDBOX_HOSTNAMES = [
  /sandbox/i, /malware/i, /cuckoo/i, /vbox/i, /virtual/i, /vmware/i,
  /qemu/i, /analysis/i, /sample/i, /infected/i, /honeypot/i,
]

// ── CDN / Load Balancer / Reverse Proxy fingerprinting (passive) ────────────

interface NetworkFingerprint {
  product: string
  headerPatterns: RegExp[]
  serverPatterns: RegExp[]
}

const NETWORK_FINGERPRINTS: NetworkFingerprint[] = [
  // CDNs
  { product: 'Cloudflare CDN', headerPatterns: [/cf-ray:/i, /cf-cache-status:/i, /cf-worker/i], serverPatterns: [/cloudflare/i] },
  { product: 'AWS CloudFront', headerPatterns: [/x-amz-cf-id:/i, /x-amz-cf-pop:/i, /via:.*cloudfront/i, /x-cache:.*cloudfront/i], serverPatterns: [/CloudFront/i] },
  { product: 'Akamai CDN', headerPatterns: [/x-akamai-/i, /akamai-grn/i, /x-akamai-request-id/i], serverPatterns: [/AkamaiGHost/i, /Akamai/i] },
  { product: 'Fastly CDN', headerPatterns: [/x-fastly-request-id:/i, /x-served-by:.*cache/i, /x-fastly/i], serverPatterns: [/Varnish/i, /Fastly/i] },
  { product: 'Azure Front Door', headerPatterns: [/x-azure-ref:/i, /x-fd-healthprobe:/i, /x-azure-/i], serverPatterns: [/AzureFD/i] },
  { product: 'Google Cloud CDN', headerPatterns: [/via:.*google/i, /x-goog-/i, /server:.*gfe/i], serverPatterns: [/gfe/i, /Google Frontend/i] },

  // Load balancers
  { product: 'F5 BIG-IP LTM', headerPatterns: [/BIGipServer/i, /\bTS\d{8}_/i, /x-wa-info/i, /F5/i], serverPatterns: [/BigIP/i, /BIG-IP/i] },
  { product: 'Citrix NetScaler ADC', headerPatterns: [/NSC_/i, /ns_af/i, /set-cookie:.*citrix_ns_id/i], serverPatterns: [/NetScaler/i, /NS-CACHE/i] },
  { product: 'HAProxy', headerPatterns: [], serverPatterns: [/HAProxy/i] },
  { product: 'AWS ELB / ALB', headerPatterns: [/awselb/i, /x-amzn-/i, /x-amz-requestid/i, /server:.*awselb/i], serverPatterns: [/awselb/i] },
  { product: 'A10 Networks', headerPatterns: [/AX-[A-F0-9]+/i, /a10/i], serverPatterns: [/A10/i] },
  { product: 'NGINX Plus', headerPatterns: [], serverPatterns: [/nginx\+/i] },

  // Reverse proxies
  { product: 'NGINX', headerPatterns: [], serverPatterns: [/nginx/i] },
  { product: 'Apache HTTPD', headerPatterns: [], serverPatterns: [/Apache/i, /\bhttpd\b/i] },
  { product: 'IIS', headerPatterns: [], serverPatterns: [/Microsoft-IIS/i, /IIS\//i] },
  { product: 'Lighttpd', headerPatterns: [], serverPatterns: [/lighttpd/i] },
  { product: 'Caddy', headerPatterns: [], serverPatterns: [/Caddy/i] },
  { product: 'Traefik', headerPatterns: [], serverPatterns: [/Traefik/i] },
  { product: 'Envoy', headerPatterns: [/x-envoy-/i, /x-request-id/i], serverPatterns: [/envoy/i] },
]

// ── Tool implementation ──────────────────────────────────────────────────────

interface EnvAnalyzerInput {
  target: string
  analyze_mode: 'waf' | 'edr' | 'sandbox' | 'network' | 'all'
  port?: number
  shell_session_id?: string
}

export class EnvAnalyzerTool implements Tool {
  name = 'EnvAnalyzer'

  definition: ToolDefinition = {
    type: 'function',
    function: {
      name: 'EnvAnalyzer',
      description: `Analyze target environment for WAF/EDR/IDS/sandbox/CDN/LB protections in authorized security assessments.

## Modes
- analyze_mode: 'waf' = WAF detection (HTTP fingerprinting, 35+ vendors), 'edr' = EDR/AV detection (process/service/driver, 25+ products), 'sandbox' = sandbox/VM detection (indicators + analysis environments), 'network' = passive CDN/LB/proxy fingerprinting, 'all' = full scan
- target: target URL (e.g., http://1.2.3.4 or http://example.com)
- port: optional port (default 80/443)
- shell_session_id: if you already have shell access, pass session_id for remote EDR/sandbox/IDS analysis

## Coverage highlights
- WAF: Cloudflare, AWS CloudFront+WAF, Azure WAF, Akamai, Fastly, StackPath, F5 BIG-IP, Fortinet FortiWeb, Citrix NetScaler, Palo Alto, Barracuda, Radware, Wallarm, Sucuri, ModSecurity, plus 18+ Chinese WAFs/CDNs (BT, 360, SafeDog, Chaitin, Anquanbao, Yundun, NSFOCUS, Venustech, Topsec, Knownsec, Sangfor, Huawei/Aliyun/Tencent Cloud, Wangsu, ChinaCache, CDNetworks)
- EDR/AV: Defender, Defender for Endpoint, CrowdStrike, SentinelOne, Carbon Black, Tanium, Symantec, Trellix, ESET, Bitdefender, Sophos, Avast, Malwarebytes, Webroot, Cortex XDR, Cybereason, DeepInstinct, Cylance, FireEye, McAfee, Trend Micro Vision One, Kaspersky, Elastic EDR
- IDS/IPS: Snort, Suricata, Zeek, OSSEC, Wazuh, Fail2ban, Cisco Firepower, FortiGate, Check Point, pfSense/OPNsense
- Sandbox: Cuckoo, Joe Sandbox, Hybrid Analysis, Any.run, VMRay, Falcon Sandbox, Intezer, Threat Grid, OPSWAT MetaDefender`,
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target URL (e.g., http://1.2.3.4)' },
          analyze_mode: { type: 'string', enum: ['waf', 'edr', 'sandbox', 'network', 'all'], description: 'Analysis mode (network = passive CDN/LB fingerprinting, no shell needed)' },
          port: { type: 'number', description: 'Target port (default parsed from URL)' },
          shell_session_id: { type: 'string', description: 'Existing shell session ID for remote EDR/sandbox/IDS analysis' },
        },
        required: ['target', 'analyze_mode'],
      },
    },
  }

  async execute(input: Record<string, unknown>, context: ToolContext): Promise<ToolResult> {
    const { target, analyze_mode, port, shell_session_id } = input as unknown as EnvAnalyzerInput

    const results: string[] = []
    const recommendations: string[] = []

    try {
      if (analyze_mode === 'waf' || analyze_mode === 'all') {
        const wafResult = await this.detectWAF(target, port)
        results.push(wafResult.report)
        if (wafResult.detected) {
          recommendations.push(...wafResult.recommendations)
        }
      }

      if ((analyze_mode === 'network' || analyze_mode === 'all')) {
        const netResult = await this.detectNetwork(target, port)
        results.push(netResult.report)
        if (netResult.detected) {
          recommendations.push(...netResult.recommendations)
        }
      }

      if ((analyze_mode === 'edr' || analyze_mode === 'all') && shell_session_id) {
        const edrResult = await this.detectEDR(shell_session_id, context)
        results.push(edrResult.report)
        if (edrResult.detected) {
          recommendations.push(...edrResult.recommendations)
        }
        const idsResult = await this.detectIDS(shell_session_id, context)
        results.push(idsResult.report)
        if (idsResult.detected) {
          recommendations.push(...idsResult.recommendations)
        }
      }

      if ((analyze_mode === 'sandbox' || analyze_mode === 'all') && shell_session_id) {
        const sandboxResult = await this.detectSandbox(shell_session_id, context)
        results.push(sandboxResult.report)
        if (sandboxResult.detected) {
          recommendations.push(...sandboxResult.recommendations)
        }
      }
    } catch (err) {
      results.push(`[Analysis Exception] ${(err as Error).message}`)
      results.push('Falling back to default evasion strategy (base64 encoding + chunked transfer).')
    }

    if (results.length === 0) {
      return {
        content: `[EnvAnalyzer] No analysis executed.
Reason: analyze_mode="${analyze_mode}" but no shell_session_id (EDR/IDS/sandbox analysis requires shell access).
WAF and network analysis attempted but target may be unreachable.

Recommend default evasion strategy.`,
        isError: false,
      }
    }

    const output = [
      '[EnvAnalyzer] Environment Analysis Report',
      '═'.repeat(50),
      ...results,
      '',
      '── Recommendations ──',
      recommendations.length > 0 ? recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n') : 'No special protections detected. Standard techniques should work.',
      '',
      'TechniqueGenerator Usage:',
      `  TechniqueGenerator({ technique: "corresponding technique", payload: "original payload", analysis_context: { waf: "detected WAF", edr: "detected EDR" } })`,
    ].join('\n')

    return { content: output, isError: false }
  }

  // ── WAF Detection ──────────────────────────────────────────────────────

  private async detectWAF(target: string, port?: number): Promise<{ detected: boolean; report: string; recommendations: string[] }> {
    const recommendations: string[] = []

    // Try wafw00f first
    try {
      const { stdout } = await exec(`wafw00f -a "${target}" 2>/dev/null || true`)
      const wafMatch = stdout.match(/Generic\s+detection\s+found:\s+(\S[^\n]+)/) || stdout.match(/identified\s+following\s+WAF:\s*(\S[^\n]+)/i)
      if (wafMatch && wafMatch[1].trim() && !stdout.includes('No WAF detected')) {
        const wafName = wafMatch[1].trim()
        recommendations.push(`WAF "${wafName}" confirmed. Use TechniqueGenerator({ technique: "waf_evasion" }) to generate evasion payloads`)
        recommendations.push('Chunked transfer encoding: Transfer-Encoding: chunked')
        recommendations.push('HTTP parameter pollution: same parameter sent multiple times')
        return { detected: true, report: `[WAF] Detected: ${wafName}\nMethod: wafw00f`, recommendations }
      }
    } catch { /* wafw00f not available */ }

    // Manual curl probes
    const probes = [
      { url: `${target}/?id=1' OR '1'='1`, headers: '' },
      { url: `${target}/../../../etc/passwd`, headers: '' },
      { url: target, headers: '-H "User-Agent: \' OR 1=1--"' },
      { url: target, headers: '-H "X-Forwarded-For: 127.0.0.1"' },
      { url: `${target.toLowerCase()}`, headers: '' },
    ]

    const allMatches: Array<{ name: string; confidence: number }> = []

    for (const probe of probes) {
      try {
        const { stdout, stderr } = await exec(
          `curl -sS -m 8 -D - ${probe.headers} "${probe.url}" 2>&1 | head -100`,
        )
        const combined = stdout + stderr

        for (const sig of WAF_SIGNATURES) {
          let matchCount = 0
          for (const pattern of sig.patterns) {
            if (pattern.test(combined)) matchCount++
          }
          if (matchCount >= 1) {
            const existing = allMatches.find((m) => m.name === sig.name)
            if (existing) {
              existing.confidence = Math.max(existing.confidence, sig.confidence)
            } else {
              allMatches.push({ name: sig.name, confidence: sig.confidence })
            }
          }
        }
      } catch {
        // Timeout or connection refused — might be WAF blocking
      }
    }

    // Check for generic blocking patterns
    let genericBlockDetected = false
    try {
      const { stdout: normalStatus } = await exec(`curl -sS -m 8 -o /dev/null -w "%{http_code}" "${target}" 2>/dev/null || echo "000"`)
      const { stdout: blockStatus } = await exec(`curl -sS -m 8 -o /dev/null -w "%{http_code}" "${target}/?id=1'+OR+1%3D1--" 2>/dev/null || echo "000"`)
      if (normalStatus !== blockStatus && (blockStatus === '403' || blockStatus === '406' || blockStatus === '503' || blockStatus === '429')) {
        genericBlockDetected = true
      }
    } catch { /* ignore */ }

    if (allMatches.length > 0) {
      const sorted = allMatches.sort((a, b) => b.confidence - a.confidence)
      const summary = sorted.map((m) => `${m.name} (${(m.confidence * 100).toFixed(0)}%)`).join(', ')

      for (const m of sorted) {
        recommendations.push(`WAF "${m.name}" confirmed (confidence: ${(m.confidence * 100).toFixed(0)}%)`)
        recommendations.push(`Use TechniqueGenerator({ technique: "waf_evasion", analysis_context: { waf: "${m.name}" } })`)
      }
      recommendations.push('Recommended: chunked transfer encoding / HTTP parameter pollution / Unicode encoding / SQL comment insertion')
      recommendations.push('Recommended per-WAF technique: see waf_evasion technique variants — Cloudflare/Akamai/CloudFront/CDN require different bypass approaches')

      return {
        detected: true,
        report: `[WAF] Detected ${sorted.length} WAF signature(s): ${summary}\nMethod: manual HTTP probes`,
        recommendations,
      }
    }

    if (genericBlockDetected) {
      recommendations.push('Possible WAF/IP restriction detected (403 on malicious probes, normal on clean requests)')
      recommendations.push('Use TechniqueGenerator({ technique: "waf_evasion" }) to generate evasion payloads')
      recommendations.push('Reduce request rate, use random User-Agent, add legitimate headers')
      return {
        detected: true,
        report: '[WAF] Suspected WAF/IP restriction (generic blocking pattern)\nMethod: status code comparison',
        recommendations,
      }
    }

    return { detected: false, report: '[WAF] No WAF protections detected', recommendations: [] }
  }

  // ── Network/CDN/LB Detection (passive, no shell required) ───────────────

  private async detectNetwork(target: string, _port?: number): Promise<{ detected: boolean; report: string; recommendations: string[] }> {
    const recommendations: string[] = []
    const matches: Array<{ category: string; product: string; confidence: number }> = []

    let headerOutput = ''
    try {
      const { stdout } = await exec(`curl -sS -m 8 -D - -o /dev/null "${target}" 2>&1 | head -50`)
      headerOutput = stdout
    } catch { /* ignore */ }

    if (!headerOutput.trim()) {
      return { detected: false, report: '[Network] Target unreachable for passive fingerprinting', recommendations: [] }
    }

    for (const fp of NETWORK_FINGERPRINTS) {
      let matched = false
      let confidence = 0
      for (const pattern of fp.headerPatterns) {
        if (pattern.test(headerOutput)) {
          matched = true
          confidence = Math.max(confidence, 0.9)
        }
      }
      for (const pattern of fp.serverPatterns) {
        if (pattern.test(headerOutput)) {
          matched = true
          confidence = Math.max(confidence, 0.85)
        }
      }
      if (matched) {
        let category = 'Other'
        if (fp.product.includes('CDN')) category = 'CDN'
        else if (fp.product.includes('LTM') || fp.product.includes('ADC') || fp.product.includes('ELB') || fp.product.includes('HAProxy') || fp.product.includes('A10')) category = 'Load Balancer'
        else if (fp.product.includes('NGINX') || fp.product.includes('Apache') || fp.product.includes('IIS') || fp.product.includes('Lighttpd') || fp.product.includes('Caddy') || fp.product.includes('Traefik') || fp.product.includes('Envoy')) category = 'Reverse Proxy'
        matches.push({ category, product: fp.product, confidence })
      }
    }

    // Geo-restriction signals
    const isGeoBlocked = /451\s+Unavailable/i.test(headerOutput) ||
      (await exec(`curl -sS -m 8 -o /dev/null -w "%{http_code}" "${target}" 2>/dev/null || echo "000"`).then((r) => r.stdout.trim())).match(/^403$/)

    // WAF overlap: if we detected a WAF, also note it as CDN if applicable
    for (const sig of WAF_SIGNATURES) {
      for (const pattern of sig.patterns) {
        if (pattern.test(headerOutput)) {
          const already = matches.find((m) => m.product === sig.name)
          if (!already) {
            matches.push({ category: 'WAF/CDN', product: sig.name, confidence: sig.confidence })
          }
          break
        }
      }
    }

    if (matches.length > 0) {
      const grouped = new Map<string, string[]>()
      for (const m of matches) {
        const list = grouped.get(m.category) ?? []
        list.push(`${m.product} (${(m.confidence * 100).toFixed(0)}%)`)
        grouped.set(m.category, list)
      }
      const lines: string[] = ['[Network] Passive fingerprinting:']
      for (const [cat, items] of grouped) {
        lines.push(`  ${cat}: ${items.join(', ')}`)
      }
      if (isGeoBlocked) {
        lines.push(`  Geo-restriction: HTTP 451 or 403 detected (likely geo-blocked)`)
      }

      // Per-category recommendations
      for (const m of matches) {
        if (m.category === 'CDN' || m.category === 'WAF/CDN') {
          recommendations.push(`Behind ${m.product}: rotate User-Agent, randomize source IP via residential proxy if rate-limited`)
          recommendations.push(`CDN edge: true origin may be revealed via X-Original-URL, X-Forwarded-Server, or Origin header probing`)
        }
        if (m.category === 'Load Balancer') {
          recommendations.push(`Load Balancer ${m.product}: try virtual host brute to find other apps behind same LB`)
          recommendations.push(`Session affinity: check Set-Cookie for routing tokens (e.g., NSC_, BIGipServer, JSESSIONID)`)
        }
        if (m.category === 'Reverse Proxy') {
          recommendations.push(`Reverse proxy ${m.product}: check version-specific CVEs (NGINX, Apache, IIS)`)
        }
      }
      if (isGeoBlocked) {
        recommendations.push('Geo-blocked: try residential/VPN proxy from approved regions')
      }

      return { detected: true, report: lines.join('\n'), recommendations }
    }

    return { detected: false, report: '[Network] No CDN/LB/reverse proxy fingerprint identified', recommendations: [] }
  }

  // ── EDR/AV Detection (requires shell access) ──────────────────────────────

  private async detectEDR(shellSessionId: string, _context: ToolContext): Promise<{ detected: boolean; report: string; recommendations: string[] }> {
    const detected: string[] = []
    const recommendations: string[] = []

    const { output: procList, success } = await executeCommand(
      shellSessionId,
      `tasklist 2>/dev/null || ps aux 2>/dev/null | head -200 || true`,
      { timeout: 10_000 },
    )

    if (!success || !procList.trim()) {
      return {
        detected: false,
        report: `[EDR] Shell session "${shellSessionId}" unreachable or returned no output.\nRun manually:\n  tasklist | findstr /I "CSFalcon Sentinel MsMpEng ccSvc RepMgr avp ekrn bdagent cyserver Sophos Trellix Tanium Cylance Cybereason Malwarebytes WRSA WinDefend MsSense"\n  sc query | findstr /I "WinDefend CrowdStrike Sentinel Trend ekrn vsserv Sophos Cybereason Tanium Cyvera MsSense"\n  driverquery | findstr /I "WdFilter CsDeviceControl SRTSP klif ekrn bdfndisf CyverDrv SophosElam DeepInstinct"`,
        recommendations: ['Assume EDR presence on Windows targets. Prepare AMSI bypass proactively.'],
      }
    }

    for (const edr of EDR_INDICATORS) {
      for (const pattern of edr.processes) {
        if (pattern.test(procList)) {
          detected.push(edr.product)
          recommendations.push(`${edr.product} confirmed. AMSI bypass should be performed before any PowerShell execution`)
          recommendations.push(`Use TechniqueGenerator({ technique: "amsi_bypass", platform: "windows", analysis_context: { edr: "${edr.product}" } })`)
          recommendations.push('Avoid disk writes — use in-memory execution or fileless techniques')
          if (edr.product.includes('Defender')) {
            recommendations.push('Defender: consider adding exclusion path via Add-MpPreference -ExclusionPath')
          }
          if (edr.product.includes('CrowdStrike') || edr.product.includes('SentinelOne') || edr.product.includes('Cybereason')) {
            recommendations.push(`${edr.product}: kernel-level driver monitoring — avoid direct syscalls, use unhooked ntdll via indirect syscalls`)
          }
          if (edr.product.includes('Kaspersky') || edr.product.includes('Trend Micro') || edr.product.includes('Bitdefender')) {
            recommendations.push(`${edr.product}: strong YARA + memory scanning — encrypt payload sections with rolling RC4`)
          }
          break
        }
      }
    }

    if (detected.length > 0) {
      const unique = Array.from(new Set(detected))
      return {
        detected: true,
        report: `[EDR/AV] Detected on ${shellSessionId}: ${unique.join(', ')}\nMethod: remote process list matching`,
        recommendations,
      }
    }

    return {
      detected: false,
      report: `[EDR/AV] No known EDR/AV processes detected on ${shellSessionId}`,
      recommendations: [],
    }
  }

  // ── IDS/IPS Detection (requires shell access) ───────────────────────────

  private async detectIDS(shellSessionId: string, _context: ToolContext): Promise<{ detected: boolean; report: string; recommendations: string[] }> {
    const detected: string[] = []
    const recommendations: string[] = []

    const commands = [
      `ps aux 2>/dev/null | head -200 || tasklist 2>/dev/null || true`,
      `ls -la /etc/snort /etc/suricata /etc/zeek /opt/zeek /var/ossec /etc/wazuh /etc/fail2ban 2>/dev/null || true`,
      `find / -name "snort.conf" -o -name "suricata.yaml" -o -name "zeek.ctl" 2>/dev/null | head -5 || true`,
    ]

    let combined = ''
    for (const cmd of commands) {
      const { output } = await executeCommand(shellSessionId, cmd, { timeout: 8_000 })
      combined += '\n' + output
    }

    if (!combined.trim()) {
      return { detected: false, report: `[IDS] Shell session "${shellSessionId}" unreachable`, recommendations: [] }
    }

    for (const ids of IDS_INDICATORS) {
      let matched = false
      for (const pattern of ids.processes) {
        if (pattern.test(combined)) { matched = true; break }
      }
      if (!matched) {
        for (const pattern of ids.configPaths) {
          if (pattern.test(combined)) { matched = true; break }
        }
      }
      if (matched) {
        detected.push(ids.product)
        recommendations.push(`${ids.product} confirmed. Use encrypted/obfuscated payloads — IDS sees signatures not behavior`)
        recommendations.push(`Tune attack pace: lower packet rate, jitter, and avoid known exploit signatures (use TechniqueGenerator)`)
        if (ids.product === 'Snort' || ids.product === 'Suricata') {
          recommendations.push('Snort/Suricata: avoid string-based signatures by encoding (XOR/Base64), fragmenting packets, or using HTTPS where possible')
        }
        if (ids.product === 'Fail2ban') {
          recommendations.push('Fail2ban: rotate source IP via residential proxy, slow brute force to <5 attempts/min, use credential stuffing with leaked passwords for higher success')
        }
        if (ids.product.includes('Firepower') || ids.product.includes('FortiGate') || ids.product.includes('Check Point')) {
          recommendations.push(`${ids.product}: enterprise NGFW with deep inspection — encrypt C2 traffic over TLS, randomize JA3 fingerprint, avoid known-malicious patterns`)
        }
      }
    }

    if (detected.length > 0) {
      const unique = Array.from(new Set(detected))
      return {
        detected: true,
        report: `[IDS/IPS] Detected on ${shellSessionId}: ${unique.join(', ')}\nMethod: process + config path matching`,
        recommendations,
      }
    }

    return { detected: false, report: `[IDS/IPS] No known IDS/IPS detected on ${shellSessionId}`, recommendations: [] }
  }

  // ── Sandbox Detection (requires shell access) ─────────────────────────────

  private async detectSandbox(shellSessionId: string, _context: ToolContext): Promise<{ detected: boolean; report: string; recommendations: string[] }> {
    const indicators: string[] = []
    const recommendations: string[] = []

    const remoteExec = async (cmd: string) =>
      executeCommand(shellSessionId, cmd, { timeout: 8_000 })

    // 1. CPU count
    const { output: cpuInfo } = await remoteExec(
      `nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || wmic cpu get NumberOfLogicalProcessors 2>/dev/null || echo "unknown"`,
    )
    const cpuCount = parseInt(cpuInfo.trim().split('\n').pop() ?? '') || 99
    if (cpuCount <= 2) indicators.push(`CPU cores: ${cpuCount} (≤2 may indicate sandbox/VM)`)

    // 2. Memory
    const { output: memInfo } = await remoteExec(
      `free -m 2>/dev/null | grep Mem | awk '{print $2}' || wmic OS get TotalVisibleMemorySize 2>/dev/null | tail -1 || echo "unknown"`,
    )
    const memMb = parseInt(memInfo.trim().split('\n').pop() ?? '') || 99999
    if (memMb > 0 && memMb < 2048) indicators.push(`Memory: ${memMb}MB (<2GB may indicate sandbox/VM)`)

    // 3. Hostname
    const { output: hostname } = await remoteExec(`hostname 2>/dev/null || echo ""`)
    for (const re of SANDBOX_HOSTNAMES) {
      if (re.test(hostname)) {
        indicators.push(`Hostname matches "${re.source}", possible sandbox environment`)
        break
      }
    }

    // 4. Username (Windows: whoami / Linux: whoami or logname)
    const { output: username } = await remoteExec(`whoami 2>/dev/null || echo ""`)
    for (const su of SANDBOX_USERNAMES) {
      if (username.toLowerCase().includes(su)) {
        indicators.push(`Username contains "${su}", possible sandbox environment`)
        break
      }
    }

    // 5. MAC address
    const { output: macInfo } = await remoteExec(
      `ip link show 2>/dev/null | grep ether | head -3 || ifconfig 2>/dev/null | grep ether | head -3 || getmac /fo csv 2>/dev/null || true`,
    )
    for (const prefix of VM_MAC_PREFIXES) {
      if (macInfo.toLowerCase().includes(prefix.toLowerCase())) {
        indicators.push(`MAC address prefix ${prefix}, possible virtual machine`)
        break
      }
    }

    // 6. Hypervisor strings (DMI/SMBIOS)
    const { output: dmiInfo } = await remoteExec(
      `dmidecode -s system-manufacturer 2>/dev/null || dmidecode -s system-product-name 2>/dev/null || true`,
    )
    for (const re of VM_HYPERVISOR_STRINGS) {
      if (re.test(dmiInfo)) {
        indicators.push(`SMBIOS matches "${re.source}", possible VM (${dmiInfo.trim().split('\n')[0] ?? ''})`)
        break
      }
    }

    // 7. Disk device names
    const { output: diskInfo } = await remoteExec(
      `lsblk -o NAME,MODEL 2>/dev/null | head -10 || wmic diskdrive get model 2>/dev/null | head -10 || true`,
    )
    for (const re of VM_DEVICES) {
      if (re.test(diskInfo)) {
        indicators.push(`Disk device matches "${re.source}", virtualized storage`)
        break
      }
    }

    // 8. Analysis sandbox specific files/processes
    const { output: sandboxArtifacts } = await remoteExec(
      `find / -maxdepth 4 -name "*cuckoo*" -o -name "*joebox*" -o -name "*vmray*" -o -name "*anyrun*" -o -name "*intezer*" 2>/dev/null | head -5; ps aux 2>/dev/null | grep -iE "cuckoo|joebox|vmray|anyrun|intezer|threatgrid" | head -5 || true`,
    )
    for (const sb of SANDBOX_INDICATORS) {
      let matched = false
      for (const re of sb.files) {
        if (re.test(sandboxArtifacts)) { matched = true; break }
      }
      if (!matched && sb.processes) {
        for (const re of sb.processes) {
          if (re.test(sandboxArtifacts)) { matched = true; break }
        }
      }
      if (matched) {
        indicators.push(`Analysis sandbox detected: ${sb.product} (artifacts in filesystem or process list)`)
        break
      }
    }

    if (indicators.length > 0) {
      recommendations.push('Sandbox/VM indicators detected. Consider delayed execution or legitimate process injection techniques')
      recommendations.push('Avoid obvious malicious behavior patterns (rapid port scanning, mass network connections)')
      recommendations.push('Sleep > 5 minutes before payload execution to bypass time-based sandbox detection')
      recommendations.push('Check for human input (mouse movement, keyboard) before triggering payload — most sandboxes have no interaction')
      return {
        detected: true,
        report: `[Sandbox/VM] Detected ${indicators.length} indicator(s) on ${shellSessionId}:\n${indicators.map((i) => `  - ${i}`).join('\n')}`,
        recommendations,
      }
    }

    return { detected: false, report: `[Sandbox/VM] No sandbox or VM indicators detected on ${shellSessionId}`, recommendations: [] }
  }
}