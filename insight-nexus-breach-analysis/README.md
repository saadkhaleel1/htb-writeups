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
