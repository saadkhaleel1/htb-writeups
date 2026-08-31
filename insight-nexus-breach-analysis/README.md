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

Each finding below is documented with: the event ID / log source used, the filter/query applied, the relevant raw log excerpt, and the reasoning that ties it back to the attacker's timeline.

## Findings

_In progress — see [`notes.md`](./notes.md) for the working investigation log._

| # | Question | Answer | Evidence |
|---|---|---|---|
| 1 | Parent process of credential dumping tool | _TBD_ | _TBD_ |
| 2 | Persistence `imagePath` on DB01 | _TBD_ | _TBD_ |
| 3 | Exfil destination IP for `diagnostics_data.zip` | _TBD_ | _TBD_ |
| 4 | User connecting to `\\fs01\projects` | _TBD_ | _TBD_ |

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1078.004 – Valid Accounts (Cloud/Default Creds) | ManageEngine `admin/admin` login |
| Initial Access | T1190 – Exploit Public-Facing Application | PHP portal file upload |
| Persistence | T1547 / T1543 / T1069 | GPO-deployed MSI, scheduled task |
| Command & Control | T1071.001 – Web Protocols | HTTPS beacon to `103.112.60.117` |
| Exfiltration | T1560 / T1041 | `diagnostics_data.zip` upload |

## Lessons Learned

- Default credentials on internet-facing admin tools remain a top initial-access vector.
- Multiple concurrent intrusions can co-exist in one environment — a "loud" low-skill actor can mask a quieter, more capable one.
- Alert correlation across disparate log sources (web app auth, Sysmon, LDAP, file share access) is what actually surfaces the full picture.
