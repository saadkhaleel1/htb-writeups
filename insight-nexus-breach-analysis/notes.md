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
