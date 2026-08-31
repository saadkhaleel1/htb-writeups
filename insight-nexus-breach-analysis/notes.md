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
