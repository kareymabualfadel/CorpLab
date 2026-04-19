# 🏢 CorpLab — Enterprise Security Home Lab

> A production-grade, multi-phase enterprise security lab built from scratch on VMware Workstation Pro.  
> Built to **attack**, **detect**, **harden**, and **automate** — continuously evolving as a living security playground.

---

## 📌 Overview

CorpLab simulates a realistic corporate SOC environment — complete with Active Directory, segmented VLANs, a CI/CD pipeline, a production web application, a full Splunk SIEM stack, and a Kali Linux attacker. Every component is intentionally misconfigured with real-world vulnerabilities, then attacked from Kali, detected in Splunk, documented as structured data, and eventually hardened.

This is not a one-time build. It's a permanent **attack → detect → fix → automate → document** cycle, mirroring what security teams face in production environments — and a rotating work simulation across multiple security roles.

### The Core Loop
> 🔴 Attack → 🔵 Detect → 🛠️ Fix → 🐍 Automate → 📄 Document → Repeat

### What this lab covers

| Domain | Activities |
|--------|-----------|
| 🔴 Red team / Pentesting | Real attacks from Kali against intentionally misconfigured AD infrastructure |
| 🔵 Blue team / SOC analysis | Splunk threat hunting, Sigma rules, MITRE ATT&CK mapping |
| 🛠️ DevSecOps | Jenkins pipeline security gates, SAST, secrets scanning, CI/CD loop |
| 💻 Secure software engineering | Fork and fix Juice Shop source code, redeploy via Jenkins, retest from Kali |
| 🐍 Python automation | Splunk REST API scripts, alert enrichment, structured logging, CLI tooling |
| 🔬 Detection engineering | Sigma rule library, MITRE ATT&CK mapping, Suricata custom rules |
| ☁️ Security engineering | OPNsense/Suricata tuning, Ansible hardening (Phase 6) |
| 🤖 AI / ML | RAG over attack docs, agentic SOC analyst, red team agent (Phase 5c) |

---

## 🖥️ Host Machine

**HP Victus 16-d1014ne** — DDR5, ~16GB RAM, Windows 11, VMware Workstation Pro 25H2

All VMs run on a single host. A second machine (HP Pavilion Gaming 15) was evaluated and shelved due to cross-machine networking complexity.

---

## 🗺️ Network Architecture

```
Internet
    |
Home Router (192.168.28.1)
    |
Victus (ethernet 192.168.28.x)
    |
OPNsense Firewall + Suricata IDS (10.10.10.1)
    |
    |--- VMnet2  LAN   10.10.10.0/24   dc-vm · blue-vm · win11-vm · kali
    |--- VMnet3  CICD  10.10.20.0/24   jenkins-vm
    |--- VMnet4  PROD  10.10.30.0/24   prod-vm (Juice Shop)
    |--- VMnet5  AD    10.10.40.0/24   dc-vm AD interface
    |--- VMnet8  NAT   192.168.174.0/24  OPNsense WAN
```

### IP Assignments

| VM | Hostname | IP | VMnet | Role |
|----|----------|----|-------|------|
| OPNsense | gateway | 10.10.10.1 | VMnet2 | Firewall + Suricata IDS |
| dc-vm | DC01 | 10.10.10.40 / 10.10.40.10 | VMnet2 + VMnet5 | Windows Server 2022 Domain Controller |
| blue-vm | blue-vm | 10.10.10.30 | VMnet2 | Ubuntu 24.04 — Splunk SIEM |
| win11-vm | WIN11-PC | 10.10.10.50 / 10.10.40.20 | VMnet2 + VMnet5 | Domain-joined workstation |
| jenkins-vm | jenkins | 10.10.20.154 | VMnet3 | Jenkins CI/CD |
| prod-vm | prod | 10.10.30.103 | VMnet4 | OWASP Juice Shop (Docker) |
| kali | kali | 10.10.10.99 | VMnet2 | ✅ Red team attacker |

---

## 🖥️ VM Inventory

| VM | OS | RAM | Status |
|----|----|-----|--------|
| OPNsense | OPNsense 26.1.2 (FreeBSD) | ~512MB | ✅ Running |
| dc-vm | Windows Server 2022 | 2GB | ✅ Running |
| blue-vm | Ubuntu 24.04 Desktop | 4GB | ✅ Running |
| win11-vm | Windows 11 | 4GB | ✅ Running (Splunk UF skipped — RAM constraint) |
| jenkins-vm | Ubuntu | ~1GB | Suspend when not needed |
| prod-vm | Ubuntu + Docker | ~1GB | Suspend when not needed |
| Kali | Kali Linux 2026.1 | 2GB | ✅ Installed — static IP 10.10.10.99 |

> **RAM note:** Victus has ~16GB. Suspend jenkins-vm and prod-vm when not actively needed. win11-vm Splunk UF is skipped for Phase 5 due to RAM — running win11-vm + blue-vm + dc-vm + Kali simultaneously exceeds available memory. Revisit in Phase 6.

---

## 🏛️ Active Directory — corp.local

**Domain:** corp.local | **DC:** DC01 (10.10.10.40 / 10.10.40.10)

### Organisational Units
`CorpUsers` · `CorpComputers` · `CorpGroups` · `ServiceAccounts`

### Domain Users

| Username | Notes |
|----------|-------|
| jsmith | Regular user — has DCSync ACL rights (intentional misconfiguration) |
| jdoe | AS-REP roastable — GenericAll over jsmith |
| svc-jenkins | Kerberoastable — SPN `HTTP/jenkins.corp.local` |
| Administrator | Domain admin |

### GPOs Deployed

| GPO | Purpose |
|-----|---------|
| CorpPasswordPolicy | Password complexity policy |
| CorpAuditPolicy | Audit logging (Security event log) |
| CorpSysmon | Sysmon v15.20 deployment to all domain machines |
| CorpDisableLLMNR | LLMNR disabled — held off until Phase 6 hardening |

---

## 🔴 Intentional Misconfigurations — Attack Surface

| Vulnerability | Target | Attack Technique |
|---------------|--------|-----------------|
| Kerberoastable SPN | `svc-jenkins` (HTTP/jenkins.corp.local) | Kerberoasting |
| AS-REP Roastable | `jdoe` | AS-REP Roasting |
| DCSync ACL rights | `jsmith` | DCSync / credential dump |
| GPP cpassword in SYSVOL | Group Policy Preferences | GPP password decryption |
| Unconstrained Delegation | `WIN11-PC` | Ticket harvesting (deprioritised — no win11 UF) |
| GenericAll ACL | `jdoe → jsmith` | ACL abuse / privilege escalation |
| LLMNR enabled | Network-wide | Responder / LLMNR poisoning |

---

## 📡 SIEM — Splunk Enterprise 10.2.1

Deployed on `blue-vm` (Ubuntu 24.04) at `http://10.10.10.30:8000`

### Indexes

| Index | Source | Host | Sourcetype | Status |
|-------|--------|------|------------|--------|
| windows | Windows Event Logs (App, System, Security) | DC01 | WinEventLog | ✅ Flowing |
| sysmon | Sysmon v15.20 Operational | DC01 | XmlWinEventLog | ✅ Flowing |
| suricata | OPNsense syslog + Suricata EVE JSON | 10.10.10.1 | suricata | ✅ Flowing |
| jenkins | Jenkins build logs | jenkins-vm | jenkins | ✅ Flowing |
| linux | prod-vm syslog, auth.log, Docker logs | prod-vm | syslog / linux_secure / docker_logs | ✅ Flowing |
| windows/sysmon | win11-vm Windows Events + Sysmon | WIN11-PC | — | ⏭️ Skipped (RAM) |

### Sysmon Event IDs Confirmed Flowing

| Event ID | Meaning |
|----------|---------|
| 1 | Process Creation |
| 8 | CreateRemoteThread |
| 11 | File Created |
| 13 | Registry Value Set |
| 22 | DNS Query |

---

## 🔁 Lab Phases

### ✅ Phase 1 — Foundation
VMware Workstation Pro setup, OPNsense firewall + NAT, Jenkins CI/CD, OWASP Juice Shop via Docker, network connectivity validation.

### ✅ Phase 2 — Network Segmentation
True VLAN segmentation across VMnet2–5, Suricata IDS with Emerging Threats Open rulesets, Unbound DNS, Docker DNS resolution, Jenkins pipeline green.

### ✅ Phase 3 — Active Directory
`corp.local` forest on Windows Server 2022, WIN11-PC domain joined, all GPOs deployed, intentional misconfigurations seeded.

### ✅ Phase 4 — SIEM & Detection
Splunk Enterprise 10.2.1 on dedicated blue-vm, Universal Forwarders on dc-vm / jenkins-vm / prod-vm, Sysmon XML parsing, OPNsense syslog — all indexes flowing.

### ⬅️ Phase 5 — Full Attack Simulation *(active)*
Kali Linux 2026.1 installed on VMnet2, static IP 10.10.10.99, fully updated. Attacks begin now.

### 🔜 Phase 5b — SOC Analysis
Per-attack Splunk investigation, Sigma rules, MITRE ATT&CK mapping, JSON documentation per attack (builds AI training dataset).

### 🔜 Phase 5c — AI Layer on blue-vm
Ollama + ChromaDB RAG over attack JSON docs + Sigma rules, agentic SOC analyst (queries Splunk, reasons over alerts), red team agent.

### 🔜 Phase 6 — Hardening & Automation
Ansible playbooks for CIS benchmark hardening, Python automation, fix all intentional misconfigurations after detection validation.

---

## ⚔️ Attack Plan — Phase 5

**Loop per attack:** 🔴 Attack → 🔵 Splunk hunt → ✍️ Sigma rule → 🗺️ MITRE map → 📄 JSON doc

| # | Attack | Tool | Target | MITRE | Status |
|---|--------|------|--------|-------|--------|
| 1 | LLMNR poisoning | Responder | Network broadcast | T1557.001 | ⬅️ Next |
| 2 | SMB relay | ntlmrelayx | dc-vm | T1557.001 | Pending |
| 3 | Kerberoasting | GetUserSPNs.py | svc-jenkins | T1558.003 | Pending |
| 4 | AS-REP roasting | GetNPUsers.py | jdoe | T1558.004 | Pending |
| 5 | BloodHound AD enum | BloodHound/SharpHound | corp.local | T1069.002 | Pending |
| 6 | DCSync | secretsdump.py | jsmith ACL | T1003.006 | Pending |
| 7 | GPP cpassword | Get-GPPPassword | SYSVOL | T1552.006 | Pending |
| 8 | Juice Shop attacks | Manual / sqlmap | 10.10.30.103:3000 | T1190 | Pending |
| 9 | Jenkins RCE | Groovy script console | 10.10.20.154:8080 | T1059 | Pending |
| 10 | Docker escape | docker.sock abuse | prod-vm | T1611 | Pending |
| 11 | Lateral movement | psexec / wmiexec | corp.local | T1550.002 | Pending |
| 12 | Unconstrained delegation | Rubeus | WIN11-PC | T1558 | Deprioritised |

---

## 🔬 Detection Engineering Approach

Attack first → observe real evidence in Splunk → write Sigma rules → map to MITRE ATT&CK

After each attack:
1. Hunt for evidence in Splunk using real observed fields
2. Write Sigma rule based on actual log data
3. Map to MITRE ATT&CK technique
4. Document the attack as structured JSON (builds AI training dataset for Phase 5c)
5. Push Sigma rule to GitHub under `/detections`

### Sigma Detection Library Structure

```
/detections
  /credential-access
    kerberoasting.yml        # T1558.003
    asrep-roasting.yml       # T1558.004
    dcsync.yml               # T1003.006
    gpp-cpassword.yml        # T1552.006
  /lateral-movement
    smb-relay.yml            # T1557.001
    pass-the-hash.yml        # T1550.002
  /discovery
    bloodhound-enum.yml      # T1069.002
  /execution
    jenkins-rce.yml          # T1059
    docker-escape.yml        # T1611
  /initial-access
    llmnr-poisoning.yml      # T1557.001
    juice-shop-sqli.yml      # T1190
```

### JSON Attack Documentation Format

Every attack is documented as structured JSON — this builds the training dataset for the Phase 5c AI layer:

```json
{
  "attack_id": "ATK-001",
  "name": "LLMNR Poisoning",
  "date": "2026-04-XX",
  "mitre_technique": "T1557.001",
  "tool": "Responder",
  "target": "Network broadcast / corp.local",
  "command": "responder -I eth0 -rdwv",
  "result": "Captured NTLMv2 hash for jsmith",
  "splunk_query": "index=suricata ...",
  "evidence_found": true,
  "sigma_rule": "llmnr-poisoning.yml",
  "notes": "Hash captured within 30s of broadcast"
}
```

---

## 🏃 Work Simulation — Role Sprints

CorpLab is a permanent work environment. Rotate through these roles across sprints:

| Role | Activities |
|------|-----------|
| 🔴 Red Teamer | Run attacks from Kali, document findings as JSON |
| 🔵 SOC Analyst T1 | Morning triage, Splunk dashboards, index health checks |
| 🔵 SOC Analyst T2 | Incident response, Sigma rules, MITRE mapping |
| 🔬 Detection Engineer | Sigma library, Suricata custom rules, detection validation |
| 🛠️ DevSecOps | Jenkins pipeline security gates, SAST, secrets scanning |
| 🌐 Web App Security | Juice Shop exploitation, bug hunting |
| 💻 Secure Developer | Fix Juice Shop vulns in source, redeploy via Jenkins, retest |
| 🐍 Python Dev | Splunk REST API scripts, alert enrichment, logging, automation |
| ☁️ Security Engineer | OPNsense/Suricata tuning, Ansible hardening |
| 🤖 AI Engineer | RAG pipeline, agentic SOC analyst, red team agent |

### Sprint Roadmap

| Sprint | Focus | Estimated Days |
|--------|-------|----------------|
| 1 | Phase 5 attacks + SOC detections (12 attacks + Sigma rules) | 10–14 |
| 2 | Juice Shop developer sprint (exploit → fix → redeploy → retest) | 5–6 |
| 3 | Python automation (Splunk REST API, enrichment scripts, logging layer) | 3–4 |
| 4 | DevSecOps pipeline (Jenkins security gates, SAST, secrets scanning) | 3–4 |
| 5 | Detection library (Sigma organised + MITRE mapped + pushed to GitHub) | 3–4 |
| 6 | Suricata tuning + custom rules | 2–3 |
| 7 | Hardening — Ansible, CIS benchmarks (Phase 6) | 5–7 |
| 8 | AI layer — RAG, agentic SOC analyst, red team agent (Phase 5c) | ongoing |
| 9 | Reporting + portfolio — dashboards, writeups, GitHub docs | 3–4 |

---

## 🐍 Python Automation Layer

### Scripts Planned

| Script | Purpose |
|--------|---------|
| `kerberoast_alert_enrichment.py` | Pull EventCode=4769 events, enrich with account/service/IP/time, export JSON/CSV |
| `dcsync_detector.py` | Flag DS-Replication-Get-Changes from non-DC sources |
| `splunk_health_report.py` | Last event time per index — health summary |
| `attack_timeline_builder.py` | Read all attack JSON docs, build chronological report |

### Engineering Practices

- OOP modelling — `Attack`, `SigmaRule`, `SplunkAlert` classes
- Retry + backoff decorator for Splunk API calls
- Generator-based streaming of large result sets
- Click CLI with flags like `--attack kerberoast --target svc-jenkins`
- Packaged as installable Python package
- Pytest tests + mock Splunk API responses
- Credentials in `.env` — never hardcoded

### Structured Logging Layer

- JSON logger on Kali — auto-generate attack doc at session end
- Rotating file handler (size + time)
- SOC event logger — poll Splunk REST API, enrich + write structured logs
- Lab health logger — ping VMs, check index freshness, alert if silent
- Jenkins build event logger — status, duration, failures → JSON
- Forward Python logs → Splunk `linux` index
- Verbose mode via `--verbose` CLI flag

---

## 🛡️ Security Stack

| Category | Tooling |
|----------|---------|
| Firewall / IDS | OPNsense 26.1.2, Suricata (ET Open rules) |
| SIEM | Splunk Enterprise 10.2.1 |
| Log shipping | Splunk Universal Forwarder 9.2.1 |
| Endpoint telemetry | Sysmon v15.20 |
| AD enumeration | BloodHound / SharpHound |
| Offensive | Kali Linux 2026.1, Responder, Impacket, hashcat |
| Hardening | Ansible, CIS Benchmarks *(Phase 6)* |
| Detection | Sigma rules, MITRE ATT&CK |
| CI/CD | Jenkins, Docker |
| Target app | OWASP Juice Shop (forked) |
| AI layer | Ollama, ChromaDB *(Phase 5c)* |

---

## 🔬 Skills Practiced

**Red Team**
- Active Directory: Kerberoasting, AS-REP Roasting, DCSync, ACL abuse, BloodHound enumeration
- Network: LLMNR poisoning, SMB relay
- Web app: SQLi, XSS, JWT manipulation, IDOR, brute force
- Infrastructure: Jenkins RCE, Docker socket escape, lateral movement

**Blue Team**
- SIEM architecture and log pipeline design
- Detection engineering: SPL queries, Sigma rules, MITRE ATT&CK mapping
- Alert tuning and false positive reduction
- Incident Response documentation
- Splunk index correlation across windows, sysmon, suricata, linux

**Engineering**
- Network segmentation and firewall policy design
- CI/CD security (Jenkins, Docker)
- Ansible automation and CIS hardening
- Python scripting — structured logging, REST API, CLI tooling
- GPO design and AD security configuration

---

## 📁 Repository Structure

```
corplab/
├── detections/
│   ├── credential-access/     # kerberoasting, asrep, dcsync, gpp
│   ├── lateral-movement/      # smb-relay, pass-the-hash
│   ├── discovery/             # bloodhound-enum
│   ├── execution/             # jenkins-rce, docker-escape
│   └── initial-access/        # llmnr-poisoning, juice-shop-sqli
├── attacks/
│   └── json/                  # Structured attack docs (ATK-001 ... ATK-011)
├── scripts/
│   ├── python/                # Splunk enrichment + automation scripts
│   └── ansible/               # Hardening playbooks (Phase 6)
├── configs/
│   ├── splunk/                # inputs.conf, transforms.conf, indexes.conf
│   ├── sysmon/                # Sysmon v15.20 XML config
│   ├── suricata/              # Custom Suricata rules
│   └── opnsense/              # Firewall rule exports
└── README.md
```

---

## 🔗 Related Projects

| Repo | Description |
|------|-------------|
| [corplab-juiceshop](https://github.com/kareymabualfadel/corplab-juiceshop) | Forked OWASP Juice Shop — attack target and secure dev playground |
| [sentinel_SOC_tool](https://github.com/kareymabualfadel/sentinel_SOC_tool) | CLI SOC tool — log analysis, AbuseIPDB IP reputation, security header auditing |
| [kama-backend-task-manager-DevSecOps](https://github.com/kareymabualfadel/kama-backend-task-manager-DevSecOPs-) | Backend task manager with DevSecOps pipeline |

---

## 👤 Author

**Kareem Abualfadel**  
Security Engineering — Red/Blue Hybrid  
[GitHub](https://github.com/kareymabualfadel) · [LinkedIn](https://linkedin.com/in/kareem-abualfadel)

---

*Currently active — Phase 5 attack simulation in progress. Phase 4 (SIEM) complete. Kali installed and configured.*
