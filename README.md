# 🏢 CorpLab — Enterprise Security Home Lab

> A production-grade, multi-phase enterprise security lab built from scratch on VMware Workstation Pro.  
> Built to **attack**, **detect**, **harden**, and **automate** — continuously evolving as a living security playground.

---

## 📌 Overview

CorpLab simulates a realistic corporate network environment — complete with Active Directory, segmented VLANs, a CI/CD pipeline, web applications, and a full SIEM stack. Every component is intentionally misconfigured with real-world vulnerabilities, then attacked, detected in Splunk, and hardened using industry tooling.

This lab is not a one-time build. It's a permanent **build → attack → detect → harden → automate** cycle, mirroring what security teams face in production environments.

---

## 🗺️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       HOST: Windows 11 (16GB RAM)                   │
│                       VMware Workstation Pro                         │
└─────────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
    ┌─────▼──────┐     ┌──────▼─────┐     ┌──────▼─────┐
    │  VMnet2    │     │  VMnet3    │     │  VMnet4    │
    │  CORP LAN  │     │  CI/CD     │     │  PROD      │
    │ 10.10.10.0 │     │ 10.10.20.0 │     │ 10.10.30.0 │
    └─────┬──────┘     └──────┬─────┘     └──────┬─────┘
          │                   │                   │
   ┌──────┴──────┐     ┌──────┴─────┐     ┌──────┴─────┐
   │  dc-vm      │     │ jenkins-vm │     │  prod-vm   │
   │ WinSrv 2022 │     │  Jenkins   │     │ Juice Shop │
   │ 10.10.10.40 │     │10.10.20.154│     │10.10.30.103│
   │ 10.10.40.10 │     └────────────┘     └────────────┘
   └─────────────┘
   ┌─────────────┐           VMnet5 — AD Segment
   │  win11-vm   │           10.10.40.0/24
   │ WIN11-PC    │     ┌─────────────────────────┐
   │ 10.10.10.50 │     │      OPNsense           │
   │ 10.10.40.20 │     │  Firewall + Suricata IDS│
   └─────────────┘     │      10.10.10.1         │
                        │      10.10.40.1         │
   ┌─────────────┐     └─────────────────────────┘
   │  blue-vm    │
   │ Splunk 10.2 │
   │ 10.10.10.30 │
   └─────────────┘
```

### Network Segments

| VMnet | Subnet | Purpose |
|-------|--------|---------|
| VMnet2 | 10.10.10.0/24 | Corporate LAN — DC, workstation, SIEM |
| VMnet3 | 10.10.20.0/24 | CI/CD Pipeline — Jenkins |
| VMnet4 | 10.10.30.0/24 | Production — Juice Shop app |
| VMnet5 | 10.10.40.0/24 | Active Directory segment |

---

## 🖥️ Infrastructure

| VM | OS | IP | Role |
|----|----|----|------|
| `OPNsense` | OPNsense 23.x | 10.10.10.1 / 10.10.40.1 | Firewall, NAT, Suricata IDS |
| `dc-vm` | Windows Server 2022 | 10.10.10.40 / 10.10.40.10 | Active Directory DC, DNS, GPO |
| `win11-vm` | Windows 11 | 10.10.10.50 / 10.10.40.20 | Domain workstation |
| `jenkins-vm` | Ubuntu | 10.10.20.154 | Jenkins CI/CD + Docker |
| `prod-vm` | Ubuntu | 10.10.30.103 | OWASP Juice Shop (Docker) |
| `blue-vm` | Ubuntu 24.04 | 10.10.10.30 | Splunk Enterprise 10.2.1 |
| `kali-vm` | Kali Linux | TBD | Attacker machine *(Phase 5)* |

---

## 🔴 Intentional Misconfigurations (Attack Surface)

The `corp.local` AD forest is deliberately configured with real-world vulnerabilities used as attack targets:

| Vulnerability | Target | Attack Technique |
|---------------|--------|-----------------|
| Kerberoastable SPN | `svc-jenkins` | Kerberoasting |
| AS-REP Roastable | `jdoe` | AS-REP Roasting |
| DCSync ACL rights | `jsmith` | DCSync / credential dump |
| GPP cpassword in SYSVOL | Group Policy | GPP password decryption |
| Unconstrained Delegation | `WIN11-PC` | Ticket harvesting |
| GenericAll ACL | `jdoe → jsmith` | ACL abuse / lateral movement |
| LLMNR enabled | Network-wide | Responder / LLMNR poisoning |

---

## 📡 Detection & SIEM — Splunk Enterprise

**Deployment:** Splunk Enterprise 10.2.1 on `blue-vm` (Ubuntu 24.04)

**Data Sources Ingested:**

| Source | Transport | Data |
|--------|-----------|------|
| `dc-vm` | Universal Forwarder | Windows Event Logs + Sysmon v15.20 |
| `win11-vm` | Universal Forwarder | Windows Event Logs + Sysmon |
| `OPNsense` | Syslog (UDP 514) | Suricata alerts, firewall logs |
| `jenkins-vm` | Universal Forwarder | Jenkins build logs |
| `prod-vm` | Universal Forwarder | Docker / app logs |

**Detection Engineering:**
- Custom Splunk searches mapped to MITRE ATT&CK techniques
- Sigma rules written for each attack scenario
- Alert tuning and false positive reduction per data source
- SOC analysis sessions per Phase 5 attack (Phase 5b)

---

## 🔁 Lab Phases

### ✅ Phase 1 — Foundation
- VMware Workstation Pro setup, flat network
- OPNsense firewall + NAT
- Jenkins CI/CD pipeline
- OWASP Juice Shop deployed via Docker
- Basic network connectivity validation

### ✅ Phase 2 — Network Segmentation
- True VLAN segmentation across VMnet2–5
- Suricata IDS with Emerging Threats Open rulesets
- Resolved DNS (Unbound SERVFAIL), Docker DNS, iptables FORWARD policy
- Jenkins pipeline reached green state

### ✅ Phase 3 — Active Directory
- `corp.local` AD forest deployed on Windows Server 2022
- Domain join: WIN11-PC workstation
- GPOs deployed: `CorpPasswordPolicy`, `CorpAuditPolicy`, `CorpSysmon`, `CorpDisableLLMNR`
- Intentional misconfigurations seeded (see Attack Surface above)

### ✅ Phase 4 — SIEM & Detection
- Splunk Enterprise 10.2.1 deployed on dedicated `blue-vm`
- Universal Forwarders onboarded: dc-vm, win11-vm
- Sysmon XML parsing via `rex` field extraction (`renderXml = true`)
- OPNsense syslog, jenkins-vm, prod-vm ingestion in progress

### 🔜 Phase 5 — Full Attack Simulation
- Kali Linux attacker VM
- LLMNR/Responder poisoning
- Kerberoasting + AS-REP Roasting
- DCSync credential dump
- BloodHound AD enumeration
- Juice Shop: SQLi, XSS, JWT forgery
- Jenkins RCE
- Docker escape
- Lateral movement chain

### 🔜 Phase 5b — SOC Analysis
- Per-attack Splunk investigation
- Wireshark pcap analysis: Responder, SMB relay, Kerberoast traffic
- Formal Incident Response report for one full attack chain
- MITRE ATT&CK mapping per detection

### 🔜 Phase 6 — Hardening & Automation
- Ansible playbooks for CIS benchmark hardening
- Python automation for detection pipeline
- Palo Alto / Check Point firewall policy writing
- Fix all intentional misconfigurations after detection validation

---

## 🛡️ Security Stack

| Category | Tools |
|----------|-------|
| Firewall / IDS | OPNsense, Suricata (ET Open rules) |
| SIEM | Splunk Enterprise 10.2.1 |
| Log shipping | Splunk Universal Forwarder |
| Endpoint telemetry | Sysmon v15.20 |
| AD enumeration | BloodHound *(Phase 5)* |
| Offensive | Kali Linux, Responder, Impacket *(Phase 5)* |
| Hardening | Ansible, CIS Benchmarks *(Phase 6)* |
| Detection engineering | Sigma rules, MITRE ATT&CK |
| CI/CD | Jenkins, Docker |
| Target app | OWASP Juice Shop |

---

## 🔬 Skills Practiced

**Red Team**
- Active Directory attacks: Kerberoasting, AS-REP Roasting, DCSync, ACL abuse
- Network attacks: LLMNR poisoning, SMB relay
- Web app attacks: SQLi, XSS, JWT manipulation
- Infrastructure attacks: Jenkins RCE, Docker escape, lateral movement

**Blue Team**
- SIEM deployment and log pipeline architecture
- Detection engineering: writing Splunk SPL queries, Sigma rules
- Alert tuning and false positive reduction
- Incident Response documentation
- Packet capture and network forensics (Wireshark)

**Engineering**
- Network segmentation and firewall policy design
- CI/CD security (Jenkins, Docker)
- Ansible automation and CIS hardening
- Python scripting for security tooling
- GPO design and AD hardening

---

## 🧰 Related Projects

- **[Sentinel SOC Tool](https://github.com/kareymabualfadel/sentinel_SOC_tool)** — CLI SOC tool built in Python with log analysis, IP reputation checking (AbuseIPDB), and security header auditing. Designed as a companion tool to this lab.

---

## 📁 Repository Structure

```
corplab/
├── docs/
│   ├── architecture/          # Network diagrams, topology maps
│   ├── attack-playbooks/      # Step-by-step attack documentation
│   ├── detection-rules/       # Splunk SPL + Sigma rules
│   └── incident-reports/      # Formal IR reports per attack chain
├── configs/
│   ├── splunk/                # Inputs.conf, transforms.conf, indexes.conf
│   ├── sysmon/                # Sysmon v15.20 XML config
│   ├── suricata/              # Custom Suricata rules
│   └── opnsense/              # Firewall rule exports
├── scripts/
│   ├── ansible/               # Hardening playbooks (Phase 6)
│   └── python/                # Automation scripts
└── README.md
```

---

## 🎯 Purpose

This lab exists to bridge the gap between theory and production-grade security engineering. Every phase reflects real enterprise tooling, real attack techniques, and real defensive processes — not CTF scenarios.

The continuous cycle of **build → attack → detect → harden** is how this stays a living project and not a snapshot.

---

## 👤 Author

**Kareem Abualfadel**  
Security Engineering — Red/Blue Hybrid  
[GitHub](https://github.com/kareymabualfadel) · [LinkedIn](https://linkedin.com/in/kareem-abualfadel)

---

*Currently active — Phase 4 in progress, Phase 5 incoming.*
