# Incident Report: Multi-Stage Intrusion 
### 1. Date of Report
2026-04-21

--- 

### 2. Reported By
Anton

---

### 3. Severity Level
Critical

---

### 4. Executive Summary

A multi-stage intrusion was identified across DESKTOP, FILES-Server, and DC01. The attack began when user t.leon on DESKTOP accessed the suspicious domain paste.sh, which was followed by hidden PowerShell execution that downloaded and launched a malicious payload from attacker-controlled infrastructure. The attacker then established command-and-control, deployed additional payloads, installed multiple persistence mechanisms using legitimate remote management tools, performed reconnaissance, accessed credentials, moved laterally to the file server and domain controller, staged data for exfiltration and downloaded scripts associated with encryption activity on the domain controller. The intrusion demonstrated a full attack chain from initial access through persistence, credential abuse, lateral movement, and potential impact on critical systems.

--- 

### 5. Scope
#### This investigation covered the following systems and activity:

- DESKTOP — initial compromised workstation
- FILES-Server — laterally accessed file server
- DC01 — laterally accessed domain controller

**Data sources reviewed included:** 

- Sysmon logs
- Windows Security logs
- PowerShell logs
- registry artifacts
- scheduled task artifacts
- file creation events
- network connection telemetry

--- 

## 6. Attack Overview

The intrusion began with user interaction with a malicious file-sharing site, leading to PowerShell-based payload delivery on DESKTOP. The attacker then established outbound command-and-control, staged and executed additional payloads, and installed persistence through AteraAgent, SplashtopRemoteService, AnyDesk, scheduled tasks, and script-based shortcut creation. Following persistence, the attacker performed domain reconnaissance, tampered with Windows Defender, accessed LSASS through a migrated process, and used compromised credentials to move laterally to FILES-Server and DC01. On the file server, the attacker compressed targeted files and used rclone for cloud-based exfiltration. On the domain controller, the attacker downloaded scripts associated with encryption-related activity, indicating a likely progression toward destructive or ransomware-style impact.

--- 

## 7. Key Findings
- Initial access was linked to paste.sh
- Hidden PowerShell downloaded iexploreplugin.exe from 10.10.5.171:8883
-  Initial C2 was established to 10.10.5.62:8080
-  Additional payloads included testc.exe, python311.dll, ws2_32.exe, and system_module.exe
-  Secondary attacker infrastructure included agegamepay.com
#### Persistence was established through:
-  AteraAgent
-  SplashtopRemoteService
-  AnyDesk
-  Monitoring Recovery
-  AteraAgentServiceWatchdog
-  scvhost.vbs
-  dhsf82.bat
-  Domain reconnaissance included net user /domain
-  BloodHound-related output 20250825133552_BloodHound.zip was generated
-   Windows Defender real-time monitoring was disabled
-   Credential dumping activity involved migration into spoolsv.exe
-   Lateral movement used account admin143
-   Data staging archive was C:\ProgramData\Teams\teams-skartech.zip
-   Exfiltration path was remote:starktech-backups
**Final-stage downloads on DC01 included crypto.psm1 and script.ps1**

--- 

## 8. Investigation Timeline
Time	Event Description
- 2025-08-25 13:27:40	User on DESKTOP accessed paste.sh
- 2025-08-25 13:30	PowerShell downloaded and executed iexploreplugin.exe
- 2025-08-25 13:30	iexploreplugin.exe connected to 10.10.5.62:8080
- 2025-08-25 13:45 onward	Remote management tooling installed for persistence
- 2025-08-25 13:47:10	Scheduled task Monitoring Recovery created
- 2025-08-25 13:51:18	Scheduled task AteraAgentServiceWatchdog created
- 2025-08-25 13:52:25	scvhost.vbs created shortcut-based persistence
- 2025-08-25 13:53:40	Windows Defender real-time monitoring disabled
- 2025-08-25 13:55:22	Attacker activity migrated toward spoolsv.exe
- 2025-08-25 13:56:54	spoolsv.exe accessed lsass.exe
- 2025-08-25 13:58:52	Lateral movement to FILES-Server using admin143
- 2025-08-25 14:03+	Additional payloads extracted and dropped
- 2025-08-25 14:05:06	DNS query to agegamepay.com observed
- 2025-08-25 14:17:04	Sensitive files compressed into teams-skartech.zip
- 2025-08-25 14:25:03	rclone used to copy archive to remote:starktech-backups
- 2025-08-25 14:34	Lateral movement to DC01 confirmed
- 2025-08-25 14:36:51	crypto.psm1 downloaded to DC01
- 2025-08-25 14:37:57	script.ps1 downloaded to DC01
- 2025-08-25 14:46:02	Auto logon configured on DC01 using dhsf82.bat

--- 

## 9. Who, What, When, Where Why, How

**Who:**
- User t.leon was associated with the initial compromised workstation activity on DESKTOP. The attacker later used the account admin143 for lateral movement. Persistence tooling was linked to bunionsneaker.4m@gmail.com
 and AccountId=001Q300000VzBKuIAN.

**What:**
- A multi-stage intrusion involving malicious payload execution, outbound C2, persistence through legitimate remote management tools, reconnaissance, credential access, lateral movement, data staging, exfiltration, and probable preparation for encryption-related activity.

**When:**
- Primary malicious activity occurred on 2025-08-25, beginning at 13:27:40 and progressing across multiple hosts through the afternoon.

**Where:**
- The intrusion affected DESKTOP, FILES-Server, and DC01.

**Why:**
- Based on observed reconnaissance, credential access, lateral movement, exfiltration staging, and download of encryption-related scripts, the attacker’s likely objective was to expand control, remove sensitive data, and prepare for further disruptive or destructive impact. This is an inference from the observed attack chain.

**How:**
- The attacker used a malicious website, hidden PowerShell execution, staged executables and archives, remote management software, Windows scripts, scheduled tasks, registry changes, credential access via LSASS, valid account lateral movement, archive compression, and rclone-based cloud transfer.

--- 

## 10. MITRE ATT&CK Techniques

- T1059.001 – PowerShell
- T1105 – Ingress Tool Transfer
- T1071 – Application Layer Protocol
- T1219 – Remote Access Software
- T1053.005 – Scheduled Task
- T1547.009 – Shortcut Modification
- T1112 – Modify Registry
- T1087.002 – Domain Account Discovery
- T1482 – Domain Trust / AD Discovery context
- T1003.001 – LSASS Memory
- T1021.002 – SMB / lateral movement context
- T1567 – Exfiltration to Cloud Storage

## 11. Impact Assessment

The intrusion reached multiple systems, including a file server and domain controller, which significantly increased overall risk. Persistence was established through several overlapping methods, including legitimate remote administration software and scheduled tasks. Credential access activity was observed through LSASS access, and lateral movement was confirmed using valid credentials. Sensitive files on the file server were compressed and staged for exfiltration, and cloud transfer tooling was used to copy data to remote storage. Encryption-related scripts were later downloaded to the domain controller, indicating the attack had progressed beyond simple access and posed serious risk of operational disruption, data loss, and broader domain compromise.

## 12. Recommendations / Next Steps
isolate affected hosts from the network
disable and reset compromised accounts, especially admin143
**remove attacker-installed persistence mechanisms:** 
- AteraAgent
- SplashtopRemoteService
- AnyDesk
- malicious scheduled tasks
- malicious scripts and shortcuts

**block known attacker infrastructure:** 
- paste.sh
- agegamepay.com
- 10.10.5.171
- 10.10.5.62
- review and reverse Winlogon auto logon changes on DC01
- investigate for additional use of rclone or similar exfiltration tools
- hunt for related payload names and paths across the environment
- review outbound traffic for cloud sync or archive transfer activity
**enhance detection coverage for:** 
- browser-to-PowerShell execution chains
- PowerShell download-and-execute behaviour
- remote management tool installation outside approved workflows
- LSASS access by unusual processes
- archive creation in suspicious directories
- certutil used for script retrieval on servers
## 13. Evidence

## 14. Report Status 
