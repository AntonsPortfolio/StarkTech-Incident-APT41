#  💢 StarkTech Incident - APT41 Investigation Lab  
## Scenario 
On August 25, 2025, CoreTech’s SOC spotted unusual activity on a workstation, hinting at a breach. Suspicious processes and network activity spread to critical servers, threatening data and systems.
 
Welcome to the DoubleDragon lab! Uncover a cunning cyberattack involving phishing, stealthy tools, and data theft. As a threat hunter, use Splunk and forensics tools to analyze logs and forensic artifacts, tracing the attacker’s moves to stop the breach.
Dive into DoubleDragon and thwart the attack!

---

# **Investigation Walkthrough**

##  💢 1. Initial Access 

#### Objective: 
Identify the website that triggered the compromise.
#### Method: 
Identified the affected user and workstation, then reviewed Sysmon DNS query activity for t.leon on host DESKTOP to isolate suspicious domains linked to the initial stage of the intrusion.
#### Findings: 
The victim resolved paste.sh via msedge.exe, aligning with the beginning of malicious activity.
#### Why it matters: 
This establishes the initial access vector and anchors the start of the intrusion timeline.
#### Query Used:
``` 
index="main" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=22 t.leon
| stats count by QueryName user
| table user, QueryName, count
| sort count
| dedup QueryName
```

### Evidence:

<img width="800" height="300" alt="image" src="https://github.com/user-attachments/assets/b7bfe4f5-c41c-4239-9564-faff7e3cead3" />
<img width="800" height="300" alt="image" src="https://github.com/user-attachments/assets/3c87590d-a7e1-4593-b651-5c327073f581" />

**Answer:** (paste.sh) the suspicious website 

---

##  💢 2. Payload Delivery and Execution

#### Objective: 
Identify the full URL used to download and execute the next-stage payload.

#### Methodology:
After confirming the likely initial access site, pivoted into process creation telemetry to determine what executed immediately afterward. Reviewed PowerShell-related process creation events on DESKTOP around the same timeframe, then examined full command-line arguments to identify any remote download and execution activity linked to the compromise.

#### Findings:
PowerShell was executed with a hidden window and used Invoke-WebRequest to download iexploreplugin.exe from 10.10.5.171:8883, then executed it from the user’s TEMP directory.

#### Why it matters:
This confirms the first-stage payload delivery method and identifies the attacker-controlled infrastructure used to place malicious code on the host.

#### Querys Used:
``` 
index="main" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=1 t.leon powershell 
| rex "Command: (?<command_line>.*)"
| table Image, CommandLine, User
| sort _time 
```

### Evidence 
<img width="2048" height="834" alt="image" src="https://github.com/user-attachments/assets/9784336b-a755-4d11-acdd-a784ecd87dd9" />

**Answer:** <ins>hxxp://10.10.5.171:8883/iexploreplugin[.]exe<ins>

---

#### Objective: 
Identify the files extracted from the malicious ZIP archive.

#### Methodology:
After confirming the initial access site and first-stage PowerShell payload on DESKTOP, expanded the investigation into file activity to determine how the intrusion progressed. Reviewed ZIP download and extraction events, then correlated them with file creation telemetry in the destination path to identify the files extracted from the archive.

#### Findings:
The archive python.zip was downloaded and extracted, resulting in two files: testc.exe and python311.dll.

#### Why it matters:
This shows the intrusion progressed beyond the initial payload and that additional components were introduced to support later stages of the attack.

#### Evidence:

<img width="2048" height="801" alt="image" src="https://github.com/user-attachments/assets/55cbbc05-61aa-4698-b75c-392df116fb22" />
<img width="2048" height="915" alt="image" src="https://github.com/user-attachments/assets/84413df3-5ba8-4ec8-9961-9e75416ba736" />
