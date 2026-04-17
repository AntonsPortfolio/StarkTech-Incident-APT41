# StarkTech Incident - APT41 Investigation Lab 
## Scenario 
On August 25, 2025, CoreTech’s SOC spotted unusual activity on a workstation, hinting at a breach. Suspicious processes and network activity spread to critical servers, threatening data and systems.
 
Welcome to the DoubleDragon lab! Uncover a cunning cyberattack involving phishing, stealthy tools, and data theft. As a threat hunter, use Splunk and forensics tools to analyze logs and forensic artifacts, tracing the attacker’s moves to stop the breach.
Dive into DoubleDragon and thwart the attack!

---

# **Investigation Walkthrough**

## 1. Initial Access 

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

<img width="800" height="833" alt="image" src="https://github.com/user-attachments/assets/b7bfe4f5-c41c-4239-9564-faff7e3cead3" />
<img width="800" height="792" alt="image" src="https://github.com/user-attachments/assets/3c87590d-a7e1-4593-b651-5c327073f581" />

### Answer: <ins>paste.sh<ins> 
was the website that initiated the attack vector 
