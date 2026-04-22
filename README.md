#  💢 StarkTech Incident 

### Scenario

On August 25, 2025, CoreTech’s SOC identified suspicious activity on a workstation that indicated a potential compromise. The intrusion began when the victim accessed a suspicious URL from a file-sharing service, triggering malicious execution.


---


## Scope

*The available artifacts showed three systems in scope:*

- DESKTOP — initial workstation under review
- FILES-Server — file server
- DC01 — domain controller

---

## Investigation Walkthrough

### 1. *Identifying the Likely User and Initial Access*

-  To establish who initiated the compromise, the first step was to review DNS activity from the workstation around the time of the alert. Filtering Sysmon DNS query events on DESKTOP showed that user t.leon resolved paste.sh at 2025-08-25 13:27:40, making this the first strong lead tied to the intrusion.

### *Query used:*

``
index="main" host="DESKTOP" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=22 coretech
| table _time user QueryName 
``



### **iscovery**
- User t.leon accessed paste.sh at 13:27:40, aligning with the suspected compromise window.

### *Evidence*

- DNS activity showing paste.sh and associated user "t.leon"

<img width="2048" height="803" alt="image" src="https://github.com/user-attachments/assets/a9b49d21-437e-4c1d-8451-7fb66d89d1a1" />

--- 

### 2. *Validating the Suspicious Link Through Browser Artifacts*

- After identifying paste.sh in DNS telemetry, the next step was to validate whether the site had actually been visited by the user. This was confirmed by reviewing the Microsoft Edge History database within the triage image for t.leon. The browser history showed the paste.sh entry, and the recorded timestamp matched the suspected compromise window after decoding the browser timestamp value. 

### *Artifact Path*

`` DESKTOP\uploads\auto\C$\Users\t.leon\AppData\Local\Microsoft\Edge\User Data\Default\History `` 

### *Discovery* 

- The suspicious paste.sh link was confirmed in the browser history for t.leon, and its timestamp aligned with the DNS activity observed in Splunk.

### *Evidence*

<table align="center">
  <tr>
    <td><img src="https://github.com/user-attachments/assets/53cc205d-7ca1-452f-9a2b-595181fd17a6" width="300" height="220"></td>
    <td><img src="https://github.com/user-attachments/assets/7bc95c56-b5b3-481b-8588-66fa690da007" width="300" height="220"></td>
    <td><img src="https://github.com/user-attachments/assets/b178d19a-9189-4140-bba3-368931c29f76" width="300" height="220"></td>
  </tr>
</table>
