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
### **Identifying the Likely User and Initial Access**

-  To establish who initiated the compromise, the first step was to review DNS activity from the workstation around the time of the alert. Filtering Sysmon DNS query events on DESKTOP showed that user t.leon resolved paste.sh at 2025-08-25 13:27:40, making this the first strong lead tied to the intrusion.

### **Query used:**

``
index="main" host="DESKTOP" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=22 coretech
| table _time user QueryName 
``



### **Discovery** 
- User t.leon accessed paste.sh at 13:27:40, aligning with the suspected compromise window.

### **Evidence**

- DNS activity showing paste.sh and associated user "t.leon"

<img width="2048" height="803" alt="image" src="https://github.com/user-attachments/assets/a9b49d21-437e-4c1d-8451-7fb66d89d1a1" />



