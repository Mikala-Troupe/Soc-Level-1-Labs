# Week 6 — Dynamic Attachment Analysis & Sandboxing 

## Overview
This week focused on using **sandboxing** and **dynamic malware analysis platforms** to safely analyze suspicious email attachments. Unlike static analysis, dynamic analysis executes the file in a controlled environment to observe real behavior such as process activity, registry modifications, network connections, and dropped files.  
I used tools like **Hybrid-Analysis**, **Falcon Sandbox**, **Joe Sandbox**, and **ANY.RUN** to examine a malicious document, review indicators, and understand how sandbox reports reveal malware behavior.

---

## 🧰 Tools Used
- **Hybrid-Analysis / Falcon Sandbox**
- **Joe Sandbox**
- **ANY.RUN**
- **Medium threat research article**
- **CVE reference documentation**

---

## 📌 Dynamic Analysis Walkthrough

![Screenshot 1 – Hybrid Analysis Homepage](./screenshots/Lab6SS1.png)  
**Screenshot 1**: Navigated to **hybrid-analysis.com**, a free malware analysis service powered by CrowdStrike Falcon Sandbox.  
This platform allows analysts to upload suspicious files and automatically detonate them in a controlled environment.

---

![Screenshot 2 – Malicious Sample Overview](./screenshots/Lab6SS2.png)  
**Screenshot 2**: Uploaded a malicious document.  
Hybrid Analysis flagged the file as **malicious** and identified a specific **CVE** associated with the exploit.

---

![Screenshot 3 – Researching the CVE](./screenshots/Lab6SS3.png)  
![Screenshot 4 – CVE Details](./screenshots/Lab6SS4.png)  
**Screenshots 3 & 4**: Researched **CVE-2017-0199**, a widely exploited Microsoft Office vulnerability.  
- Allows attackers to execute arbitrary code using a crafted document  
- Affects multiple Office versions  
Reference: https://cloud.google.com/blog/topics/threat-intelligence/cve-2017-0199-hta-handler/

---

![Screenshot 5 – Attack Chain Reference](./screenshots/Lab6SS5.png)  
**Screenshot 5**: Reviewed an attack chain breakdown from Medium:
https://medium.com/@asmcybersecurity/diving-deeper-into-the-microsoft-office-cve-2017-0199-vulnerability-11bd3e725ab7  
This illustrates how the malicious document triggers the exploit, downloads external payloads, and executes attacker-controlled code.

---

![Screenshot 6 – Falcon Sandbox Dynamic Report](./screenshots/Lab6SS6.png)  
**Screenshot 6**: Viewed the **Falcon Sandbox** dynamic report, showing how the malicious file behaved when detonated:  
- Processes spawned  
- Network communications  
- Persistence attempts  
- Scripts or executables dropped

---

![Screenshot 7 – Malicious Indicators](./screenshots/Lab6SS7.png)  
![Screenshot 8 – Registry & Process Findings](./screenshots/Lab6SS8.png)  
![Screenshot 9 – Network Indicators](./screenshots/Lab6SS9.png)  
![Screenshot 10 – Behavioral Summary](./screenshots/Lab6SS10.png)  
**Screenshots 7–10**: These views highlighted numerous **malicious indicators**, including:  
- Suspicious child processes  
- Registry modifications  
- External network callbacks  
- Evidence of exploitation consistent with CVE-2017-0199

---

![Screenshot 11 – Joe Sandbox](./screenshots/Lab6SS11.png)  
**Screenshot 11**: Explored **Joe Sandbox**, a powerful multi-OS malware analysis engine.  
Requires a business email for registration, so it's less accessible than Hybrid Analysis.  
Supports Windows, macOS, Linux, and Android detonation environments.

---

![Screenshot 12 – ANY.RUN Sandbox](./screenshots/Lab6SS12.png)  
**Screenshot 12**: Reviewed **ANY.RUN**, an interactive malware analysis platform.  
Also requires an account with a business email for free usage.  
Hybrid Analysis remains the preferred tool for accessibility and ease of use.

---

## 🧾 Notes / Takeaways
- **Sandboxing** isolates harmful files in a safe environment, preventing real damage.  
- Dynamic analysis helps detect **behavior**, not just static signatures.  
- During analysis, always observe:
  - **Process Activity**: spawned processes, parent-child relationships  
  - **Registry Activity**: creation, deletion, modification of keys  
  - **Network Connectivity**: C2 traffic, IP lookups, outbound requests  
  - **File Activity**: dropped files, modified files, temporary payloads  
- Never upload sensitive documents to public sandboxes.  
- Sandboxing is powerful, but should be paired with static analysis, threat intel, and header/content review.

---

## 📚 Concepts Introduced
| Concept | Purpose / Use |
|--------|----------------|
| Sandbox Environment | Safely detonates malware in an isolated VM |
| Dynamic Analysis | Observes runtime behavior of a suspicious file |
| Hybrid-Analysis / Falcon Sandbox | Automated detonation & behavior reporting |
| CVE Research | Identifies exploited vulnerabilities used by malware |
| Joe Sandbox | Enterprise-level multi-OS malware analysis |
| ANY.RUN | Interactive sandbox for visualizing malware actions |

---

## 🧠 Skills Learned
- Uploading suspicious attachments to a dynamic sandbox  
- Interpreting behavioral indicators (process, registry, network, file actions)  
- Understanding how Office document exploits (like CVE-2017-0199) operate  
- Reviewing dynamic analysis reports for threat classification  
- Leveraging multiple sandboxing engines for cross-validation  
- Documenting findings clearly for SOC workflows  


