# Week 10 — Wireshark: Analyzing Network Traffic 🌐

## Overview
This week focused on **network traffic analysis using Wireshark**, building on previous tcpdump analysis skills.  
The goal was to analyze a real-world malware PCAP, identify malicious behavior, extract indicators of compromise (IOCs), and understand attacker post-compromise activity such as lateral movement, credential harvesting, and file transfer.

This lab followed a structured SOC workflow: starting with high-level traffic analysis, narrowing down suspicious activity, validating findings with threat intelligence, and documenting results clearly.

---

##  Tools Used
- **Wireshark**
- **VirusTotal**
- **MALWAREbazaar**
- **CyberChef**
- **MITRE ATT&CK Framework**
- **Public PCAP samples (malwareanalysis.net)**

---

## 📌 Wireshark Analysis Walkthrough

![Screenshot 1: Loading PCAP File](./screenshots/Lab11SS1.png)  
**Screenshot 1:** Loaded a public malware PCAP sample into **Wireshark**.  
This PCAP was provided by *malwareanalysis.net* and contains traffic from a compromised Windows host.

---

![Screenshot 2: Setting Timestamp Format](./screenshots/Lab11SS2.png)  
**Screenshot 2:** Configured timestamps for consistent documentation.  
Path used: `View → Time Display Format → UTC Date and Time of Day`.  
Using UTC ensures consistent correlation across logs, alerts, and reports.

---

![Screenshot 3: Capture File Properties](./screenshots/Lab11SS3.png)  
**Screenshot 3:** Reviewed **Capture File Properties** under the `Statistics` tab.  
Key observations:
- Over **50,000 packets** captured  
- Nearly **3 hours** of traffic (approx. 12:00 PM – 2:45 PM)  

This high-level overview helps determine whether the PCAP is worth deeper investigation.

---

![Screenshot 4: Conversations Analysis](./screenshots/Lab11SS4.png)  
**Screenshot 4:** Reviewed **IPv4 Conversations** to identify top talkers.  
Findings:
- `10.0.0.149` communicated heavily with `10.0.0.6`
- `10.0.0.149` is likely the infected victim host  
- Other notable external IPs included:
  - `208.187.122.74`
  - `78.31.67.7`
  - `5.75.205.43`

This helps narrow down which endpoints to prioritize.

---

![Screenshot 5: Protocol Hierarchy](./screenshots/Lab11SS5.png)  
**Screenshot 5:** Viewed **Protocol Hierarchy** to identify dominant protocols.  
Observations:
- Heavy NetBIOS, SMB, LDAP, and RPC traffic  
- Very little HTTP traffic (only 4 packets)  

Low-volume HTTP traffic often deserves closer inspection since it can hide malware delivery.

---

![Screenshot 6: Inspecting HTTP Traffic](./screenshots/Lab11SS6.png)  
**Screenshot 6:** Investigated the limited HTTP traffic.  
Suspicious indicators:
1. Host header used an **IP address**, not a domain  
2. HTTP GET request for `/86607.dat`  

`.dat` files can be abused to disguise executable payloads.

---

![Screenshot 7: Following HTTP Stream](./screenshots/Lab11SS7.png)  
**Screenshot 7:** Followed the HTTP stream to reconstruct the conversation.  
Observations:
- User-Agent identified as `curl/7.83.1` (unusual for normal users)  
- Server response included:
  - `This program cannot be run in DOS mode`
  - `MZ` magic bytes (Windows executable signature)  

This confirms the victim downloaded a Windows executable using `curl`.

---

![Screenshot 8: Exporting HTTP Objects](./screenshots/Lab11SS8.png)  
**Screenshot 8:** Exported the file using `File → Export Objects → HTTP`.  
Findings:
- File identified as a **PE32 Windows executable (DLL)**  
- Hashes were recorded for further investigation.

---

![Screenshot 9: VirusTotal File Reputation](./screenshots/Lab11SS9.png)  
**Screenshot 9:** Submitted the file hash to **VirusTotal**.  
The file was flagged as malicious by multiple vendors.

---

![Screenshot 10: MALWAREbazaar Lookup](./screenshots/Lab11SS10.png)  
**Screenshot 10:** Checked the hash in **MALWAREbazaar**.  
The file was associated with the **Quakbot** malware family.

---

![Screenshot 11: Quakbot Research](./screenshots/Lab11SS11.png)  
**Screenshot 11:** Researched **Quakbot** using MITRE ATT&CK and threat reports.  
Key behaviors:
- Performs **ARP scanning** to identify other hosts  
- Commonly used for lateral movement and credential theft  

---

![Screenshot 12: ARP Scan Detection](./screenshots/Lab11SS12.png)  
**Screenshot 12:** Filtered ARP traffic using:  
`arp and eth.dst eq ff:ff:ff:ff:ff:ff`  

Observations:
- Broadcast ARP requests  
- Sequential IP address probing  
- Indicates network discovery behavior.

---

![Screenshot 13: ICMP Traffic](./screenshots/Lab11SS13.png)  
**Screenshot 13:** Filtered ICMP traffic to confirm host discovery.  
Findings:
- ICMP echo requests and replies identified  
- Attacker discovered:
  - `10.0.0.6`
  - `10.0.0.1`

---

![Screenshot 14: Port Scan Activity](./screenshots/Lab11SS14.png)  
**Screenshot 14:** Investigated possible port scanning on `10.0.0.1`.  
Findings:
- Incomplete TCP handshakes  
- Frequent RST packets  

This suggests a **stealthy SYN scan**, used to identify open ports while avoiding detection.

---

![Screenshot 15: SMTP Traffic Analysis](./screenshots/Lab11SS15.png)  
**Screenshot 15:** Analyzed SMTP traffic.  
Observed `AUTH LOGIN` commands containing Base64-encoded credentials.

---

![Screenshot 16: Credential Decoding](./screenshots/Lab11SS16.png)  
**Screenshot 16:** Used **CyberChef** to decode Base64 data.  
Recovered:
- Username: `arthit@macnels.co.th`  
- Password: `Art123456`  

Authentication failed, but credentials may still be compromised.

---

![Screenshot 17: SMB Object Transfers](./screenshots/Lab11SS17.png)  
**Screenshot 17:** Exported SMB objects.  
Findings:
- Multiple `.dll` and `.dll.cfg` files  
- Files transferred to `10.0.0.6` (domain controller)  

Executable transfers over SMB are highly suspicious.

---

![Screenshot 18: Hash Comparison](./screenshots/Lab11SS18.png)  
**Screenshot 18:** Analyzed hashes of SMB-transferred files.  
Results:
- DLL files matched the **original Quakbot hash**
- Indicates propagation from the infected host to the domain controller  

This suggests potential **domain compromise**.

---

## 🧾 Notes / Takeaways
- Wireshark allows deep inspection beyond command-line tools
- Starting with high-level statistics saves time
- Low-volume traffic can be high-risk
- Malware often performs network discovery after infection
- Credential exposure can occur over unencrypted protocols
- SMB traffic should be monitored closely in AD environments
- Clear documentation is critical for escalation and response

---

## 🧠 Skills Learned
- PCAP triage and traffic prioritization
- Protocol and conversation analysis
- Malware delivery identification
- IOC extraction and validation
- ARP scan and port scan detection
- Credential decoding and investigation
- SMB lateral movement analysis

