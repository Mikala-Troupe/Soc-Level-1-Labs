# Week 9 — tcpdump: Analyzing & Reporting 

## Overview
This week focused on **network traffic analysis using tcpdump**, a command-line packet analysis tool commonly used by SOC analysts.  
The goal was to analyze a provided PCAP file, apply display filters, identify suspicious network behavior, and uncover indicators of compromise (IOCs) related to malware activity.  
Through filtering, timestamp analysis, string searching, and threat-intel validation, I identified malicious downloads and confirmed them using external tools.

---

## 🧰 Tools Used
- **tcpdump**
- **grep**
- **WHOIS Lookup**
- **CyberChef**
- **VirusTotal**
- **Linux command line**

---

## 📌 tcpdump Analysis Walkthrough

![Screenshot 1: Viewing a PCAP in tcpdump](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/eb3a44662eadcdc56a39584b68fe661c022e3e3a/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS1.png)  
**Screenshot 1:** Opened a packet capture file using tcpdump.  
Used the `-r` option to read an existing PCAP file instead of capturing live traffic.  
Observed ICMP echo requests and replies, indicating basic network communication.

---

![Screenshot 2: Counting Packets](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/eb3a44662eadcdc56a39584b68fe661c022e3e3a/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS2.png)  
**Screenshot 2:** Used the `--count` option to determine the total number of packets matching the current filter.  
This provides a quick overview of capture size without printing all packet details.

---

![Screenshot 3: Limiting Packet Output](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/eb3a44662eadcdc56a39584b68fe661c022e3e3a/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS3.png)  
**Screenshot 3:** Applied the `-c <number>` option to limit the number of packets displayed.  
Useful when working with large PCAPs and only needing a subset of packets.

---

![Screenshot 4: Timestamp Options](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/eb3a44662eadcdc56a39584b68fe661c022e3e3a/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS4.png)  
![Screenshot 5: Timestamp Options Continued](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/eb3a44662eadcdc56a39584b68fe661c022e3e3a/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS5.png)  
![Screenshot 6: Timestamp Formats](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS6.png)  
**Screenshots 4–6:** Explored tcpdump timestamp display options.  
- `-t`: Removes timestamps  
- `-tt`: Displays Unix epoch timestamps  
- `-ttt`: Shows time delta between packets  
- `-tttt`: Displays full date and time  

Using Unix epoch timestamps is best practice for SOC documentation.

---

## Analyzing a Malicious PCAP Sample

![Screenshot 7: Initial PCAP Review](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS7.png)  
**Screenshot 7:** Analyzed `2021-09-14.pcap`, which contains traffic from a host infected with **LockBit malware**.  
Identified **3,679 packets** and observed frequent communication between internal IP `10.0.0.168` and external IP `103.232.55.148` over HTTP (port 80).

---

![Screenshot 8: Filtering HTTP Traffic](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS8.png)  
![Screenshot 9: Searching with grep](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS9.png)  
**Screenshots 8 & 9:** Narrowed analysis by filtering HTTP traffic and focusing on the suspected infected host.  
Used `grep` to identify HTTP GET and POST requests, which often reveal data retrieval or credential submission.

---

![Screenshot 10: Suspicious File Download](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS10.png)  
**Screenshot 10:** Identified a suspicious download path containing `.audiodg.exe`.  
Executable files are high-risk, and the leading dot suggests an attempt to hide the file.

---

![Screenshot 11: File Name Research](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS11.png)  
**Screenshot 11:** Investigated the filename.  
Although it resembles a legitimate Windows process, it was not downloaded from an official Microsoft source.

---

![Screenshot 12: Investigating the IP Address](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS12.png)  
**Screenshot 12:** WHOIS lookup revealed the IP belongs to a hosting provider in Vietnam and is not associated with Microsoft.  
At this stage, two IOCs were identified: a suspicious filename and a suspicious IP.

---

![Screenshot 13: Searching for Additional Indicators](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS13.png)  
**Screenshot 13:** Used `grep` to find additional packets referencing `audiodg.exe`.  
Discovered embedded URLs pointing back to the same malicious IP.

---

![Screenshot 14: Viewing ASCII Payloads](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS14.png)  
**Screenshot 14:** Used the `-A` option to view packet payloads in ASCII format.  
This allows limited inspection of packet contents using only command-line tools.

---

![Screenshot 15: Bing API Traffic](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS15.png)  
![Screenshot 16: WHOIS Verification](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/61cba10ba55a4acfa864c766bf2da08208547fdf/Week-11_Snort-Intrusion-Detection-and-Prevention/Week-11_Snort-Intrusion-Detection-and-Prevention/screenshots/Lab10SS16.png)  
**Screenshots 15 & 16:** Investigated traffic involving `api.bing.com`.  
WHOIS confirmed Microsoft ownership, suggesting abuse of Bing’s API to redirect victims to malware.

---

![Screenshot 17: CyberChef Analysis](./screenshots/Lab9SS17.png)  
**Screenshot 17:** Used CyberChef to safely decode and analyze the suspicious URL.  
Indicators included HTTP usage, direct IP addressing, and executable delivery.

---

![Screenshot 18: VirusTotal Validation](./screenshots/Lab9SS18.png)  
**Screenshot 18:** VirusTotal confirmed the URL as malicious based on multiple vendor detections.

---

![Screenshot 19: Executable File Signature](./screenshots/Lab9SS19.png)  
**Screenshot 19:** Identified the string *“This program cannot be run in DOS mode”*, confirming the file is a Windows executable.

---

## 🧾 Notes / Takeaways
- tcpdump is effective for identifying malicious behavior from the command line.
- Display filters are essential for narrowing investigations.
- HTTP traffic provides valuable visibility due to lack of encryption.
- Command-line tools have limitations; Wireshark would allow deeper analysis.
- IOC correlation across filenames, IPs, and URLs strengthens investigations.
- External threat-intel sources are critical for validation.
- Clear documentation supports escalation and incident response.

---

## 📚 Concepts Introduced
| Concept | Purpose / Use |
|-------|---------------|
| PCAP Analysis | Reviewing captured network traffic |
| Display Filters | Isolating relevant packets |
| Capture vs Display Filters | Pre- vs post-capture filtering |
| IOC Identification | Detecting malicious artifacts |
| HTTP Traffic Analysis | Inspecting unencrypted traffic |
| WHOIS Lookup | Validating IP ownership |
| Malware Delivery | Identifying executable downloads |

---

## 🧠 Skills Learned
- Reading and analyzing PCAPs with tcpdump  
- Applying filters and timestamps for investigations  
- Identifying suspicious network behavior  
- Extracting indicators using grep  
- Validating findings with threat-intel platforms  
- Writing SOC-style network investigation documentation

