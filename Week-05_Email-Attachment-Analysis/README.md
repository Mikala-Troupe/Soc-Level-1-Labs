# Week 5: Email Attachment Analysis 📎

## Overview
This week I practiced analyzing **email attachments**, which are one of the most common delivery methods for malware in phishing campaigns. Attachments can appear harmless—PDFs, ZIP files, ISO images, and documents, but can easily contain malicious payloads such as executables, scripts, or macros.

The goal of this lab was to learn how to safely extract attachments from raw email files, understand where attachments live within MIME structure, generate file hashes for identification, and perform reputation checks using threat-intelligence tools like VirusTotal and Cisco Talos.

---

## 🧰 Tools Used
- **Terminal / CLI**: For extracting attachments and collecting hashes  
- **emldump.py (Didier Stevens Suite)**: To extract attachments from `.eml` files  
- **Sublime Text**: To view MIME structure and raw email content  
- **Email IOC Extractor (Python Tool)**: To automatically extract indicators  
- **macOS/Linux Hashing Utilities**: `sha256sum`, `sha1sum`, `md5sum`  
- **PowerShell Hashing (Get-FileHash)**: Windows hash collection  
- **VirusTotal**: Multi-engine file reputation and malware detection  
- **Cisco Talos Intelligence**: Threat intelligence and malware classification  
- **Secure Analysis Environment** (isolated VM): Safe email/attachment review  

---

## 📌 Attachment Extraction & Review

![Screenshot 1 – Sample Email w/ Attachment](./screenshots/Lab5SS1.png)  
**Screenshot 1**: Opened Sample 1 email and saved the **quotation.iso** attachment to the desktop. ISO files are frequently used to hide malware inside container-style file structures.

![Screenshot 2 – emldump.py Script](./screenshots/Lab5SS2.png)  
**Screenshot 2** — Viewed the `emldump.py` script (DidierStevensSuite). This tool lets analysts extract attachments directly from `.eml` files using terminal commands rather than relying on an email client.

![Screenshot 3 – Running emldump.py](./screenshots/Lab5SS3.png)  
**Screenshot 3** — Ran the script on the Sample 1 email.  
The output displayed the internal **MIME structure**, including:
- **Part 1:** Header information  
- **Part 2:** HTML body  
- **Part 3:** Attached ISO file (`quotation.iso`)  

This allows analysts to confirm which MIME part contains the attachment.

![Screenshot 4 – Extracting the Attachment](./screenshots/Lab5SS4.png)  
**Screenshot 4** — Extracted the ISO file using:


`emldump.py sample1.eml -s 4 -d > quotation.iso`

Explanation of flags:

- -s 4 → Selects the stream containing the attachment

- -d → Dumps the content of that stream

- ">" → Writes output to a real .iso file instead of printing raw bytes on screen

This approach avoids interacting with potentially dangerous attachments through the email client GUI, keeping the analysis controlled and safe.

![Screenshot 5 – Hashing the Attachment](./screenshots/Lab5SS5.png)  
**Screenshot 5** — Demonstrated how to collect file hashes on macOS/Linux.  
Used three commands to generate different hashing algorithms:  
- `sha256sum` → SHA256 hash of the ISO file  
- `sha1sum` → SHA1 hash  
- `md5sum` → MD5 hash  
Hashes act as unique fingerprints and are essential for documenting, verifying integrity, and performing threat-intel lookups. Multiple commands can be chained using `&&`.

![Screenshot 6 – IOC Extractor Tool Output](./screenshots/Lab5SS6.png)  
**Screenshot 6** — Used the Email IOC Extractor tool to pull the same information automatically.  
This tool extracts: file hashes, URLs, IPs, and header details.  
It’s safer because it avoids manually handling the attachment, and the output is clean for documentation.

![Screenshot 7 – Windows PowerShell Hashing](./screenshots/Lab5SS7.png)  
**Screenshot 7** — Used a Windows machine (PowerShell) to generate the file hash.  
This demonstrates cross-platform hash generation using:  
`Get-FileHash .\quotation.iso -Algorithm SHA256`

![Screenshot 8 – VirusTotal Lookup & Detection Results](./screenshots/Lab5SS8.png)  
**Screenshot 8** — Submitted the SHA256 hash to **VirusTotal**. Multiple antivirus engines immediately flagged the file as **malicious**, confirming it is not a safe attachment. This view shows the detection results summary.

![Screenshot 9 – VirusTotal File Details](./screenshots/Lab5SS9.png)  
**Screenshot 9** — Viewed the **File Details** tab in VirusTotal. This section provides metadata such as file size, type, timestamps, compression info, and other low-level attributes used in malware classification.

![Screenshot 10 – VirusTotal Relations](./screenshots/Lab5SS10.png)  
**Screenshot 10** — The **Relations** view shows connections between this file and other malicious indicators. This includes related URLs, domains, IPs, or other files previously seen in the same malware family or campaign.

![Screenshot 11 – VirusTotal Behavior Activity Summary](./screenshots/Lab5SS11.png)  
**Screenshot 11** — The **Behavior** tab summarizes dynamic analysis results. It highlights actions taken by the malware during sandbox execution, such as process creation, registry modification, network communication, or file drops.


![Screenshot 12 – Cisco Talos Intelligence](./screenshots/Lab5SS12.png)  
**Screenshot 12** — Queried the file hash using Cisco Talos Intelligence.  
Talos provides additional threat research, IP/domain reputation, and malware classification.  
Useful when cross-validating findings between multiple threat-intel platforms.

---

## 🧾 Notes / Takeaways
- Always analyze attachments in a **controlled environment** (VM, sandbox, isolated Linux machine).  
- ISO files, ZIPs, Office documents, and scripts frequently hide **malware payloads**.  
- File hashes serve as **unique identifiers** that can be checked across multiple threat-intel platforms.  
- No single TI source is 100% accurate — always corroborate detection results across **multiple tools**.  
- Command-line extraction helps reduce risk and maintains clean **forensic chain-of-custody**.  
- Automated IOC extraction tools speed up investigations and reduce manual handling of malicious files.  
- Thorough documentation (hashes, screenshots, notes) is essential for **SOC workflows** and report writing.

---

## 📚 Concepts Introduced
| Concept | Purpose / Use |
|--------|----------------|
| MIME Structure | Shows how email content and attachments are organized internally |
| emldump.py | Extracts attachments from `.eml` files safely via command line |
| File Hashing | Creates a unique fingerprint for malware identification |
| VirusTotal | Multi-engine threat-intel platform for file/URL analysis |
| Cisco Talos | Provides advanced malware classification & TI context |
| IOC Extraction | Automated extraction of file and network indicators |

---

## 🧠 Skills Learned
- Extracting attachments from raw email `.eml` files  
- Understanding MIME structure and locating embedded objects  
- Hashing suspicious files on Linux/macOS/Windows  
- Using threat-intel platforms (VirusTotal, Cisco Talos) to confirm malware  
- Identifying malware delivered via ISO containers  
- Documenting findings clearly for SOC investigations  
