# Week 7 — Automated Email Analysis with PhishTool 

## Overview
This week focused on using **PhishTool**, a web-based phishing analysis platform that automatically parses, categorizes, and enriches suspicious emails.  
PhishTool provides a structured interface for reviewing metadata, headers, URLs, attachments, and authentication results, making it much faster to triage phishing attempts.  
It also integrates with **VirusTotal**, providing additional context on URLs, file hashes, and attachments without leaving the platform.

---

## 🧰 Tools Used
- **PhishTool** (automated email analysis)
- **VirusTotal** integration (URL & hash lookups)
- Built-in PhishTool tabs: Rendered, HTML, Source, Details, Transmission, X-Headers, Authentication, Attachments, URLs

---

## 📌 PhishTool Email Analysis Walkthrough

![Screenshot 1 – PhishTool Dashboard](./screenshots/Lab7SS1.png)  
**Screenshot 1**: Opened **PhishTool**, a cloud-based phishing analysis solution.  
It automatically extracts metadata, parses URLs, identifies suspicious fields, and generates reports.  
You can also integrate VirusTotal to check attachments, URLs, and file hashes all from the same pane.

---

![Screenshot 2 – Uploaded Sample Email](./screenshots/Lab7SS2.png)  
**Screenshot 2**: Uploaded “Sample Email #1” (Chase Bank phishing email).  
PhishTool provides multiple views for analysis:  
- **Rendered**: How the victim sees the email  
- **HTML**: Raw HTML markup  
- **Source**: Full email source including headers and MIME structure  

---

![Screenshot 3 – Details Tab](./screenshots/Lab7SS3.png)  
![Screenshot 4 – Header Details](./screenshots/Lab7SS4.png)  
**Screenshots 3 & 4**: The **Details** tab summarizes key header fields:  
- **From / To**  
- **Timestamp**  
- **Reply-To** (flagged): Does NOT match the sender, a common phishing indicator  
- **Return-Path** (flagged): `proton.me` mismatch with `chase.com` spoof  
- **Originating IP**  
- **rDNS lookup results**  

These inconsistencies immediately suggest spoofing.

---

![Screenshot 5 – Transmission Chain](./screenshots/Lab7SS5.png)  
**Screenshot 5**: The **Transmission** tab displays the full chain of mail servers the email passed through.  
Extracted from the *Received* headers, this view shows:  
- All Mail Transfer Agents (MTAs) involved  
- Timestamps  
- Sending and receiving servers  
- Original sending IP  

This helps track the email’s path and confirm legitimacy.

---

![Screenshot 6 – X-Headers](./screenshots/Lab7SS6.png)  
**Screenshot 6**: The **X-Headers** tab lists extended/custom headers added by security products or mail systems.  
These can include spam scores, filtering signatures, additional metadata, or tool-specific indicators.

---

![Screenshot 7 – Authentication Results](./screenshots/Lab7SS7.png)  
**Screenshot 7**: The **Authentication** tab checks SPF, DKIM, and DMARC.  
Findings:  
- **SPF Passed**: Originating IP matched approved sender  
- **DMARC Failed**: Domain spoofing attempt (`chase.com`)  

A DMARC fail is strong evidence of a phishing email.

---

![Screenshot 8 – Attachments View](./screenshots/Lab7SS8.png)  
**Screenshot 8**: The **Attachments** tab lists any files included in the email.  
(Our sample had none, but this tab is used for pulling file hashes or detonating attachments.)

---

![Screenshot 9 – URLs Extracted](./screenshots/Lab7SS9.png)  
**Screenshot 9**: The **URLs** tab lists all extracted hyperlinks, including hidden or encoded ones.  
Useful for spotting shortened URLs or obfuscated credential-harvesting links.

---

![Screenshot 10 – Sample Resolution](./screenshots/Lab7SS10.png)  
**Screenshot 10**: After reviewing indicators, clicking **Resolve** allows us to edit and finalize the classification.  
PhishTool automatically fills:  
- **Email Disposition:** *Malicious*  
- **Flagged Artifacts:**  
  - Reply-To mismatch  
  - Return-Path mismatch  
  - URL shortening/redirection  
- **Classification Codes:**  
  - *Spoofing*  
  - *Credential Harvesting*

---

![Screenshot 11 – Updated Analyst Dashboard](./screenshots/Lab7SS11.png)  
**Screenshot 11**: After resolving the phish, the dashboard updates with:  
- Manual uploads  
- Resolved  
- Resolved malicious  
- Resolved safe  

This supports clean SOC documentation and makes reporting easier.

---

## 🧾 Notes / Takeaways
- PhishTool accelerates phishing investigations by automatically parsing and categorizing key indicators.  
- Automated enrichment (URLs, headers, authentication, attachments) eliminates manual parsing.  
- Mismatched **Reply-To**, **Return-Path**, and **From** domains strongly indicate spoofing.  
- DMARC failures are highly suspicious and often seen in credential-harvesting campaigns.  
- URL analysis quickly identifies shortening services or redirection behavior.  
- The Resolve feature standardizes classifications for SOC workflows.  
- Strong documentation (screenshots, flagged artifacts, disposition) improves case tracking.

---

## 📚 Concepts Introduced
| Concept | Purpose / Use |
|--------|----------------|
| PhishTool | Automated phishing email analysis and reporting |
| Header Mismatch Indicators | Detect spoofing through inconsistent fields |
| Transmission Chain | Visualizes all MTAs an email traversed |
| SPF / DKIM / DMARC | Email authentication frameworks to verify legitimacy |
| URL Extraction | Identifies obfuscated or shortened malicious links |
| Case Resolution | Standardizes phishing classifications & SOC documentation |

---

## 🧠 Skills Learned
- Uploading suspicious emails for automated analysis  
- Interpreting PhishTool’s tabs (Details, Transmission, X-Headers, Authentication)  
- Identifying spoofing indicators in Reply-To and Return-Path fields  
- Understanding authentication failures (SPF/DMARC)  
- Extracting URLs and evaluating them for phishing behavior  
- Resolving and documenting phishing cases in a structured format  


