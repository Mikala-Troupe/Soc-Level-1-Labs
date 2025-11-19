# Week 4 — Email URL Analysis 🔗

## Overview
This week I focused on analyzing URLs embedded in phishing emails. The goal was to identify how attackers disguise malicious links, extract and decode URLs safely, and perform reputation checks using multiple online tools.  
I practiced searching email bodies for hyperlinks, decoding quoted-printable text, defanging URLs, automating IOC extraction, and running threat-intelligence lookups to evaluate URL safety.

---

## 🧰 Tools Used
- **Terminal / CLI** — to view raw email content and run Python scripts  
- **Sublime Text** — for readable HTML and searching for hidden links  
- **CyberChef** — decoding quoted-printable, extracting URLs, defanging  
- **Email-IOC-Extractor (Python Script)** — automated IOC extraction  
- **PhishTank** — community-reported phishing URL checking  
- **URL2PNG** — safe visual preview of suspicious webpages  
- **URLScan.io** — sandbox and behavioral URL analysis  
- **VirusTotal** — multi-engine URL reputation scanning  
- **URLVoid** — domain blocklist and reputation checks  
- **WannaBrowser.net** — retrieve raw HTML + HTTP responses  
- **URLHaus / Unshorten.it** — investigate shortened or malicious URLs

---

## 📌 URL Discovery & Extraction

![Screenshot 1 – Navigate to URL Analysis Folder](https://github.com/Mikala-Troupe/Soc-Level-1-Labs/blob/a5d4e486a2d9f2179866dcd8a52e1d0307b2627d/Week-04_Email-URL-Analysis/Week-04_Email-URL-Analysis/screenshots/Lab4SS1.png)  
**Screenshot 1** — Organized environment for URL analysis.

![Screenshot 2 – Sample 1 Email](./screenshots/sample1-email.png)  
**Screenshot 2** — Opened the raw email sample for inspection.

![Screenshot 3 – Open in Terminal](./screenshots/open-in-terminal.png)  
![Screenshot 4 – Open in Sublime Text](./screenshots/open-in-sublime.png)  
**Screenshots 3 & 4** — Viewed the email body in both Terminal and Sublime Text to make HTML and links easier to read.

---

### Searching for Links
![Screenshot 5 – Find “http”](./screenshots/find-http.png)  
**Screenshot 5** — Searched for `http` using **Ctrl + F**, finding four matches including a *“Reactivate Your Account”* button.

![Screenshot 6 – Find “<a” (anchor tags)](./screenshots/find-anchor-tag.png)  
**Screenshot 6** — Used the `<a` search (HTML anchor tags) to locate all hyperlinks without risk of accidentally opening them.

---

### Quoted-Printable Encoding
![Screenshot 7 – Quoted-Printable Encoding](./screenshots/quoted-printable.png)  
**Screenshot 7** — Identified *quoted-printable* encoding, where URLs are split into multiple lines and special characters are replaced using `=xx` hexadecimal pairs.

---

## 📌 Decoding & Defanging URLs

![Screenshot 8 – CyberChef Decoding](./screenshots/cyberchef-decode.png)  
**Screenshot 8** — Uploaded the email to **CyberChef** and used *From Quoted Printable* + *Extract URLs* to decode and identify embedded URLs.

![Screenshot 9 – Defanging URLs](./screenshots/defang-urls.png)  
**Screenshot 9** — Defanged URLs (`https → hxxps`) so they could be documented safely without becoming clickable.

---

## 📌 Automating URL Extraction

![Screenshot 10 – Email IOC Extractor Script](./screenshots/email-ioc-extractor.png)  
**Screenshot 10** — Used the **Email-IOC-Extractor** Python script to quickly extract URLs, IPs, and relevant headers.

![Screenshot 11 – Running Script in Terminal](./screenshots/run-script.png)  
**Screenshot 11** — Script output showing extracted IOCs such as URLs, sender information, IP addresses, and authentication-related headers.

---

## 📌 URL Reputation & Threat Intelligence Tools

### PhishTank
![Screenshot 12 – PhishTank](./screenshots/phishtank.png)  
**Screenshot 12** — Checked URLs against [PhishTank.org](https://phishtank.org), an open phishing-URL verification database.

### URL2PNG
![Screenshot 13 – URL2PNG Preview](./screenshots/url2png.png)  
**Screenshot 13** — Used URL2PNG to safely preview what the malicious page looks like without visiting it.

### URLScan.io
![Screenshot 14 – URLScan Report](./screenshots/urlscan.png)  
**Screenshot 14** — URLScan revealed:
- Server hosted in **Singapore**  
- Domain newly registered (<30 days)  
- Google Safe Browsing marked it as malicious  
- ISP + IP information linked to suspicious hosting  

### VirusTotal
![Screenshot 15 – VirusTotal Scan 1](./screenshots/virustotal-1.png)  
![Screenshot 16 – VirusTotal Scan 2](./screenshots/virustotal-2.png)  
**Screenshots 15 & 16** — VirusTotal aggregated results from dozens of engines confirming the URL as malicious.

### URLVoid
![Screenshot 17 – URLVoid](./screenshots/urlvoid.png)  
**Screenshot 17** — URLVoid scanned 30+ blocklists, producing additional reputation insights.

### WannaBrowser
![Screenshot 18 – WannaBrowser Results](./screenshots/wannabrowser.png)  
**Screenshot 18** — Retrieved raw HTML + HTTP response to inspect the site’s content safely.

---

## 📌 Additional URL Analysis Resources
- Shortened-link resolvers: **unshorten.it**, **WannaBrowser.net**  
- Malicious URL feeds: **URLHaus (abuse.ch)**  
- Domain safety checks: **Google Safe Browsing**  
- Attackers often abuse link shorteners like *bit.ly* or *tinyurl* to hide true destinations

---

## 🧾 Notes / Takeaways
- Always decode **quoted-printable** encoding to reveal true URLs.  
- **Defang** URLs before storing, sharing, or reporting them.  
- A single clean scan does **not** guarantee safety — use multiple intel sources.  
- Newly registered domains (<30 days) are major phishing red flags.  
- Inspect the **base domain** to understand attacker infrastructure (subdomains, redirects, campaign scope).  
- Even URLs from well-known services (Google Drive, Dropbox, etc.) can host malicious content.  

---

## 📚 Concepts Introduced
| Concept | Purpose / Use |
|----------|----------------|
Quoted-Printable Encoding | Obfuscates email content using `=xx` hex and line wrapping |
Defanging | Makes URLs safe (`https → hxxps`) for documentation |
CyberChef | Decodes and extracts URLs quickly |
Email-IOC-Extractor | Automates URL, IP, and header extraction |
PhishTank / URLScan / VirusTotal | Validate and correlate phishing indicators |
Short-Link Analysis | Expands shortened URLs to reveal true destinations |

---

## 🧠 Skills Learned
- Locating and safely analyzing embedded links  
- Decoding quoted-printable and other encodings  
- Defanging URLs for safe documentation  
- Automating IOC extraction  
- Running multi-source reputation checks  
- Identifying phishing characteristics via domain age, hosting, behavior  
- Inspecting HTML responses without visiting live sites  
- Distinguishing between benign, suspicious, and malicious URLs  

