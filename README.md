# Phishing Email Analysis – TryHackMe (Case 1)

This project is a walkthrough of **Phishing Email Analysis Case 1** on [TryHackMe](https://tryhackme.com/), where I analyze a suspicious email using CyberChef. This is part of my cybersecurity learning and hands on experience in email threat investigation.

## Objective

Analyze a phishing email to:
- Extract key indicators of compromise (IOCs)
- Identify spoofing or impersonation attempts
- Deobfuscate links and attachments
- Understand and explain why the email is malicious

## Tools Used
Cyberchef, Notepad

- **TryHackMe Phishing Email Analysis Lab**
- **PhishTool** – for email header inspection and IOC extraction
- **Header analysis** – to detect spoofing and suspicious domains
- **URL & IP deobfuscation** (defanging analysis)
  

##  What I Did

1. **Inspected raw email headers**
   - Checked `Received-SPF` and `DKIM` results
   - Noted suspicious sender and reply-to email not matching

2. **Defanged and analyzed URLs**
   - Identified shortened links and resolved them to final malicious domains
   - Checked links against threat databases

3. **Extracted and examined IP addresses**
   - Verified whether sender IPs were permitted by SPF
   - Flagged unauthorized senders

4. **Documented all IOCs**
   - Malicious URLs
   - IP addresses
   - Suspicious domains and email addresses

5. **Summarized findings**
   - Email is confirmed to be phishing
   - Attempted credential harvesting via fake login page

## Demo Video
-Listed Above

## Files Included

- Recorded demo of the analysis
  

##  Key Takeaways

- Always verify SPF/DKIM/DMARC alignment
- Shortened URLs are a red flag – always unshorten and inspect
- Email headers reveal a lot about sender legitimacy
- Tools like CyberChef can speed up investigation and help automate IOC extracts

## About Me

I’m a cybeesecurity intern currently doing an **IAM internship with the City of Dallas**, learning hands on skills in identity security, phishing analysis, and access management. This project is part of my growing portfolio in cybersecurity
