# 🛡️ EventLog_Triage1 – Windows Security Event Log Triage Tool (PowerShell)

A PowerShell-based tool designed to help SOC Analysts and incident responders quickly collect, parse, and triage high-value Windows **Security** event logs.  
This script automates event retrieval, extracts actionable fields from raw XML, sorts events by relevance, and enables exporting results for deeper investigation or SIEM ingestion.

---

## 🔍 Features

- **Pulls common SOC-critical Security Event IDs**, including:
  - **4624** – Successful logon  
  - **4625** – Failed logon  
  - **4634** – Logoff  
  - **4648** – Logon with explicit credentials  
  - **4672** – Special privileges assigned  
  - **4688** – Process creation  
  - **4720–4726** – Account creation/delete/enable/disable  
  - **4728, 4729, 4732, 4733** – Security group membership changes  
  - **4768, 4769, 4771, 4776** – Kerberos/NTLM authentication events  

- **Parses Windows event XML** to extract:
  - SubjectUser / SubjectDomain  
  - TargetUser / TargetDomain  
  - IP Address / Port  
  - Workstation  
  - LogonType  
  - Authentication package (NTLM, Kerberos, etc.)  
  - ProcessName  
  - Status & SubStatus codes  
  - ✔ **FailureReason for 4625 events**  

- **Groups and sorts events** by:
  - `EventId`  
  - `TimeCreated`

- **Optional CSV export** for:
  - Excel analysis  
  - SIEM ingestion  
  - Automated triage pipelines  
  - IR documentation  

---

## 🧠 Use Case

This project simulates real Tier 1 SOC responsibilities, enabling analysts to:

- Triage failed logons (Event ID 4625)  
- Investigate suspicious authentication patterns  
- Identify unusual account activity  
- Detect potentially malicious process creation  
- Monitor password resets, account disablements, and group membership changes  
- Build stronger log analysis and Windows security monitoring skills  

Ideal for SOC analysts, blue teamers, homelab environments, and anyone strengthening Windows log analysis proficiency.

---

