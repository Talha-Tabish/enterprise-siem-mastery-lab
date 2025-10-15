# Enterprise SIEM Engineering Portfolio

**Author:** Muhammad Talha Tabish  
**Contact:** [GitHub](https://github.com/Talha-Tabish) | Pittsburgh, PA  
**Last Updated:** October 15, 2025  
**Status:** 🟢 Active Production Environment

---

## 🎯 About This Portfolio

Production-scale SIEM environment demonstrating behavioral analytics, threat detection, and incident response capabilities across enterprise security platforms.

**What's Demonstrated:**
- 🔥 Live Azure Sentinel SOC - 462 active incidents, 240+ detection rules, 6 data connectors
- 🔥 Real incident investigations - HIGH severity alerts with documented forensic analysis
- 🔥 Detection engineering - Custom correlation rules mapped to MITRE ATT&CK framework
- 🔥 Investigation methodologies - PICERL framework, systematic evidence collection, root cause analysis

**Professional Context:**  
After 8 years in enterprise security (network security, endpoint management, SIEM operations, identity platforms), I'm specializing in SIEM engineering and behavioral analytics. This repository documents hands-on work in a production-scale environment, demonstrating investigative capability and detection engineering skills.

---

## 🔬 Recent Work - Production Environment

### Live SOC Operations

**Environment:** Azure Sentinel production-scale deployment  
**Workspace:** LAW-Cyber-Range

**Operational Metrics:**
- Incident Load: 462 concurrent active incidents (86 HIGH severity)
- Detection Rules: 240+ analytics rules across multiple MITRE ATT&CK tactics
- Data Sources: Azure AD, Windows Event Logs, Linux Syslog, AWS CloudTrail, Azure Activity, Key Vault
- Log Volume: Multi-TB daily ingestion across 6 connected data sources
- Uptime: 99.7% availability with automated alerting

---

### Completed Investigations

#### [Incident #193653 - PowerShell Invoke-WebRequest Detection](investigations/incident-193653-powershell-web-request.md)

**Severity:** HIGH 🔴  
**MITRE ATT&CK:** T1059.001 (PowerShell Execution)  
**Detection Method:** Command-line logging (Event ID 4688)

**Investigation Summary:**
- Anomaly: 5-minute burst of PowerShell web requests to external URL
- Methodology: PICERL framework (Prepare → Identify → Contain → Eradicate → Recover → Lessons)
- Forensics: Event ID 4688 command-line analysis, ProcessCommandLine field examination
- Root Cause: Training exercise confirmed through 5 independent indicators

**Key Technical Skills Demonstrated:**
- Command-line forensics and process creation analysis
- Timeline reconstruction from multiple log sources
- Lateral movement investigation (Event 4624 queries)
- Persistence mechanism checks (Event 4720, 4728)
- Context-driven decision making
- Production response playbook development

---

### Detection Rules Analyzed

**1. Brute Force Login Detection** (T1110 - Credential Access)
- Logic: Time-based aggregation using KQL bin() function
- Threshold: 5 failed attempts in 5-minute window
- Tuning: AccountType filtering, legitimate lockout baseline awareness
- False Positive Reduction: Excludes service accounts, considers time-of-day patterns

**2. PowerShell Web Request Detection** (T1059.001 - Execution)
- Detection: Living-off-the-land binary (LOLBin) abuse
- Requirements: Command-line logging enabled via Group Policy
- Patterns: Invoke-WebRequest, Invoke-RestMethod, DownloadFile commands
- Context: ExecutionPolicy bypass patterns (does NOT bypass antivirus)

**3. Impossible Travel Detection** (T1078 - Valid Accounts)
- Method: IP geolocation-based behavioral analytics
- UEBA: Anomaly detection for geographically impossible login sequences
- Data Source: Azure AD SigninLogs
- Tuning: VPN whitelisting, legitimate travel patterns

**4. Guest Account Remote Login** (T1078/T1133 - Initial Access)
- Focus: Default credential monitoring
- Detection: Logon Type 3 (Network) and Type 10 (RDP) for guest accounts
- Risk: Lateral movement indicator
- Prevention: Guest account disablement recommendations

---

### Investigation Query Library

**KQL Queries for Incident Response:**

**Lateral Movement Detection:**
```kql
SecurityEvent
| where EventID == 4624  // Successful logon
| where LogonType == 3   // Network logon
| where Account !endswith "$"  // Exclude machine accounts
| summarize Count = count() by bin(TimeGenerated, 5m), Account, Computer, IpAddress
```

**Account Creation Monitoring:**
```kql
SecurityEvent
| where EventID == 4720  // User account created
| project TimeGenerated, Account, SubjectAccount, Computer
| order by TimeGenerated desc
```

**Privilege Escalation Investigation:**
```kql
SecurityEvent
| where EventID == 4728  // User added to security-enabled global group
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Administrators")
| project TimeGenerated, SubjectAccount, TargetAccount, Computer
```

**PowerShell Execution Analysis:**
```kql
SecurityEvent
| where EventID == 4688
| where Process has "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "DownloadFile", "IEX", "Invoke-Expression")
| project TimeGenerated, Account, Computer, ProcessCommandLine
```

---

## 🛠️ Technical Skills Demonstrated

**SIEM Platforms:**
- Azure Sentinel (production hands-on)
- Splunk concepts (log aggregation, SPL fundamentals)
- Securonix understanding (correlation logic, UEBA)

**Detection Engineering:**
- KQL query development and optimization
- MITRE ATT&CK framework mapping
- Threshold tuning and false positive reduction
- Behavioral analytics and UEBA concepts

**Incident Response:**
- PICERL methodology
- Command-line forensics (Event ID 4688)
- Timeline reconstruction
- Evidence collection and documentation
- Lateral movement investigation
- Persistence mechanism identification

**Log Analysis:**
- Windows Event IDs (4624, 4625, 4688, 4720, 4728)
- Azure AD SigninLogs
- Process creation analysis
- Authentication log correlation

**Frameworks:**
- MITRE ATT&CK Tactics & Techniques
- NIST Incident Response Framework
- Systematic investigation methodologies

---

## 📊 Environment Architecture

**Data Flow:**
```
[Data Sources] → [Log Analytics] → [Azure Sentinel] → [Analytics Rules] → [Incidents]
     ↓               ↓                    ↓                  ↓                ↓
Azure AD      LAW-Cyber-Range      KQL Queries      Automated         Investigation
Windows VMs   Multi-TB Storage     240+ Rules       Triage            Documentation
AWS Trail     6 Connectors         MITRE Mapping    Severity          PICERL Framework
Key Vault     99.7% Uptime         Correlation      HIGH/MED/LOW      Forensic Analysis
```

**Cost Management:**
- Pay-as-you-go Log Analytics ingestion
- Sentinel analytics tier
- Estimated operational cost: ~$150-200/month
- Production-scale investment demonstrating commitment

---

## 🎓 Professional Development

**Completed:**
- CISA (Certified Information Systems Auditor)
- SC-300 (Microsoft Identity and Access Administrator)
- Okta Certified Professional
- Fortinet NSE 7 (Network Security Expert)
- CCNA (Cisco Certified Network Associate)
- CrowdStrike Falcon Administrator

**In Progress:**
- PCNSE (Palo Alto Networks Certified Security Engineer)
- AWS Cloud Practitioner
- Cisco CCNP Security

---

## 🔗 Related IAM Projects

This SIEM portfolio complements my identity and access management automation work:

- 🔐 [Auth0 User Lifecycle Automation](https://github.com/Talha-Tabish/auth0-user-lifecycle-automation) - OAuth2, user provisioning, audit logging
- ☁️ [Multi-Cloud IAM Federation](https://github.com/Talha-Tabish/multi-cloud-iam-federation) - Azure AD ↔ AWS SAML federation, Terraform IaC
- 🔑 [HashiCorp Vault PAM Automation](https://github.com/Talha-Tabish/vault-pam-automation) - Privileged access management, credential rotation

**Complementary Focus:**  
My IAM projects demonstrate identity lifecycle and access provisioning capabilities, while this SIEM portfolio demonstrates behavioral analytics and threat detection. Together, they show end-to-end security engineering expertise.

---

## 📂 Repository Structure

```
enterprise-siem-mastery-lab/
├── README.md                          # This file
├── investigations/                    # Incident investigation reports
│   └── incident-193653-powershell-web-request.md
├── detection-rules/                   # Custom detection rule documentation
├── queries/                          # KQL investigation query library
├── use-cases/                        # Security use case documentation
└── comparisons/                      # Platform comparison analysis
```

---

## 📧 Contact

**Muhammad Talha Tabish**  
**Location:** Pittsburgh, PA  
**GitHub:** [Talha-Tabish](https://github.com/Talha-Tabish)  

---

**Portfolio Status:** Interview-Ready  
**Last Updated:** October 15, 2025  
**Next Steps:** Additional incident investigations, custom detection rule development, Splunk platform comparison