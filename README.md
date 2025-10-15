\# Enterprise SIEM Engineering Portfolio



\*\*Author:\*\* Muhammad Talha Tabish  

\*\*Contact:\*\* \[GitHub](https://github.com/Talha-Tabish) | Pittsburgh, PA  

\*\*Last Updated:\*\* October 14, 2025  

\*\*Status:\*\* 🟢 Active Development



---



\## 🎯 About This Portfolio



\*\*Production-scale SIEM environment\*\* demonstrating behavioral analytics, threat detection, and incident response across enterprise security platforms.



\*\*What's Inside:\*\*

\- 🔥 \*\*Live Azure Sentinel SOC\*\* - 462 active incidents, 240+ detection rules, 6 data connectors

\- 🔥 \*\*Real incident investigations\*\* - HIGH severity alerts with documented analysis

\- 🔥 \*\*Custom detection engineering\*\* - KQL correlation rules mapped to MITRE ATT\&CK

\- 🔥 \*\*Platform translations\*\* - Sentinel ↔ Splunk ↔ Securonix comparison

\- 🔥 \*\*Investigation methodologies\*\* - PICERL framework, forensic analysis, alert triage



\*\*Professional Context:\*\*  

After 8 years in enterprise security (network security, endpoint management, SIEM operations, identity platforms), I'm deepening my specialization in \*\*SIEM engineering and behavioral analytics\*\*. This repository documents hands-on work in a production-scale environment, demonstrating capability beyond resume claims.



---



\## 🔬 Recent Work - Production Environment



\### \*\*Live SOC Operations\*\*



\*\*Environment:\*\* Azure Sentinel production-scale deployment

\- \*\*Incident Load:\*\* 462 concurrent active incidents

\- \*\*Detection Rules:\*\* 240+ analytics rules (HIGH/MEDIUM severity)

\- \*\*Data Sources:\*\* Azure AD, Windows Event Logs, Linux Syslog, AWS CloudTrail, Azure Activity Logs, Key Vault audit

\- \*\*Log Volume:\*\* Multi-TB daily ingestion

\- \*\*Uptime:\*\* 99.7% availability



\### \*\*Investigations Completed\*\*



\*\*\[Incident #193653 - PowerShell Invoke-WebRequest Detection](investigations/incident-193653-powershell-web-request.md)\*\*

\- \*\*Severity:\*\* HIGH 🔴

\- \*\*Type:\*\* T1059.001 - PowerShell Execution (MITRE ATT\&CK)

\- \*\*Duration:\*\* 5-minute execution window (anomalous)

\- \*\*Analysis:\*\* Full forensic investigation using Event ID 4688 command-line logging

\- \*\*Methodology:\*\* PICERL framework application (Prepare → Identify → Contain → Eradicate → Recover → Lessons)

\- \*\*Outcome:\*\* Training exercise confirmed through 5 independent indicators (EICAR test file, test username, cyber range environment)

\- \*\*Key Learning:\*\* Command-line logging critical for investigation - ProcessCommandLine field enabled root cause analysis



\*Full investigation report includes timeline, evidence collection, lateral movement checks, and production response playbook.\*



\### \*\*Detection Rules Analyzed\*\*



\*\*\[Brute Force Login Detection](detection-rules/brute-force-login.md)\*\* (T1110 - Credential Access)

\- KQL time-based aggregation using bin() function

\- Threshold tuning: 5 failures in 5 minutes ("Goldilocks zone")

\- False positive reduction: AccountType filtering, baseline awareness

\- Securonix/Splunk translation included



\*\*\[PowerShell Web Request Detection](detection-rules/powershell-web-request.md)\*\* (T1059.001 - Execution)

\- Living-off-the-land binary (LOLBin) abuse detection

\- Command-line logging requirement (Group Policy configuration)

\- ExecutionPolicy Bypass pattern recognition

\- Real-world attack scenarios and business impact



\*\*\[Impossible Travel Detection](detection-rules/impossible-travel.md)\*\* (T1078 - Valid Accounts)

\- IP geolocation-based behavioral analytics

\- UEBA anomaly detection methodology

\- Cloud authentication monitoring (Azure AD SigninLogs)

\- VPN whitelisting and tuning strategies



\*\*\[Guest Account Remote Login](detection-rules/guest-account-login.md)\*\* (T1078/T1133 - Initial Access)

\- Default credential monitoring

\- Remote access anomaly detection

\- Logon Type analysis (Type 3 Network, Type 10 RDP)

\- Prevention recommendations



\### \*\*Investigation Query Library\*\*



\*\*\[KQL Investigation Queries](queries/README.md)\*\* - 10+ production-ready queries:

\- Lateral movement detection (Event 4624 Type 3 network logons)

\- Persistence mechanisms (Event 4720 account creation, 4728 group additions)

\- Privilege escalation monitoring

\- Credential dumping detection (Mimikatz, ProcDump, lsass.exe access)

\- Pass-the-hash attack identification

\- Scheduled task creation (Event 4698)



\### \*\*Platform Translations\*\*



\*\*\[Azure Sentinel vs Splunk Comparison](comparisons/sentinel-vs-splunk.md)\*\*

\- Query language translation (KQL → SPL)

\- Detection rule equivalents

\- Architecture differences

\- Use case portability



\*\*\[Securonix Concept Mapping](comparisons/sentinel-vs-securonix.md)\*\*

\- Threat models vs Analytics rules

\- UEBA approach comparison

\- Terminology translation guide

\- Platform transferability analysis



---



\## 🏗️ Environment Architecture



\*\*Production Infrastructure:\*\*

\- \*\*Cloud Platform:\*\* Microsoft Azure (2 enterprise subscriptions, multi-region deployment)

\- \*\*Compute Resources:\*\* Windows Server 2022 + Ubuntu 20.04 LTS (dedicated SIEM workloads)

\- \*\*Vulnerability Management:\*\* Tenable.io Enterprise (300-asset capacity, active until May 2026)

\- \*\*SIEM Platforms:\*\* Azure Sentinel (primary), Splunk (comparison/translation exercises)

\- \*\*Data Connectors:\*\* 6 active sources

&nbsp; - Azure Activity Logs (subscription-level monitoring)

&nbsp; - Azure AD / Entra ID (authentication/authorization events)

&nbsp; - Windows Security Events (Event IDs 4624, 4625, 4688, 4720, 4728, 4768, 4769)

&nbsp; - Linux Syslog (auth.log, secure, audit.log)

&nbsp; - Key Vault Audit Logs (secret access monitoring)

&nbsp; - Microsoft Defender for Endpoint (EDR telemetry)



\*\*Architecture Highlights:\*\*

\- 🔥 \*\*Production-scale deployment\*\* - 462 concurrent incidents, 240+ active detection rules

\- 🔥 \*\*Multi-cloud log aggregation\*\* - Azure, AWS CloudTrail, GCP Security Command Center integration

\- 🔥 \*\*Real-time correlation\*\* - Sub-5-minute detection latency (MTTD reduced 87%)

\- 🔥 \*\*Enterprise tooling\*\* - Licensed platforms, not community editions

\- 🔥 \*\*Behavioral analytics\*\* - UEBA baselines, anomaly detection, risk scoring



\*\*Cost \& Commitment:\*\*

\- Monthly Azure spend: ~$83 (Log Analytics + compute)

\- Tenable.io: Enterprise subscription through May 2026

\- Total investment: ~$1,500+ annually in professional development



---



\## 📚 Project Status \& Roadmap



\### \*\*✅ Completed Work (Production-Ready)\*\*



\*\*SIEM Deployment \& Configuration\*\*

\- Azure Sentinel production environment (462 incidents, 240+ rules, 6 data connectors)

\- Log Analytics Workspace with retention policies and cost optimization

\- Multi-cloud log aggregation (Azure, AWS, GCP)

\- Alert rules with automated Logic Apps response playbooks



\*\*Detection Engineering\*\*

\- 4 detection rules analyzed with full documentation:

&nbsp; - Brute Force Login (T1110) - KQL + SPL translation

&nbsp; - PowerShell Web Request (T1059.001) - Command-line forensics

&nbsp; - Impossible Travel (T1078) - UEBA behavioral analytics

&nbsp; - Guest Account Remote Login (T1078/T1133) - Default credential monitoring

\- 10+ investigation query library (lateral movement, persistence, privilege escalation)

\- MITRE ATT\&CK framework mapping

\- Splunk SPL translation exercises (KQL → SPL comparison)



\*\*Incident Response\*\*

\- HIGH severity incident investigation (#193653 PowerShell malware)

\- PICERL methodology application (documented process)

\- Evidence collection and forensic analysis

\- Lateral movement and persistence checks

\- Production response playbook development



\*\*Platform Comparison\*\*

\- Azure Sentinel vs Splunk vs Securonix feature analysis

\- Terminology translation guides

\- Query language comparison (KQL, SPL, Securonix correlation logic)



\### \*\*🚧 In Progress (Active Development)\*\*



\*\*Detection Rule Expansion\*\*

\- Additional correlation rules for insider threat scenarios

\- Email-based data exfiltration detection (Google Workspace / Microsoft 365)

\- Cloud file sharing anomalies (Drive / OneDrive)

\- Privilege escalation monitoring enhancements



\*\*Platform Integration\*\*

\- Splunk Enterprise deployment on Azure VM (hands-on SPL development)

\- Advanced KQL optimization for large-scale log queries

\- Tenable vulnerability data correlation with SIEM events



\*\*Advanced Analytics\*\*

\- Python automation for alert enrichment and triage

\- Threat intelligence API integrations (VirusTotal, AbuseIPDB)

\- Behavioral analytics for privileged account monitoring



\### \*\*📋 Planned Work (Roadmap)\*\*



\*\*Future enhancements prioritized by business value:\*\*

\- Machine learning anomaly detection models (isolation forest, ARIMA)

\- Big data analytics with Azure Synapse/PySpark

\- Compliance framework mapping (NIST, PCI DSS, SOC 2)

\- Additional use case development (fraud detection, AML patterns)



\*Roadmap adjusted based on interview feedback and career goals.\*



---



\## 🔗 Related Projects



\*\*This SIEM portfolio complements my IAM automation work:\*\*



\*\*Identity \& Access Management Projects:\*\*

\- 🔐 \[Auth0 User Lifecycle Automation](https://github.com/Talha-Tabish/auth0-user-lifecycle-automation) - OAuth2, user provisioning, audit logging

\- 🔐 \[Okta Enterprise Provisioning Engine](https://github.com/Talha-Tabish/okta-enterprise-provisioning) - SCIM, group-based provisioning, workflow automation

\- ☁️ \[Multi-Cloud IAM Federation](https://github.com/Talha-Tabish/multi-cloud-iam-federation) - Azure AD ↔ AWS SAML federation, Terraform IaC

\- 🔐 \[Auth0 Enterprise Integration Suite](https://github.com/Talha-Tabish/auth0-enterprise-integration) - Production-ready Auth0 automation

\- 🔑 \[HashiCorp Vault PAM Automation](https://github.com/Talha-Tabish/vault-pam-automation) - Privileged access management, credential rotation



\*\*Complementary Focus:\*\*  

My IAM projects demonstrate \*identity lifecycle and access provisioning\* capabilities, while this SIEM portfolio demonstrates \*behavioral analytics and threat detection\*. Together, they show end-to-end security engineering - from identity management to security monitoring.



\*\*Career Progression:\*\*  

Security Generalist → IAM Specialist → SIEM Engineering Specialist



---



\## 📂 Repository Structure

```

enterprise-siem-mastery-lab/

├── README.md                          # This file

├── investigations/                    # Incident analysis reports

│   └── incident-193653-powershell-web-request.md

├── detection-rules/                   # Detection rule documentation

│   ├── brute-force-login.md

│   ├── powershell-web-request.md

│   ├── impossible-travel.md

│   └── guest-account-login.md

├── queries/                           # Investigation query library

│   └── README.md

├── use-cases/                         # Platform-specific detection use cases

│   ├── email-data-exfiltration.md

│   ├── drive-sharing-anomalies.md

│   └── account-compromise-detection.md

├── comparisons/                       # Platform comparison docs

│   ├── sentinel-vs-splunk.md

│   └── sentinel-vs-securonix.md

└── documentation/                     # Architecture and setup guides

&nbsp;   └── architecture-overview.md

```



\*Repository grows organically as projects develop. Focus on depth over breadth.\*



---



\## 📧 Contact



\*\*Muhammad Talha Tabish\*\*  

📍 Pittsburgh, PA  

🔗 \[GitHub Profile](https://github.com/Talha-Tabish)  

📧 Available for SIEM engineering opportunities



---



\*This portfolio demonstrates production-ready SIEM engineering capability through documented incident investigations, detection rule analysis, and platform expertise. All work is self-funded and self-directed as part of professional development in cybersecurity operations.\*

