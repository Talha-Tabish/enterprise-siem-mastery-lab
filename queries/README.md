\# KQL Investigation Query Library



Production-ready queries for incident response and threat hunting in Azure Sentinel.



---



\## Query Index



1\. \[Lateral Movement Detection](#1-lateral-movement-detection)

2\. \[Account Creation Monitoring](#2-account-creation-monitoring)

3\. \[Privilege Escalation Investigation](#3-privilege-escalation-investigation)

4\. \[PowerShell Execution Analysis](#4-powershell-execution-analysis)

5\. \[Failed Login Pattern Analysis](#5-failed-login-pattern-analysis)

6\. \[Pass-the-Hash Attack Detection](#6-pass-the-hash-attack-detection)

7\. \[Credential Dumping Detection](#7-credential-dumping-detection)

8\. \[Scheduled Task Creation](#8-scheduled-task-creation)

9\. \[Remote Desktop Login Monitoring](#9-remote-desktop-login-monitoring)

10\. \[Impossible Travel Detection](#10-impossible-travel-detection)



---



\## 1. Lateral Movement Detection



\*\*MITRE ATT\&CK:\*\* T1021 - Remote Services  

\*\*Use Case:\*\* Detect user accounts authenticating to multiple systems (potential lateral movement)  

\*\*Event ID:\*\* 4624 (Successful Logon), Logon Type 3 (Network)



```kql

SecurityEvent

| where EventID == 4624  // Successful logon

| where LogonType == 3   // Network logon (lateral movement indicator)

| where Account !endswith "$"  // Exclude machine accounts

| where Account !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")

| summarize 

&nbsp;   DistinctComputers = dcount(Computer),

&nbsp;   LoginCount = count(),

&nbsp;   Computers = make\_set(Computer)

&nbsp;   by bin(TimeGenerated, 1h), Account, IpAddress

| where DistinctComputers >= 3  // Threshold: 3+ systems in 1 hour

| order by DistinctComputers desc

```



\*\*When to Use:\*\* 

\- Investigating suspected compromise

\- Post-incident lateral movement analysis

\- Hunting for advanced persistent threats (APT)



\*\*Tuning Tips:\*\*

\- Adjust threshold based on environment (3-5 systems typical)

\- Exclude service accounts that legitimately access multiple systems

\- Lower threshold for privileged accounts (Domain Admins)



---



\## 2. Account Creation Monitoring



\*\*MITRE ATT\&CK:\*\* T1136.001 - Create Account (Local Account)  

\*\*Use Case:\*\* Monitor new user account creation for unauthorized access  

\*\*Event ID:\*\* 4720 (User Account Created)



```kql

SecurityEvent

| where EventID == 4720  // User account created

| extend 

&nbsp;   CreatedAccount = TargetAccount,

&nbsp;   CreatedBy = SubjectAccount,

&nbsp;   CreationTime = TimeGenerated

| project 

&nbsp;   CreationTime,

&nbsp;   CreatedAccount,

&nbsp;   CreatedBy,

&nbsp;   Computer,

&nbsp;   TargetDomainName

| order by CreationTime desc

```



\*\*When to Use:\*\*

\- Detecting persistence mechanisms

\- Insider threat investigations

\- Unauthorized admin account creation

\- Compliance auditing



\*\*Follow-up Investigation:\*\*

\- Check Event 4728 (account added to privileged groups)

\- Verify if created account has admin rights

\- Correlate with Event 4624 (first login of new account)



---



\## 3. Privilege Escalation Investigation



\*\*MITRE ATT\&CK:\*\* T1078.002 - Valid Accounts (Domain Accounts)  

\*\*Use Case:\*\* Detect users added to privileged security groups  

\*\*Event ID:\*\* 4728 (User Added to Security-Enabled Global Group)



```kql

SecurityEvent

| where EventID == 4728  // User added to global group

| where TargetUserName in (

&nbsp;   "Domain Admins",

&nbsp;   "Enterprise Admins",

&nbsp;   "Administrators",

&nbsp;   "Schema Admins",

&nbsp;   "Account Operators",

&nbsp;   "Backup Operators"

)

| extend 

&nbsp;   PrivilegedGroup = TargetUserName,

&nbsp;   AddedUser = MemberName,

&nbsp;   AddedBy = SubjectAccount

| project 

&nbsp;   TimeGenerated,

&nbsp;   PrivilegedGroup,

&nbsp;   AddedUser,

&nbsp;   AddedBy,

&nbsp;   Computer

| order by TimeGenerated desc

```



\*\*When to Use:\*\*

\- Privilege escalation detection

\- Insider threat monitoring

\- Post-compromise investigation

\- Compliance auditing (who has admin rights?)



\*\*Alert Threshold:\*\*

\- ANY addition to Domain Admins/Enterprise Admins = HIGH severity

\- Additions to Administrators group = MEDIUM severity



---



\## 4. PowerShell Execution Analysis



\*\*MITRE ATT\&CK:\*\* T1059.001 - PowerShell  

\*\*Use Case:\*\* Hunt for suspicious PowerShell commands and scripts  

\*\*Event ID:\*\* 4688 (Process Creation)



```kql

SecurityEvent

| where EventID == 4688

| where Process has "powershell.exe"

| where ProcessCommandLine has\_any (

&nbsp;   "Invoke-WebRequest",

&nbsp;   "Invoke-RestMethod",

&nbsp;   "DownloadFile",

&nbsp;   "IEX",

&nbsp;   "Invoke-Expression",

&nbsp;   "EncodedCommand",

&nbsp;   "-enc",

&nbsp;   "Net.WebClient",

&nbsp;   "Start-Process",

&nbsp;   "Invoke-Mimikatz",

&nbsp;   "bypass"

)

| extend 

&nbsp;   CommandLength = strlen(ProcessCommandLine),

&nbsp;   HasObfuscation = iff(ProcessCommandLine has "EncodedCommand", "Yes", "No")

| project 

&nbsp;   TimeGenerated,

&nbsp;   Account,

&nbsp;   Computer,

&nbsp;   ProcessCommandLine,

&nbsp;   CommandLength,

&nbsp;   HasObfuscation,

&nbsp;   ParentProcessName

| order by TimeGenerated desc

```



\*\*When to Use:\*\*

\- Malware execution investigation

\- Living-off-the-land binary (LOLBin) detection

\- Command-and-control (C2) activity

\- Data exfiltration hunting



\*\*Investigation Tips:\*\*

\- Commands > 500 characters often indicate obfuscation

\- EncodedCommand requires Base64 decoding

\- Check ParentProcessName (explorer.exe = user-initiated, unexpected parent = suspicious)



---



\## 5. Failed Login Pattern Analysis



\*\*MITRE ATT\&CK:\*\* T1110 - Brute Force  

\*\*Use Case:\*\* Analyze failed login patterns to identify attack campaigns  

\*\*Event ID:\*\* 4625 (Failed Logon)



```kql

SecurityEvent

| where EventID == 4625  // Failed logon

| where AccountType == "User"

| extend 

&nbsp;   FailureReason = case(

&nbsp;       Status == "0xC000006D", "Bad Username",

&nbsp;       Status == "0xC000006A", "Bad Password",

&nbsp;       Status == "0xC0000234", "Account Locked",

&nbsp;       Status == "0xC0000064", "Account Does Not Exist",

&nbsp;       Status == "0xC000006F", "Outside Logon Hours",

&nbsp;       Status == "0xC0000072", "Account Disabled",

&nbsp;       "Other"

&nbsp;   )

| summarize 

&nbsp;   FailureCount = count(),

&nbsp;   UniqueAccounts = dcount(Account),

&nbsp;   FailureReasons = make\_set(FailureReason),

&nbsp;   Accounts = make\_set(Account)

&nbsp;   by bin(TimeGenerated, 5m), IpAddress, Computer

| where FailureCount >= 10  // High-volume failures

| order by FailureCount desc

```



\*\*When to Use:\*\*

\- Distinguishing brute force vs password spray attacks

\- Identifying attacker infrastructure (source IPs)

\- Understanding attack methodology



\*\*Pattern Recognition:\*\*

\- Many failures, one account = Brute force

\- Few failures per account, many accounts = Password spray

\- "Account Does Not Exist" = Username enumeration



---



\## 6. Pass-the-Hash Attack Detection



\*\*MITRE ATT\&CK:\*\* T1550.002 - Pass the Hash  

\*\*Use Case:\*\* Detect NTLM authentication without prior Kerberos ticket  

\*\*Event IDs:\*\* 4768 (Kerberos TGT Request), 4769 (Kerberos Service Ticket)



```kql

SecurityEvent

| where EventID in (4768, 4769)  // Kerberos authentication

| where Status == "0x0"  // Successful

| where TicketEncryptionType == "0x17"  // RC4 encryption (Pass-the-Hash indicator)

| extend 

&nbsp;   AuthType = case(

&nbsp;       EventID == 4768, "TGT Request",

&nbsp;       EventID == 4769, "Service Ticket",

&nbsp;       "Unknown"

&nbsp;   )

| summarize 

&nbsp;   AuthCount = count(),

&nbsp;   Computers = make\_set(Computer)

&nbsp;   by bin(TimeGenerated, 5m), Account, IpAddress, TicketEncryptionType

| where AuthCount >= 5  // Multiple authentications with RC4

| order by TimeGenerated desc

```



\*\*When to Use:\*\*

\- Post-compromise lateral movement investigation

\- Advanced persistent threat (APT) hunting

\- Credential theft detection



\*\*Detection Logic:\*\*

\- RC4 encryption (0x17) = Legacy/weak, often indicates Pass-the-Hash

\- Modern systems use AES256 (0x12)

\- Multiple rapid RC4 auths = suspicious



---



\## 7. Credential Dumping Detection



\*\*MITRE ATT\&CK:\*\* T1003 - OS Credential Dumping  

\*\*Use Case:\*\* Detect tools accessing LSASS memory (Mimikatz, ProcDump)  

\*\*Event ID:\*\* 4688 (Process Creation), 4656 (Handle to Object Requested)



```kql

SecurityEvent

| where EventID == 4688

| where ProcessCommandLine has\_any (

&nbsp;   "lsass",

&nbsp;   "lsass.exe",

&nbsp;   "lsass.dmp",

&nbsp;   "mimikatz",

&nbsp;   "procdump",

&nbsp;   "sekurlsa",

&nbsp;   "gsecdump",

&nbsp;   "wce.exe",

&nbsp;   "pwdump"

)

| extend 

&nbsp;   CredentialDumpingTool = case(

&nbsp;       ProcessCommandLine has "mimikatz", "Mimikatz",

&nbsp;       ProcessCommandLine has "procdump", "ProcDump",

&nbsp;       ProcessCommandLine has "lsass.dmp", "LSASS Memory Dump",

&nbsp;       "Suspicious Process"

&nbsp;   )

| project 

&nbsp;   TimeGenerated,

&nbsp;   Account,

&nbsp;   Computer,

&nbsp;   ProcessCommandLine,

&nbsp;   CredentialDumpingTool,

&nbsp;   ParentProcessName

| order by TimeGenerated desc

```



\*\*When to Use:\*\*

\- HIGH severity alerts (credential theft = critical)

\- Post-breach investigation

\- Hunting for credential harvesting



\*\*Immediate Response:\*\*

\- Isolate endpoint immediately

\- Force password resets for all accounts on affected system

\- Check for lateral movement from compromised credentials



---



\## 8. Scheduled Task Creation



\*\*MITRE ATT\&CK:\*\* T1053.005 - Scheduled Task  

\*\*Use Case:\*\* Detect persistence via scheduled tasks  

\*\*Event ID:\*\* 4698 (Scheduled Task Created)



```kql

SecurityEvent

| where EventID == 4698  // Scheduled task created

| extend 

&nbsp;   TaskName = extract("Task Name:\\\\s+(.+)", 1, tostring(EventData)),

&nbsp;   TaskContent = tostring(EventData)

| where TaskContent has\_any (

&nbsp;   "powershell",

&nbsp;   "cmd.exe",

&nbsp;   "wscript",

&nbsp;   "cscript",

&nbsp;   "regsvr32",

&nbsp;   "rundll32",

&nbsp;   "mshta"

)

| project 

&nbsp;   TimeGenerated,

&nbsp;   Account,

&nbsp;   Computer,

&nbsp;   TaskName,

&nbsp;   TaskContent

| order by TimeGenerated desc

```



\*\*When to Use:\*\*

\- Persistence mechanism detection

\- Post-compromise hunting

\- Insider threat monitoring



\*\*Suspicious Indicators:\*\*

\- Tasks running PowerShell/scripts

\- Tasks executing from temp directories

\- Tasks created by non-admin accounts

\- Tasks with names mimicking system tasks



---



\## 9. Remote Desktop Login Monitoring



\*\*MITRE ATT\&CK:\*\* T1021.001 - Remote Desktop Protocol  

\*\*Use Case:\*\* Monitor RDP access to critical systems  

\*\*Event ID:\*\* 4624 (Successful Logon), Logon Type 10 (RDP)



```kql

SecurityEvent

| where EventID == 4624  // Successful logon

| where LogonType == 10  // RDP logon

| extend 

&nbsp;   SourceIP = IpAddress,

&nbsp;   TargetSystem = Computer,

&nbsp;   RDPUser = Account

| summarize 

&nbsp;   LoginCount = count(),

&nbsp;   FirstLogin = min(TimeGenerated),

&nbsp;   LastLogin = max(TimeGenerated),

&nbsp;   TargetSystems = make\_set(Computer)

&nbsp;   by RDPUser, SourceIP

| order by LoginCount desc

```



\*\*When to Use:\*\*

\- Monitoring privileged access

\- Detecting unauthorized RDP sessions

\- Investigating lateral movement via RDP

\- Compliance auditing



\*\*Alert Criteria:\*\*

\- RDP from external IPs = HIGH severity

\- RDP to Domain Controllers = CRITICAL

\- RDP outside business hours = MEDIUM severity



---



\## 10. Impossible Travel Detection



\*\*MITRE ATT\&CK:\*\* T1078 - Valid Accounts  

\*\*Use Case:\*\* Detect logins from geographically impossible locations  

\*\*Data Source:\*\* Azure AD SigninLogs



```kql

SigninLogs

| where ResultType == 0  // Successful sign-in

| extend 

&nbsp;   Location1 = tostring(LocationDetails.city),

&nbsp;   Country1 = tostring(LocationDetails.countryOrRegion),

&nbsp;   Latitude = toreal(LocationDetails.geoCoordinates.latitude),

&nbsp;   Longitude = toreal(LocationDetails.geoCoordinates.longitude)

| order by UserPrincipalName, TimeGenerated asc

| serialize

| extend 

&nbsp;   PrevLocation = prev(Location1),

&nbsp;   PrevTime = prev(TimeGenerated),

&nbsp;   TimeDiff = datetime\_diff('minute', TimeGenerated, PrevTime)

| where UserPrincipalName == prev(UserPrincipalName)

| where Location1 != PrevLocation

| where TimeDiff < 60  // Less than 1 hour between logins

| where Location1 != "" and PrevLocation != ""

| project 

&nbsp;   TimeGenerated,

&nbsp;   UserPrincipalName,

&nbsp;   PrevLocation,

&nbsp;   Location1,

&nbsp;   TimeDiff,

&nbsp;   IPAddress

| order by TimeDiff asc

```



\*\*When to Use:\*\*

\- Compromised credential detection

\- Account takeover investigation

\- Insider threat with VPN abuse



\*\*Legitimate Scenarios (Whitelist):\*\*

\- VPN exit points in different countries

\- Users traveling internationally

\- Shared accounts (discouraged but common)



---



\## Query Usage Tips



\### Investigation Workflow



1\. \*\*Start Broad:\*\* Use time-based queries to identify suspicious timeframes

2\. \*\*Narrow Down:\*\* Add account/computer filters based on initial findings

3\. \*\*Pivot:\*\* Use related Event IDs to build full attack timeline

4\. \*\*Correlate:\*\* Combine multiple queries to validate findings



\### Performance Optimization



\- Always include time filters: `| where TimeGenerated > ago(24h)`

\- Use `summarize` instead of raw event dumps

\- Test queries on small time windows first

\- Add `| take 100` during development



\### Saving Custom Queries



In Azure Sentinel:

1\. Log Analytics → Queries

2\. Save Query → Name + Category

3\. Pin frequently used queries to dashboard



---



\## Integration with Detection Rules



These queries can be converted to scheduled analytics rules:



\*\*Example: Convert Query #1 to Alert Rule\*\*



```kql

// Lateral Movement Alert Rule

SecurityEvent

| where EventID == 4624

| where LogonType == 3

| where Account !endswith "$"

| summarize DistinctComputers = dcount(Computer) by bin(TimeGenerated, 1h), Account

| where DistinctComputers >= 3

// Rule Configuration:

// Frequency: Every 1 hour

// Lookback: 1 hour

// Severity: HIGH

// Tactics: Lateral Movement

```



---



\## References



\- \[MITRE ATT\&CK Framework](https://attack.mitre.org/)

\- \[Windows Security Event IDs](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)

\- \[Azure Sentinel KQL Documentation](https://docs.microsoft.com/en-us/azure/sentinel/kusto-overview)



---



Last Updated: October 15, 2025  

Author: Muhammad Talha Tabish  

Status: Production-Tested

