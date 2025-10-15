# KQL Investigation Query Library

Production-ready queries for incident response and threat hunting in Azure Sentinel.

---

## Query Index

1. [Lateral Movement Detection](#1-lateral-movement-detection)
2. [Account Creation Monitoring](#2-account-creation-monitoring)
3. [Privilege Escalation Investigation](#3-privilege-escalation-investigation)
4. [PowerShell Execution Analysis](#4-powershell-execution-analysis)
5. [Failed Login Pattern Analysis](#5-failed-login-pattern-analysis)
6. [Pass-the-Hash Attack Detection](#6-pass-the-hash-attack-detection)
7. [Credential Dumping Detection](#7-credential-dumping-detection)
8. [Scheduled Task Creation](#8-scheduled-task-creation)
9. [Remote Desktop Login Monitoring](#9-remote-desktop-login-monitoring)
10. [Impossible Travel Detection](#10-impossible-travel-detection)

---

## 1. Lateral Movement Detection

**Purpose:** Detect suspicious network logons indicating lateral movement across systems.

**MITRE ATT&CK:** T1021 - Remote Services

```kql
SecurityEvent
| where EventID == 4624  // Successful logon
| where LogonType == 3   // Network logon
| where Account !endswith "$"  // Exclude machine accounts
| where Account !in ("ANONYMOUS LOGON", "LOCAL SERVICE", "NETWORK SERVICE")
| summarize 
    LogonCount = count(),
    DistinctComputers = dcount(Computer),
    Computers = make_set(Computer)
    by bin(TimeGenerated, 5m), Account, IpAddress
| where DistinctComputers >= 3  // Logged into 3+ systems
| order by LogonCount desc
```

**Use Case:** Investigation after malware detection or compromised account

**Threshold Tuning:** Adjust DistinctComputers based on environment (3-5 typical)

---

## 2. Account Creation Monitoring

**Purpose:** Track new user account creation for unauthorized access detection.

**MITRE ATT&CK:** T1136.001 - Create Account: Local Account

```kql
SecurityEvent
| where EventID == 4720  // User account created
| project 
    TimeGenerated,
    NewAccount = TargetAccount,
    CreatedBy = SubjectAccount,
    Computer,
    AccountDomain = TargetDomainName
| order by TimeGenerated desc
```

**Use Case:** Persistence mechanism detection, insider threat investigation

**Alert On:** Account creation outside business hours or by non-admin users

---

## 3. Privilege Escalation Investigation

**Purpose:** Monitor additions to privileged security groups.

**MITRE ATT&CK:** T1098 - Account Manipulation

```kql
SecurityEvent
| where EventID == 4728  // User added to security-enabled global group
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins")
| project 
    TimeGenerated,
    AddedUser = MemberName,
    AddedBy = SubjectAccount,
    PrivilegedGroup = TargetUserName,
    Computer
| order by TimeGenerated desc
```

**Use Case:** Privilege escalation detection, unauthorized admin access

**Alert On:** Any addition to Domain Admins or Enterprise Admins groups

---

## 4. PowerShell Execution Analysis

**Purpose:** Detect suspicious PowerShell commands indicating malware or attack tools.

**MITRE ATT&CK:** T1059.001 - PowerShell

```kql
SecurityEvent
| where EventID == 4688  // Process creation
| where Process has_any ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "Invoke-WebRequest",
    "Invoke-RestMethod", 
    "DownloadFile",
    "IEX",
    "Invoke-Expression",
    "EncodedCommand",
    "FromBase64String",
    "-enc",
    "Bypass"
)
| project 
    TimeGenerated,
    Account,
    Computer,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

**Use Case:** Malware download detection, living-off-the-land attack investigation

**Alert On:** Encoded commands, web download functions, execution policy bypass

---

## 5. Failed Login Pattern Analysis

**Purpose:** Identify brute force attacks and credential stuffing attempts.

**MITRE ATT&CK:** T1110 - Brute Force

```kql
SecurityEvent
| where EventID == 4625  // Failed logon
| where AccountType == "User"
| summarize 
    FailureCount = count(),
    FailureReasons = make_set(SubStatus),
    TargetComputers = make_set(Computer)
    by bin(TimeGenerated, 5m), Account, IpAddress
| where FailureCount >= 5
| extend 
    AttackType = case(
        FailureCount >= 20, "Aggressive Brute Force",
        FailureCount >= 10, "Moderate Brute Force",
        "Potential Brute Force"
    )
| order by FailureCount desc
```

**Use Case:** Brute force attack detection, account lockout investigation

**Threshold:** 5+ failures in 5 minutes (adjust based on baseline)

---

## 6. Pass-the-Hash Attack Detection

**Purpose:** Detect NTLM authentication anomalies indicating pass-the-hash attacks.

**MITRE ATT&CK:** T1550.002 - Use Alternate Authentication Material: Pass the Hash

```kql
SecurityEvent
| where EventID == 4624  // Successful logon
| where LogonType == 3  // Network logon
| where AuthenticationPackageName == "NTLM"
| where Account !endswith "$"
| summarize 
    LogonCount = count(),
    UniqueWorkstations = dcount(WorkstationName),
    Workstations = make_set(WorkstationName)
    by bin(TimeGenerated, 1h), Account, IpAddress
| where UniqueWorkstations >= 5  // Same account, multiple sources
| order by LogonCount desc
```

**Use Case:** Credential theft detection, advanced persistent threat (APT) investigation

**Alert On:** High-value accounts with unusual NTLM authentication patterns

---

## 7. Credential Dumping Detection

**Purpose:** Detect tools attempting to extract credentials from memory.

**MITRE ATT&CK:** T1003 - OS Credential Dumping

```kql
SecurityEvent
| where EventID == 4688  // Process creation
| where ProcessCommandLine has_any (
    "mimikatz",
    "procdump",
    "lsass",
    "sekurlsa",
    "pwdump",
    "gsecdump"
)
or Process has_any (
    "mimikatz.exe",
    "procdump.exe",
    "procdump64.exe"
)
| project 
    TimeGenerated,
    Account,
    Computer,
    Process,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

**Use Case:** Post-exploitation activity detection, credential theft investigation

**Alert On:** Any execution of credential dumping tools

---

## 8. Scheduled Task Creation

**Purpose:** Monitor scheduled task creation for persistence mechanisms.

**MITRE ATT&CK:** T1053.005 - Scheduled Task/Job: Scheduled Task

```kql
SecurityEvent
| where EventID == 4698  // Scheduled task created
| project 
    TimeGenerated,
    TaskName,
    CreatedBy = SubjectAccount,
    Computer,
    TaskContent
| order by TimeGenerated desc
```

**Use Case:** Persistence mechanism detection, malware investigation

**Alert On:** Tasks created by non-admin users or unusual task names

---

## 9. Remote Desktop Login Monitoring

**Purpose:** Track RDP connections for unauthorized remote access.

**MITRE ATT&CK:** T1021.001 - Remote Services: Remote Desktop Protocol

```kql
SecurityEvent
| where EventID == 4624  // Successful logon
| where LogonType == 10  // RemoteInteractive (RDP)
| where Account !endswith "$"
| project 
    TimeGenerated,
    Account,
    SourceIP = IpAddress,
    TargetComputer = Computer,
    LogonType
| order by TimeGenerated desc
```

**Use Case:** Remote access monitoring, insider threat detection

**Alert On:** RDP from external IPs, non-business hours access

---

## 10. Impossible Travel Detection

**Purpose:** Identify logons from geographically impossible locations.

**MITRE ATT&CK:** T1078 - Valid Accounts

```kql
SigninLogs
| where ResultType == 0  // Successful sign-in
| where Location != ""
| extend 
    PreviousLocation = prev(Location, 1),
    PreviousTime = prev(TimeGenerated, 1)
| where PreviousLocation != Location
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PreviousTime)
| where TimeDiff <= 60  // Less than 1 hour between logins
| project 
    TimeGenerated,
    UserPrincipalName,
    CurrentLocation = Location,
    PreviousLocation,
    TimeDiffMinutes = TimeDiff,
    IPAddress,
    AppDisplayName
| order by TimeGenerated desc
```

**Use Case:** Compromised credential detection, account takeover investigation

**Alert On:** Multiple geographic locations within physically impossible timeframes

---

## Query Usage Guidelines

**Investigation Workflow:**
1. Start with broad queries (Failed Logins, Account Creation)
2. Narrow based on findings (Lateral Movement, Privilege Escalation)
3. Correlate across multiple queries for timeline reconstruction
4. Export results for documentation and reporting

**Performance Optimization:**
- Use time filters to limit query scope: `| where TimeGenerated > ago(24h)`
- Add Computer filters for targeted investigations: `| where Computer == "TARGET-PC"`
- Use summarize for aggregation instead of multiple where clauses

**False Positive Reduction:**
- Establish baselines for each query in your environment
- Whitelist known service accounts and automated processes
- Adjust thresholds based on organizational behavior patterns

---

**Last Updated:** October 15, 2025  
**Author:** Muhammad Talha Tabish  
**Status:** Production-Ready