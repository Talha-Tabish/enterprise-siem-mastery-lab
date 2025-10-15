# Incident #193653 - PowerShell Invoke-WebRequest Investigation

**Incident ID:** 193653  
**Severity:** HIGH  
**MITRE ATT&CK:** T1059.001 (PowerShell Execution)  
**Detection Date:** October 12, 2025  
**Investigation Date:** October 12, 2025, 8:00 PM - 10:00 PM EST  
**Investigator:** Muhammad Talha Tabish  
**Status:** CLOSED - Training Exercise

---

## Executive Summary

Azure Sentinel detected HIGH severity PowerShell web request activity on October 12, 2025. The alert triggered on Event ID 4688 (process creation) indicating PowerShell executing Invoke-WebRequest commands to an external URL. Initial triage suggested potential malware download or command-and-control (C2) communication.

**Investigation Outcome:** Through systematic forensic analysis using the PICERL framework, this incident was confirmed as a **training exercise** within the LAW-Cyber-Range environment. Five independent indicators validated this assessment, including EICAR test file signatures, test username patterns, and cyber range context.

**Key Finding:** Command-line logging (Event ID 4688 with ProcessCommandLine field) was critical to root cause analysis. Without this audit policy, the investigation would have required significantly more time and resources.

---

## Alert Details

**Azure Sentinel Alert Information:**
- **Alert Name:** PowerShell Invoke-WebRequest Detected
- **Alert ID:** 193653
- **Severity:** HIGH
- **Detection Rule:** PowerShell Web Request Activity
- **Triggered:** October 12, 2025, 8:15 PM EST
- **Environment:** LAW-Cyber-Range (Azure Sentinel Workspace)

**Initial Indicators:**
- PowerShell process (powershell.exe) execution detected
- Invoke-WebRequest command with external URL
- Execution duration: 5-minute burst (anomalous pattern)
- User account: user123 (non-administrative)
- Source computer: DESKTOP-TEST-01

---

## Investigation Methodology - PICERL Framework

### P - PREPARE (8:00 PM - 8:10 PM)

**Gathered Required Context:**
- Alert severity and description
- Detection rule logic and threshold
- Expected baseline behavior
- Recent security advisories

**Tools Prepared:**
- Azure Sentinel Log Analytics workspace
- KQL query templates for investigation
- MITRE ATT&CK framework reference
- Incident response playbook

**Initial Assessment:**
- **Risk Level:** Potentially HIGH if malware download or C2
- **Urgency:** Immediate investigation required
- **Scope:** Single user, single endpoint initially

---

### I - IDENTIFY (8:10 PM - 8:30 PM)

**Event ID 4688 Analysis:**

Queried Log Analytics for process creation events:

```
SecurityEvent
| where EventID == 4688
| where Process has "powershell.exe"
| where TimeGenerated between (datetime(2025-10-12 20:10:00) .. datetime(2025-10-12 20:20:00))
| where Account == "user123"
| project TimeGenerated, Account, Computer, ProcessCommandLine
```

**Key Findings from Command-Line Analysis:**

**Command Executed:**
```
powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'http://testdomain.com/eicar.txt' -OutFile 'C:\temp\test.txt'"
```

**Red Flags Identified:**
1. `-ExecutionPolicy Bypass` - Attempting to bypass script execution policy
2. `Invoke-WebRequest` - Downloading file from external URL
3. External domain: testdomain.com (unknown origin)
4. Output file: C:\temp\test.txt (local disk write)

**CRITICAL CLARIFICATION - ExecutionPolicy Bypass:**
- Does NOT bypass antivirus or EDR detection
- Only disables PowerShell script signing policy
- Windows Defender still scans downloaded files
- This is commonly misunderstood even by security professionals

---

**Timeline Reconstruction:**

| Time (EST) | Event | Details |
|------------|-------|---------|
| 20:10:15 | PowerShell process start | User123 launched powershell.exe |
| 20:10:18 | Invoke-WebRequest execution | Download initiated to testdomain.com |
| 20:10:22 | File write | test.txt saved to C:\temp\ |
| 20:10:25 | Process termination | PowerShell.exe closed |
| 20:15:30 | Alert triggered | Azure Sentinel HIGH severity alert |

**Duration Analysis:**
- Total execution: 10 seconds (20:10:15 → 20:10:25)
- 5-minute window in alert (likely aggregation window)
- Single execution, not sustained activity

---

**Lateral Movement Check:**

Queried for subsequent network logons (Event ID 4624, Logon Type 3):

```
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where Account == "user123"
| where TimeGenerated > datetime(2025-10-12 20:10:00)
| project TimeGenerated, Computer, IpAddress
```

**Result:** No lateral movement detected. User123 did not authenticate to other systems.

---

**Persistence Mechanism Check:**

Searched for account creation or privilege escalation:

```
SecurityEvent
| where EventID in (4720, 4728, 4732)  // Account created, user added to group
| where TimeGenerated > datetime(2025-10-12 20:10:00)
| where SubjectAccount == "user123" or TargetAccount == "user123"
```

**Result:** No persistence mechanisms created. No new accounts, no privilege escalation.

---

### C - CONTAIN (8:30 PM - 8:40 PM)

**Initial Containment Assessment:**

**Evidence Suggesting Training Exercise (Not Real Attack):**
1. **EICAR Test File:** URL contains "eicar.txt" - industry-standard antivirus test file
2. **Test Username:** "user123" follows training naming convention
3. **Test Computer:** "DESKTOP-TEST-01" indicates test environment
4. **Cyber Range Context:** LAW-Cyber-Range workspace used for training
5. **File Location:** C:\temp\ (typical training sandbox location)

**EICAR Test File Background:**
- European Institute for Computer Antivirus Research standard
- Harmless text file that antivirus treats as malware
- Used globally for testing AV detection without real malware
- Content: Plain text ASCII string, not executable code

**Decision:** Based on 5 independent indicators, this is a training exercise. **No containment actions required.**

**Hypothetical Production Response (if this were real):**
- Isolate endpoint from network immediately
- Disable user account user123
- Block testdomain.com at firewall/proxy
- Initiate malware scan on DESKTOP-TEST-01
- Alert SOC team for coordinated response

---

### E - ERADICATE (8:40 PM - 8:50 PM)

**Training Exercise Context:**
No eradication required as this is not a real threat.

**Hypothetical Production Eradication (if real attack):**
1. **Remove malware:** Delete C:\temp\test.txt and scan for additional artifacts
2. **Remove persistence:** Check scheduled tasks, registry run keys, startup folders
3. **Credential reset:** Force password change for user123
4. **System rebuild:** If heavily compromised, reimage endpoint
5. **Network cleanup:** Remove any C2 beacons or backdoors

---

### R - RECOVER (8:50 PM - 9:00 PM)

**Training Exercise:**
No recovery actions needed. System remains operational for continued training.

**Hypothetical Production Recovery:**
1. **Restore from backup:** If data was encrypted/deleted
2. **Re-enable user account:** After password reset and security training
3. **Network reconnection:** After confirming system is clean
4. **Monitor for reinfection:** 72-hour enhanced monitoring period

---

### L - LESSONS LEARNED (9:00 PM - 10:00 PM)

**What Worked Well:**

1. **Command-Line Logging Was Critical**
   - Event ID 4688 with ProcessCommandLine enabled full investigation
   - Without this, we'd only see "powershell.exe" without context
   - **Recommendation:** Ensure all production systems have command-line audit policy enabled

2. **PICERL Framework Provided Structure**
   - Systematic approach prevented rushing to conclusions
   - Ensured comprehensive evidence collection
   - Documented decision-making process for audit trail

3. **Detection Rule Triggered Appropriately**
   - PowerShell web requests are legitimate concern
   - Alert fired within 5 minutes (good MTTD - Mean Time to Detect)

**What Could Be Improved:**

1. **False Positive Rate**
   - Training environments should be whitelisted to reduce alert noise
   - **Recommendation:** Add "LAW-Cyber-Range" workspace exclusion to production rules

2. **EICAR File Download Flagging**
   - Legitimate security testing triggers HIGH severity alerts
   - **Recommendation:** Create separate detection rule for EICAR downloads with INFORMATIONAL severity

3. **Context Enrichment**
   - Alert didn't include "cyber range" context automatically
   - **Recommendation:** Tag training/test systems in asset inventory for automatic enrichment

**Production Playbook Development:**

Based on this investigation, created response playbook for real PowerShell malware incidents:

**Tier 1 Analyst Actions (0-15 minutes):**
- Review Event ID 4688 for full command line
- Check if EICAR test file (training) or real malware
- Verify user account legitimacy (AD lookup)
- Check endpoint location (physical/virtual, prod/test)

**Tier 2 Analyst Actions (15-45 minutes):**
- Full timeline reconstruction (5 minutes before/after)
- Lateral movement analysis (Event 4624 queries)
- Persistence check (scheduled tasks, registry, accounts)
- Malware sample collection (if safe)

**Tier 3 / Incident Commander Actions (45+ minutes):**
- Containment decision (isolate or monitor)
- Stakeholder notification (management, legal, CISO)
- Coordinate with endpoint security team
- Determine root cause (phishing, exploit, insider)

---

## Technical Evidence

**Event ID 4688 - Process Creation:**

**Raw Log Sample:**
```
TimeGenerated: 2025-10-12 20:10:15
EventID: 4688
Computer: DESKTOP-TEST-01
Account: LAW-CYBER-RANGE\user123
Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessCommandLine: powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'http://testdomain.com/eicar.txt' -OutFile 'C:\temp\test.txt'"
ParentProcessName: C:\Windows\explorer.exe
NewProcessId: 0x1a4c
TokenElevationType: %%1936 (Default - not elevated)
```

**Key Fields for Investigation:**
- **ProcessCommandLine:** Full command with arguments (CRITICAL field)
- **ParentProcessName:** Explorer.exe = user-initiated, not automated script
- **TokenElevationType:** Not elevated = no admin privileges used
- **Computer:** DESKTOP-TEST-01 = test environment indicator

---

## Where to Find Critical Information in Azure Sentinel

**For Future Investigations:**

**1. ProcessCommandLine Field:**
- Location: Log Analytics → SecurityEvent table → ProcessCommandLine column
- Enable: Group Policy → Computer Config → Policies → Admin Templates → System → Audit Process Creation → Include command line in process creation events = ENABLED

**2. Incident Duration:**
- Incident Panel → "Time Generated" (start time)
- Compare first event vs last event timestamps
- Use KQL: `| summarize min(TimeGenerated), max(TimeGenerated)`

**3. MITRE ATT&CK Mapping:**
- Incident Panel → "Tactics and techniques" section
- Shows T1059.001 (PowerShell) classification
- Links to MITRE ATT&CK framework documentation

**4. Related Events:**
- Incident Panel → "Related events" or "Investigate" button
- Opens Log Analytics with filtered query
- Shows all events in same timeframe for same entity

**5. Alert Rule Logic:**
- Analytics → Active rules → Search for "PowerShell"
- View KQL query used for detection
- Review threshold and frequency settings

---

## MITRE ATT&CK Mapping

**Primary Technique:**
- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **Tactic:** Execution
- **Description:** Adversaries abuse PowerShell for executing malicious commands
- **Detection:** Monitor Event ID 4688 with command-line logging enabled

**Related Techniques (Not Observed in This Incident):**
- T1105 - Ingress Tool Transfer (file download, but EICAR test file)
- T1027 - Obfuscated Files or Information (ExecutionPolicy bypass attempt)
- T1071 - Application Layer Protocol (HTTP used for download)

---

## Interview Talking Points

**Question: "Walk me through how you investigated this PowerShell alert"**

**Answer Framework:**
"I received a HIGH severity alert for PowerShell Invoke-WebRequest activity. I used the PICERL framework for systematic investigation.

First, I queried Event ID 4688 in Log Analytics to get the full command line. This showed me the exact PowerShell command - it was downloading from testdomain.com with ExecutionPolicy Bypass.

I clarified that ExecutionPolicy Bypass does NOT bypass antivirus - common misconception. It only disables PowerShell script signing checks.

Then I checked for lateral movement using Event 4624 network logons - nothing found. Checked for persistence with Event 4720 and 4728 - no new accounts or privilege escalation.

The key evidence that made me confident this was a training exercise: EICAR test file in the URL, username 'user123', computer name 'DESKTOP-TEST-01', and the LAW-Cyber-Range environment context. All five indicators aligned.

In production, I would have contained immediately - isolated the endpoint, disabled the account, blocked the domain. But with training confirmed, I documented it as a lessons-learned exercise and recommended whitelisting cyber range environments to reduce false positives."

---

**Question: "How would you handle this in Splunk or Securonix?"**

**Answer Framework:**
"The core investigation process is platform-agnostic. I'd use the same PICERL methodology.

In Sentinel, I used KQL to query SecurityEvent table for Event 4688. In Splunk, I'd use SPL to query the Windows Event logs with EventCode=4688. In Securonix, I'd query their normalized process creation logs using their correlation search language.

The field names differ - Sentinel calls it ProcessCommandLine, Securonix might call it CommandLine or ProcessArgs - but the logic is the same: filter for powershell.exe + web download commands + external URLs.

The detection rule would use Securonix's threat model with similar correlation logic. Same investigation queries, same timeline reconstruction, same lateral movement checks - just different query syntax."

---

## Supporting Evidence

**Evidence Collected:**
- ✅ Event ID 4688 logs from Log Analytics (PowerShell process creation)
- ✅ Alert details from Azure Sentinel incident panel
- ✅ Screenshots of investigation process
- ✅ Timeline reconstruction
- ✅ Lateral movement query results (negative findings)
- ✅ Persistence check query results (negative findings)

**Evidence Location:**
- Azure Sentinel Incident #193653 (archived)
- Log Analytics Workspace: LAW-Cyber-Range
- Investigation timeframe: 10/12/2025 8:00 PM - 10:00 PM EST

---

## Conclusion

**Final Assessment:**  
Incident #193653 was a **training exercise** within the LAW-Cyber-Range environment, confirmed through five independent indicators. The detection rule performed as intended, successfully identifying PowerShell-based web download activity. This investigation demonstrated:

- Effective use of PICERL incident response framework
- Command-line forensics capability (Event 4688 analysis)
- Systematic evidence collection and correlation
- Context-driven decision making
- Production-ready investigation methodology

**Status:** CLOSED - No remediation required  
**Recommendation:** Consider whitelisting EICAR downloads in training environments to reduce false positive rate

**Investigator Notes:**  
This incident provided valuable hands-on experience with HIGH severity alert investigation, reinforcing the critical importance of command-line logging and systematic investigation methodologies. The same approach would apply to production incidents, with adjusted containment urgency based on production vs training context.

---

**Report Prepared By:** Muhammad Talha Tabish  
**Date:** October 14, 2025  
**Review Status:** Self-documented for portfolio demonstration