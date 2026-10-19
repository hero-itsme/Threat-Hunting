# Windows Threat Hunting with Sysmon, Python and Event Viewer

## 1. Overview

This project focuses on using **Sysmon (System Monitor)** to perform threat hunting on Windows systems. Sysmon records detailed system activity that can help investigate suspicious processes, network connections, file operations, registry modifications, and potential defense evasion techniques.

The objective is to learn how to identify suspicious behavior, correlate multiple events, distinguish malicious activity from legitimate administrative actions, and document investigation findings.

This project is part of my hands-on journey into **Threat Hunting, Endpoint Detection and Response (EDR), and Windows Security Monitoring**.

## 2. Objectives

- Understand important Sysmon event categories and their security relevance.
- Investigate suspicious process creation and command-line activity.
- Identify unusual parent-child process relationships.
- Monitor network connections and DNS queries.
- Investigate suspicious file creation, deletion, and registry modifications.
- Correlate multiple events to reconstruct potential attack activity.
- Distinguish suspicious behavior from legitimate administrative activity.
- Document findings with supporting evidence and recommended actions.

## 3. What Is Sysmon?

Sysmon is a Windows system service and device driver from Microsoft Sysinternals that logs detailed system activity to the Windows Event Log.

Unlike traditional Windows logging, Sysmon provides additional telemetry that can help analysts investigate how processes were created, which network connections they initiated, what files they created, and how they interacted with other system components.

Sysmon is a **telemetry collection tool, not a complete threat detection solution**. Analysts must interpret its events using context, correlation, threat intelligence, and behavioral analysis.

Official documentation: [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## 4. Important Sysmon Event IDs for Threat Hunting

The following events are useful starting points for a Windows threat-hunting investigation.

| Event ID | Category | What to investigate |
|---|---|---|
| 1 | Process Create | Suspicious command lines, unusual parent-child relationships, unexpected execution paths |
| 3 | Network Connection | Unexpected outbound connections, unusual destination IPs or ports, suspicious process-to-network activity |
| 7 | Image Loaded | Unusual DLL loading, unexpected module paths, potential DLL hijacking indicators |
| 8 | CreateRemoteThread | Possible process injection activity |
| 10 | Process Access | Unusual access to sensitive processes, possible credential theft or process manipulation |
| 11 | File Create | Executables or scripts created in temporary directories, downloads folders, or startup locations |
| 12 | Registry Object Create/Delete | Registry key creation or deletion |
| 13 | Registry Value Set | Changes to registry values, including potential persistence settings |
| 14 | Registry Key/Value Rename | Registry key or value renaming activity |
| 15 | File Create Stream Hash | File creation involving named streams, including potential alternate data stream activity |
| 22 | DNS Query | Unexpected domain lookups, suspicious domains, unusual DNS activity |
| 23 | File Delete | File deletion activity, including possible cleanup after execution |
| 25 | Process Tampering | Possible process image manipulation |
| 26 | File Delete Detected | File deletion detection without the archival behavior associated with Event ID 23 |

## 5. How to Access Sysmon Logs

Sysmon events are stored in the Windows Event Log.

### Event Viewer

1. Open the Windows Start menu.
2. Search for `Event Viewer`.
3. Navigate to:

   `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`

4. Open the log.
5. Filter the current log by the Event IDs you want to investigate.
6. Review the event details, including timestamps, process identifiers, executable paths, command lines, and network information when available.

## 6. Practical Threat-Hunting Methodology

### Step 1: Establish a Baseline

Understand normal activity on the system before deciding that an event is suspicious.

Review:

- Common Windows processes and their expected locations.
- Typical parent-child process relationships.
- Legitimate administrative scripts and scheduled tasks.
- Normal network destinations and DNS queries.
- Common software installation and update activity.

### Step 2: Identify Anomalies

Look for deviations from expected behavior, such as:

- PowerShell executing an unusually obfuscated command.
- Office applications spawning command interpreters unexpectedly.
- Executables running from user-writable temporary directories.
- A process connecting to an unfamiliar external IP address.
- Unexpected registry modifications associated with startup execution.
- Unusual access to sensitive processes.

A single anomaly does not prove malicious activity. Validate each finding with supporting evidence.

### Step 3: Investigate the Process

Start with Sysmon Event ID 1.

Review the following fields where available:

- `UtcTime`: Time of process creation.
- `Image`: Executable path.
- `CommandLine`: Full command line.
- `ParentImage`: Parent process path.
- `ParentCommandLine`: Parent process command line.
- `ProcessId`: Process identifier.
- `ParentProcessId`: Parent process identifier.
- `User`: Account associated with the process.
- `Hashes`: File hashes, when configured and available.

Ask:

- Is the executable in an expected location?
- Is the parent process relationship normal?
- Does the command line have a legitimate explanation?
- Was the process launched by a user, scheduled task, service, or another application?
- Is there related activity before or after process creation?

### Step 4: Pivot to Related Events

Use process identifiers, timestamps, executable paths, file paths, and network details to search for related activity.

For example:

- **Event ID 1:** Identify the suspicious process.
- **Event ID 11:** Check for files created around the same time.
- **Event ID 3:** Check whether the process established network connections.
- **Event ID 22:** Examine DNS queries associated with the process.
- **Event ID 13:** Check for relevant registry value changes.

This sequence is an investigation guide, not a fixed attack sequence. Events may be missing, disabled, unrelated, or generated in a different order.

### Step 5: Assess and Document

Classify the activity as one of the following:

- **Benign:** Supported by evidence of legitimate activity.
- **Suspicious:** Anomalous behavior requiring further investigation.
- **Likely malicious:** Multiple corroborating indicators support a malicious explanation.
- **Inconclusive:** Available evidence is insufficient to reach a reliable conclusion.

Document the evidence and confidence level rather than relying on assumptions.

## 8. What to Look for During Process Creation Hunting

When analyzing Event ID 1, pay particular attention to:

### Suspicious-looking command lines

Examples of behaviors that deserve investigation:

- Encoded or heavily obfuscated PowerShell commands.
- Unexpected use of script interpreters.
- Commands that download and execute remote content.
- Execution of scripts from temporary or user-writable directories.
- Unusual combinations of command-line arguments.

These patterns also occur in legitimate administration, software deployment, and security testing.

### Unusual parent-child relationships

Examples worth reviewing:

- Microsoft Office applications spawning command interpreters.
- Browsers launching scripting engines unexpectedly.
- Script interpreters spawning additional interpreters.
- Unexpected system utilities launching from user applications.

Validate the executable paths, user context, command line, software behavior, and surrounding events.

### Process execution from unusual locations

Review executables running from:

- `%TEMP%`
- `%APPDATA%`
- `%LOCALAPPDATA%`
- Downloads directories
- Other user-writable locations

These locations are not inherently malicious. Determine whether the executable is expected, trusted, and consistent with normal system activity.

## 9. Common Threat-Hunting Mistakes

Avoid these mistakes when conducting investigations:

1. **Treating every unusual command as malicious.** Legitimate administrators frequently use PowerShell and other scripting tools.
2. **Analyzing Event ID 1 in isolation.** Process creation becomes more useful when correlated with other telemetry.
3. **Ignoring the parent process.** The process that initiated an action can provide important investigative context.
4. **Assuming every event category is enabled.** Verify the Sysmon configuration before interpreting missing events.
5. **Treating missing telemetry as proof of no activity.** Logging gaps, configuration limitations, and retention policies can affect visibility.
6. **Ignoring time zones.** Sysmon timestamps and displayed Event Viewer times may use different representations.
7. **Confusing an indicator with a conclusion.** A suspicious domain, process, or registry modification needs contextual validation.
8. **Failing to document benign explanations.** Recording why activity was considered legitimate improves future investigations and reduces false positives.

## 10. Conclusion

- **Classification:** Benign / Suspicious / Likely malicious / Inconclusive
- **Confidence:** Low / Medium / High
- **Recommended next steps:**
- **MITRE ATT&CK mapping, if supported by evidence:**

## 11. MITRE ATT&CK Mapping

Map observed behavior to MITRE ATT&CK only when the evidence supports the technique.

Potential areas to investigate include:

- **Command and Scripting Interpreter: PowerShell** — T1059.001
- **Windows Management Instrumentation** — T1047
- **Process Injection** — T1055
- **Boot or Logon Autostart Execution** — T1547
- **Ingress Tool Transfer** — T1105

Reference: [MITRE ATT&CK Enterprise](https://attack.mitre.org/)

These are examples of possible mappings, not conclusions that should automatically be assigned to the events listed in this project.

## 12. References

- [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Windows Event Viewer Documentation](https://learn.microsoft.com/en-us/shows/inside/event-viewer)
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/)
- [Sysinternals Utilities](https://learn.microsoft.com/en-us/sysinternals/)

---
