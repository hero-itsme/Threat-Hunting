1. Which Sysmon event categories should you analyze?
Here are the most useful Sysmon Event IDs for your Windows threat-hunting lab.
Event ID	Category	What to hunt for
1	Process Create	Suspicious command lines, unusual parent-child relationships
3	Network Connection	Unexpected outbound connections from a process
7	Image Loaded	Unusual DLL loading; can generate high event volume
8	CreateRemoteThread	Possible process injection activity
10	Process Access	Unusual access to another process, including possible credential theft behavior
11	File Create	Executables or scripts created in temporary or startup locations
12, 13, 14	Registry Events	Registry key/value creation, modification, or renaming
15	File Create Stream Hash	Alternate data streams and associated file creation activity
22	DNS Query	Suspicious domains queried by a process
23, 26	File Delete	File deletion activity, including potential cleanup
25	Process Tampering	Possible process image manipulation
These events are available only when the relevant Sysmon event collection is enabled and supported by your configuration. For example, network connections (Event ID 3) are not enabled by default in every Sysmon configuration. Event ID 7 can also generate substantial telemetry.
Official reference: Microsoft Sysmon documentation.
2. How to correlate events during a hunt
Imagine you're investigating a suspicious PowerShell process.
Event ID 1 — Process Create
PowerShell starts with an unusual command line


Event ID 11 — File Create
Check whether the process created a script or executable


Event ID 22 — DNS Query
Check whether the process queried an unexpected domain


Event ID 13 — Registry Value Set
Check for a related registry modification, including possible persistence


This is a hypothetical investigation path, not a mandatory sequence. The events might not occur, and their timestamps alone do not prove they are related.
