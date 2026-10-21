
# Sysmon Overall Assessment

Summary assessment of five Sysmon events from a Windows endpoint, with the threat hunting focus for each.

## Overall Assessment

All five events look like **benign, baseline system and user activity**. No Indicators of Compromise (IoCs) or malicious patterns were detected in these isolated log snippets.

## Summary

| # | Event ID | Event | Process | Status | Risk |
|---|----------|-------|---------|--------|------|
| 1 | 1 | Process Creation | `consent.exe` | Legitimate / Expected | Low |
| 2 | 3 | Network Connection | `Perplexity.exe` | Legitimate / Low Risk | Low |
| 3 | 11 | File Created | `msiexec.exe` | Legitimate Administrative Activity | Low |
| 4 | 13 | Registry Value Set | `svchost.exe` | Normal System Telemetry | Low |
| 5 | 22 | DNS Query | `svchost.exe` | Legitimate Domain Lookup | Low |

---

## Detailed Analysis by Event

### 1. Event ID 1: Process Creation (`consent.exe`)

**Activity:** `svchost.exe` (Appinfo service) spawned `C:\Windows\System32\consent.exe` with command line arguments referencing process handles (`consent.exe 7192 426 0000011E4E88C950`).

**Context:** `consent.exe` is the standard Windows User Account Control (UAC) prompt interface. The Application Information (`Appinfo`) service launches it whenever an application requests administrative privilege elevation.

**Threat hunting focus**
- **Status:** Legitimate / Expected
- **What to hunt for elsewhere:**
  - Identify which process requested elevation, using other activity around `09:51:25` UTC on 2026-10-16.
  - Look for UAC bypass techniques, where privilege escalation happens *without* invoking `consent.exe`. For Example: auto-elevating system binaries, registry keys, or COM interfaces, DLL Hijacking, Schedule Task Abuse.
  - Look for anomalous parents spawning `consent.exe` other than `svchost.exe` running Appinfo.
---

### 2. Event ID 3: Network Connection (`Perplexity.exe`)

**Activity:** `Perplexity.exe`, running from `C:\Users\MK\AppData\Local\Programs\Perplexity\`, opened an outbound TCP connection to `104.18.27.48` on port 443 (HTTPS).

**Context:** This looks like standard outbound API/web traffic for the Perplexity desktop client. The destination IP is in Cloudflare's address space.

**Threat hunting focus**
- **Status:** Legitimate / Low Risk
- **What to hunt for elsewhere:**
  - Binaries running from `AppData\Local\` are common targets for user-space malware and unauthorized software installs.
  - Check the executable's digital signature and SHA-256 hash against known baseline software inventories to confirm it is signed by the vendor.
  - Confirm the destination hostname through the matching DNS query. A Cloudflare IP alone doesn't identify the service.

---

### 3. Event ID 11: File Created (`msiexec.exe`)

**Activity:** `msiexec.exe`, running as `NT AUTHORITY\SYSTEM`, wrote `System.Reflection.Primitives.dll` to `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\10.0.13\`.

**Context:** Standard file extraction during a .NET runtime installation or patch managed by Windows Installer.

**Threat hunting focus**
- **Status:** Legitimate Administrative Activity
- **What to hunt for elsewhere:**
  - Threat actors often abuse `msiexec.exe` to run remote payloads (for example, `msiexec.exe /q /i http://...`).
  - Confirm `msiexec` was started by a legitimate installer package, not an unverified download in a temp directory.
  - File creation does not prove the DLL was loaded. Use Sysmon Event ID 7 if image-load logging is enabled.

---

### 4. Event ID 13: Registry Value Set (`svchost.exe`, Inventory Telemetry)

**Activity:** `svchost.exe` wrote `Publisher = Microsoft Corporation` under `\Root\InventoryApplication\...`.

**Context:** This is the built-in Windows Compatibility Appraiser / Application Inventory recording installed software metadata for system maintenance and telemetry.

**Threat hunting focus**
- **Status:** Normal System Telemetry
- **What to hunt for elsewhere:** Standard background behavior. No hunting anomaly detected here.

---

### 5. Event ID 22: DNS Query (`cdn.onenote.net`)

**Activity:** `svchost.exe` resolved `cdn.onenote.net` through the CNAME chain `cdn.onenote.net.edgekey.net` and `e1553.dspg.akamaiedge.net` to the Akamai CDN IP `23.50.12.60`. The query completed successfully (status `0`).

**Context:** A standard lookup made when Microsoft OneNote or Office synchronizes assets or content over the network.

**Threat hunting focus**
- **Status:** Legitimate Domain Lookup
- **What to hunt for elsewhere:**
  - Monitor DNS for domain generation algorithms (DGA), typosquatting, and high-entropy domains used for command and control (C2).
  - `cdn.onenote.net` is a standard, verified Microsoft asset and is not itself a concern.

---

## Suggested Follow-Up Checks

| Check | Applies to |
|-------|-----------|
| Verify Authenticode signature and SHA-256 hash | `consent.exe`, `Perplexity.exe`, the .NET DLL |
| Identify the elevation-requesting process via the process tree and `ProcessGuid` | Event 1 |
| Review the matching DNS query for the `104.18.27.48` connection | Event 3 |
| Review Windows Installer logs around 05:06 UTC | Event 11 |
| Check for follow-on process launches from temp or user-writable paths | Events 1, 11 |
| Review other Event ID 3 records from `Perplexity.exe` for unusual destinations or ports | Event 3 |

## Timeline

```
2026-10-16 09:51:25  consent.exe launched by Appinfo (UAC prompt)
2026-10-19 05:03:13  DNS: cdn.onenote.net resolved
2026-10-19 05:06:26  Registry: InventoryApplication Publisher value set
2026-10-19 05:06:34  File created: System.Reflection.Primitives.dll (msiexec.exe)
2026-10-19 05:07:47  Network: Perplexity.exe -> 104.18.27.48:443
```
