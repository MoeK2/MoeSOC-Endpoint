# Sysmon: setup and how MoeSOC uses it

Sysmon (System Monitor) records process creation with hashes and parent process, network connections, DNS queries, file creation and registry changes in the `Microsoft-Windows-Sysmon/Operational` log. MoeSOC **reads** that log when it exists. MoeSOC never installs, updates, configures or uninstalls Sysmon, and never replaces an existing configuration.

## What the Health check shows

| Health | Meaning |
| --- | --- |
| **Available** | The Sysmon log is readable. The message names the variant and the service state, e.g. `standalone (Sysinternals); service Sysmon64 running` |
| **Limited** | The log exists but is empty, the service is stopped, or a Sysmon service exists without a readable log |
| **Unavailable — Not installed** | No Sysmon log on this computer: process-tree, network, DNS, file and registry visibility is not available |
| **Unavailable — Access denied** | Run MoeSOC as administrator to read it |

The variant is **inferred** from where the service binary lives (`C:\Windows\Sysmon64.exe` → standalone; `C:\Windows\System32\…` → built-in), and the Health message says so.

## Option A: built-in Windows Sysmon (Windows 11 / Windows Server 2025)

Microsoft added Sysmon as an optional Windows feature. It is **disabled by default**. Microsoft's instructions: enable the feature, then install the service with `sysmon -i`. If Sysinternals Sysmon is already installed, Microsoft says it must be uninstalled first. ([Windows Insider blog, build 26300.7733](https://blogs.windows.com/windows-insider/2026/02/03/announcing-windows-11-insider-preview-build-26300-7733-dev-channel))

```powershell
# Administrator PowerShell — your decision; MoeSOC does not run this
Get-WindowsOptionalFeature -Online -FeatureName Sysmon      # is the feature offered on this build?
Dism /Online /Enable-Feature /FeatureName:Sysmon
sysmon -i <your-config.xml>
```

Availability depends on the Windows build and servicing level; check with `Get-WindowsOptionalFeature` first. Reports describe the built-in version as writing to the same `Microsoft-Windows-Sysmon/Operational` log and accepting the same XML configuration format ([example write-up](https://www.turbogeek.co.uk/?p=9467)); verify on your build.

## Option B: standalone Sysinternals Sysmon

1. Download Sysmon from Microsoft Sysinternals (`learn.microsoft.com/sysinternals/downloads/sysmon`) and check the signature.
2. Choose a configuration. A config controls volume and privacy; running without one logs very little. Well-known community starting points are the SwiftOnSecurity `sysmon-config` and Olaf Hartong's `sysmon-modular`. Read and adapt them; do not paste blindly.
3. Install (administrator): `sysmon64 -accepteula -i sysmonconfig.xml`
4. Later changes: `sysmon64 -c sysmonconfig.xml` (updates the config only).

**If Sysmon is already installed, keep its configuration.** Check it with `sysmon64 -c` (prints the active config). MoeSOC works with whatever events your config produces.

## Events MoeSOC uses (roadmap order)

| Sysmon ID | Meaning | MoeSOC use |
| --- | --- | --- |
| 1 | Process created (image, command line, hashes, parent, user, logon ID, integrity) | Process tree, pivots, correlation with logons |
| 3 | Network connection | Context for processes and logons (no alert per connection) |
| 11 | File created | Timeline context |
| 13 | Registry value set | Timeline context |
| 22 | DNS query | Process-to-DNS correlation |

## How MoeSOC collects Sysmon (implemented)

- **Events 3, 11, 13 and 22** are collected as context (Phases 14–17): they never create findings on their own. Network connections keep both endpoints, protocol and direction (`initiated`); file creation keeps the target file; registry value sets keep the key and the written value (stored locally, never shown in summaries because values can contain secrets); DNS queries keep the name, status, raw results and the resolved IP addresses (for process → DNS → connection correlation). The IP filter matches connection destinations too.
- **Event 1 (process create)** is collected with the same incremental, gap-aware logic as the Security log (see collection.md), with its own position and budget per event family (`sysmon_process`, …) so noisy families cannot crowd out others.
- **Normalized:** user (`DOMAIN\user` from the `User` field — the event's System UserID is the Sysmon service, not the user), logon ID in the Security log's spelling (`0x5a3f21`, so a process joins its 4624 logon session), process and parent GUID, PID, image, command line, integrity level, hashes as configured, and in `details`: current directory, parent command line, parent user, original file name, company, description, product, file version, terminal session, rule name.
- **Process GUIDs** (schema v5 columns, indexed) identify a process even after its PID is reused; the process tree uses them.
- **Missing Sysmon** is recorded in the scan (`sysmon: not installed`), never treated as a failure. An unreadable Sysmon log is a note on the scan, and the Security collection still completes.
- **Live monitoring** subscribes to the Security log only; Sysmon events are collected by every scan and by the catch-up that precedes each live session.
- Sysmon events never feed the Security authentication rules.

## Process tree (implemented)

Select a process event (Sysmon 1 or Security 4688) in **Events** and choose **Process tree**, or run `python -m moesoc.cli process-tree <Event #>`. The tree shows ancestors and descendants with user, PID, start time and integrity; the selected process is highlighted, and pivots (this process, this user, around this time, open raw event) are one click away.

| Link | Source | Strength |
| --- | --- | --- |
| ProcessGuid | Sysmon `ProcessGuid` / `ParentProcessGuid` | Exact, survives PID reuse |
| PID match | Security 4688 `ProcessId` / `NewProcessId`: the most recent process with that PID that started before the child, on the same computer | Weaker (labelled) |
| parent not collected | The parent's own creation event is not stored; the node is built from the child's recorded parent fields | Information only |

A tree is evidence, not a verdict: nothing is labelled malicious because of its shape. Up to 300 processes and 25 ancestors are shown; cycles in inconsistent data are cut.

## Verify (read-only)

```powershell
Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational   # exists? how many records?
Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue   # which service, running?
```

Then open MoeSOC → Overview → Telemetry Health → **Sysmon**.
