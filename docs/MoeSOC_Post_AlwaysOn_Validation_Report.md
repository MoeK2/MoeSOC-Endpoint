# MoeSOC Post-Always-On Validation Report

**Audit dates:** 2026-10-10 / 2026-10-11 (Windows runs on 2026-10-11).
**Scope:** validation only; **no product code was changed**. Audit tooling lives outside git (`audit\` on the test PC). Every audit-tooling mistake is labelled as such.
**Labels used:** TESTED — REAL WINDOWS ✅ · TESTED — AUTOMATED ✅ · TESTED — SYNTHETIC ⚠ · PARTIALLY TESTED ⚠ · NOT TESTED · BLOCKED BY ENVIRONMENT · BLOCKED BY USER INTERACTION · FAILED ❌

## Executive Summary

**Old MoeSOC (v1.0 scope: collection, 8 detections, 4 correlations, investigation, CLI, GUI):** no regressions were found.

- Full Windows suite: **610 passed / 1 skipped** (non-elevated) and **611 passed** (elevated, twice).
- Linux: **609 passed / 2 skipped**.
- Ruff clean, **GUI smoke 76/76**.
- The A-1 / A-2 / A-3 audit probes still give the corrected results.

**Always-On architecture:** the code exists and the separation is correct.

- The sensor loads no Qt; the tray loads neither Qt nor the detection engine (import check); there is one pipeline (the sensor drives the existing `ScanService` / `LiveMonitor`).
- On real Windows the first installed build **ran unattended for about 19 hours**. It received **146 live batches (218 events) without any scan**, with **0 duplicate rows** and `quick_check: ok`.
- Measured idle: **0.0 % average CPU, 36.6 MB working set, flat**.

The audit also found **two HIGH and two MEDIUM real-Windows defects** in the Always-On *operational* layer (install/update, health, deep link):

1. **B-1 HIGH:** re-running `install` (the documented update path) destroys the access rights on the sensor's existing files. The service then shows *Running* but cannot open its database, so **monitoring silently stops**.
2. **B-2 HIGH:** a failed update (files locked by the auto-started tray) stops the sensor and leaves it stopped, with a partly copied program folder.
3. **B-3 MEDIUM:** the "open this finding" hand-over opened **a new console each time** instead of reusing the open one.
4. **B-4 MEDIUM:** while the database cannot be opened, the sensor's IPC never starts, so nobody can see why it is not working.

**As left at the end of the audit, the sensor on the test PC is not monitoring** (B-1). A one-step repair script is prepared and waits for a UAC approval.

Not tested on real hardware: the real toast and its click, the reboot, sleep/resume, the current build's IPC fix, and the real console RAM.

**Verdict: PARTIAL.** The detection product is solid. The always-on layer is architecturally right and idles very lightly, but it is **not yet safe for unattended daily use** until B-1 and B-2 are fixed.

## Exact Version Audited

| Item | Value |
|---|---|
| Branch / commit | `master` @ `7c845f4` (docs-only commits after `d48a4bb`, the last code change) |
| Version | 1.0.0 (`moesoc/__init__.py`) |
| Tags | `v1.0.0` (on `62ca492`, local) |
| Remotes | none |
| Working tree | clean |
| Tracked files / Python files / test files | 266 / 152 / 49 |
| Collected tests | 611 (Windows; 2 are Windows-only) |
| Schema | v9 (9 migrations) |
| Build artifacts on the PC | `dist\MoeSOC\` with `MoeSOC.exe`, `MoeSOCSensor.exe`, `MoeSOCTray.exe` (built 2026-10-10 17:31 from `d48a4bb` code, console self-test PASSED); installed copy in `C:\Program Files\MoeSOC Endpoint` |
| Installer | **none** (Inno Setup not installed) |

## Repository State

| Check | Result |
|---|---|
| Uncommitted changes | none |
| Tracked databases, logs, `.evtx`, output files, `.env` | none (`git ls-files` pattern search) |
| Secrets / passwords / tokens | none found (pattern search) |
| Real host name, user name, e-mail, real SIDs | none in tracked text. Fixtures use the synthetic `alice` and `S-1-5-21-7777777777-…`. |
| Machine-specific absolute paths | only synthetic `C:\Users\alice\…` in test fixtures |
| Screenshots | 24 tracked PNGs; the earlier audit reviewed and redacted them. **Git history** still contains older screenshots with the real computer name (known, A-M6). |
| Static: `shell=True`, HTTP server, raw sockets, `urllib`/`requests` | none. The only "socket" is `QLocalSocket` (a local named pipe). |
| `subprocess` uses | 3: `icacls` (full path, list args), tray → console (fixed path, list args), launcher (fixed). No event content reaches a command line. |
| Threads / queues | sensor: monitor thread + 4 IPC threads; tray: 1 poller thread + `Queue(maxsize=100)`; hub `deque(maxlen=50)`. All bounded. |
| Tray import closure | no `moesoc.engine`, no PySide6 (checked) |
| Sensor import closure | no PySide6 |

## What MoeSOC Contains Today

### Master feature matrix

| Feature | Exists | Automated | Synthetic | Real Windows | Status | Notes |
|---|---|---|---|---|---|---|
| Security collector (watermarked, groups core/process) | ✓ | ✓ | ✓ | ✓ | TESTED — REAL WINDOWS ✅ | v1.0 audit: 1,269 records, 0 parse failures; today: 664 events in the sensor DB, 0 duplicates |
| Sysmon collector + parser | ✓ | ✓ | ✓ | – | TESTED — SYNTHETIC ⚠ | Sysmon not installed on the PC (correctly reported "not installed") |
| PowerShell 4104 collector + parser | ✓ | ✓ | ✓ | records seen | PARTIALLY TESTED ⚠ | real 4104 parsed (v1.0 audit); channel live in the sensor |
| Defender collector + parser | ✓ | ✓ | ✓ | channel live | PARTIALLY TESTED ⚠ | 0 real detection events on the PC |
| Normalization / `parse_any_xml` dispatch | ✓ | ✓ | ✓ | ✓ | TESTED — REAL WINDOWS ✅ | |
| Identity resolution (A-2, A-11) | ✓ | ✓ (42) | ✓ | – | TESTED — AUTOMATED ✅ | probe B/C still corrected |
| Incremental collection, watermarks, catch-up | ✓ | ✓ | ✓ | ✓ | TESTED — REAL WINDOWS ✅ | sensor restarts caught up only new records |
| Duplicate prevention | ✓ | ✓ | – | ✓ | TESTED — REAL WINDOWS ✅ | `duplicates (channel, record): 0` after 19 h |
| Detection engine (8 DET) | ✓ | ✓ | ✓ | DET-001, DET-005 | see Detection Rules | |
| Correlation engine (4 COR) | ✓ | ✓ | ✓ | COR-001 | see Correlation Rules | |
| Campaign continuity (A-1) | ✓ | ✓ (9) | ✓ | – | TESTED — AUTOMATED ✅ | probe D: 1 finding |
| Risk engine + explanation, A-7/A-8 | ✓ | ✓ (11) | ✓ | – | TESTED — AUTOMATED ✅ | |
| Evidence verification (A-3) | ✓ | ✓ (23) | ✓ | Security only | PARTIALLY TESTED ⚠ | probe: all sources "verified" |
| Retention (preview/apply) | ✓ | ✓ (10) | ✓ | – | TESTED — AUTOMATED ✅ | sensor runs it only if a period was chosen |
| Migrations v1→v9, newer DB refused | ✓ | ✓ | – | v8→v9 | TESTED — REAL WINDOWS ✅ | sensor DB at schema 9 |
| Triage / notes / history / verdict | ✓ | ✓ | ✓ | earlier phases | TESTED — AUTOMATED ✅ | |
| Search / pivots / timeline / process tree / story | ✓ | ✓ | ✓ | GUI smoke | TESTED — AUTOMATED ✅ | |
| HTML report + redaction + XSS escaping | ✓ | ✓ (10) | ✓ | – | TESTED — AUTOMATED ✅ | |
| Tuning: enable/disable, parameters, suppressions, expiry, audit log | ✓ | ✓ (22) | ✓ | – | TESTED — AUTOMATED ✅ | |
| GUI, 9 pages | ✓ | smoke 76 | ✓ | ✓ | TESTED — REAL WINDOWS ✅ | offscreen real window |
| CLI, 16 commands | ✓ | ✓ | ✓ | health/scan/events/detections | TESTED — REAL WINDOWS ✅ | |
| Launcher, single instance, UAC | ✓ | ✓ (24) | – | earlier phases | TESTED — AUTOMATED ✅ | |
| Packaged `MoeSOC.exe` self-test | ✓ | – | – | ✓ | TESTED — REAL WINDOWS ✅ | build 2026-10-10 |
| SensorCore | ✓ | ✓ (15) | ✓ | ✓ | TESTED — REAL WINDOWS ✅ | 19 h unattended run |
| Windows service host | ✓ | – | – | ✓ | TESTED — REAL WINDOWS ✅ | start/stop/restart, delayed auto |
| Service install / update | ✓ | – | – | ✗ | **FAILED ❌** | B-1, B-2 |
| Service uninstall | ✓ | – | – | – | NOT TESTED | |
| Multi-channel live subscription | ✓ | ✓ (13+) | ✓ | ✓ | TESTED — REAL WINDOWS ✅ | Security, PowerShell, Defender live |
| Live delivery of a deliberately generated event | ✓ | ✓ | – | ✗ | FAILED ❌ (consequence of B-2, not of delivery) | see Live Monitoring |
| Local IPC (named pipe) | ✓ | ✓ (23) | – | partial | PARTIALLY TESTED ⚠ | hostile inputs ✓ on the old build; the current build's multi-client fix is unverified |
| Notification engine + dedup + prefs | ✓ | ✓ (20) | ✓ | – | TESTED — AUTOMATED ✅ | |
| Real toast and click | ✓ | ✓ (controller) | – | – | BLOCKED BY USER INTERACTION | |
| Tray | ✓ | ✓ (12) | – | ran, 0 sockets, 33 MB | PARTIALLY TESTED ⚠ | menu/toast not visually checked |
| Deep link `--finding` | ✓ | ✓ (12) | – | ✗ | **FAILED ❌** | B-3 |
| Startup: sensor auto (delayed) | ✓ | – | – | config ✓ | PARTIALLY TESTED ⚠ | no reboot done |
| Startup: tray at sign-in | ✓ | – | – | ✓ | TESTED — REAL WINDOWS ✅ | tray was running after today's sign-in |
| Service recovery (failure actions) | ✓ | ✓ (back-off) | – | config ✓ | PARTIALLY TESTED ⚠ | |
| Health model | ✓ | ✓ | – | ✓ / ✗ | PARTIALLY TESTED ⚠ | truthful when up; silent when the DB is down (B-4) |
| Sensor / tray logs | ✓ | – | – | ✓ | TESTED — REAL WINDOWS ✅ | no host name, user name or SIDs |
| Sleep / resume | ✓ | ✓ | – | indirect | PARTIALLY TESTED ⚠ | see Sleep / Resume |

Total components identified: **54 rows** (counted from the matrix and inventories in this report).

## Architecture

There are three processes; this was verified in the code and on real Windows.

- **Sensor** (`MoeSOCSensor.exe`, a Windows service): `SensorCore` drives the existing `ScanService` and `LiveMonitor`. Its notification decisions reach the tray over IPC.
- **Tray** (`MoeSOCTray.exe`): pywin32 only.
- **Console** (`MoeSOC.exe`): the unchanged GUI plus the deep link. It opens the sensor's database when the sensor is installed.

**One pipeline: verified.** `moesoc/sensor/core.py` builds `ScanService(...)` and `LiveMonitor(...)` and contains no rule logic. No detection code exists in `tray/` or `gui/console_link.py`.

## Sensor

| Check | Result | Status |
|---|---|---|
| Start → DB → catch-up → subscriptions → idle | log and status: ON in about 1 s; Sysmon "not installed", others "live" | TESTED — REAL WINDOWS ✅ |
| 19 h unattended run (2026-10-10 14:13 → 2026-10-11 12:08) | 146 live batches, 218 events stored, parse failures 0 | TESTED — REAL WINDOWS ✅ |
| Event ingest → store → detect (no findings on this PC: only routine logons) | 0 findings, which is correct for benign activity | TESTED — REAL WINDOWS ✅ (negative) |
| Detection → notification decision | automated (`test_live_events_become_one_notification`) | TESTED — AUTOMATED ✅ |
| Stop / restart | clean, no duplicates (2026-10-10); stop today took ≤ 35 s | TESTED — REAL WINDOWS ✅ |

## Windows Service

| Property | Value (`sc qc`, `sc qprivs`, `sc qfailure`) | Status |
|---|---|---|
| Name / display | `MoeSOCSensor` / MoeSOC Endpoint Sensor | ✅ |
| Binary | `"C:\Program Files\MoeSOC Endpoint\MoeSOCSensor.exe"` (quoted) | ✅ |
| Start type | `AUTO_START (DELAYED)` | ✅ |
| Account | `NT SERVICE\MoeSOCSensor`, member of Event Log Readers | ✅ |
| Privileges | `SeChangeNotifyPrivilege` only | ✅ |
| Recovery | restart after 60 s, twice per day | ✅ (configured, not provoked) |
| Data / logs | `C:\ProgramData\MoeSOC\data`, `\logs` | ✅ |
| Working directory | System32 (service default); the code uses absolute paths | ✅ |
| Install (first) | worked (2026-10-10) | TESTED — REAL WINDOWS ✅ |
| Install again = update | **FAILED ❌** (B-1, B-2) | |
| Uninstall | NOT TESTED | |
| Sensor survives console closed / tray closed | not measurable today: the sensor was down because of B-2/B-1 | BLOCKED BY USER INTERACTION (repair needs UAC) |
| Exe started without arguments | prints usage, exit 2 (no traceback) | TESTED — REAL WINDOWS ✅ |

## Tray

| Check | Result | Status |
|---|---|---|
| Runs in the user session, not elevated | started at sign-in (HKCU Run) and via Explorer | TESTED — REAL WINDOWS ✅ |
| Resources | 31–33 MB working set, 19 MB private, 2–5 threads, ~175 handles, **0.000 % CPU** over 3 + 2 min | TESTED — REAL WINDOWS ✅ |
| Network sockets | 0 | TESTED — REAL WINDOWS ✅ |
| Detection logic in the tray | none (import closure) | ✅ |
| Exit Tray never stops the sensor | code: `EXIT` → `DestroyWindow` only; automated test | TESTED — AUTOMATED ✅ |
| Shows status / reconnects / opens console / recent finding | controller tests | TESTED — AUTOMATED ✅; real visual check NOT TESTED |
| Sensor independent of the tray | by design (no dependency); not re-measured today | PARTIALLY TESTED ⚠ |

The tray locks its files in Program Files, which makes an update fail; that is B-2.

## Console

- **Opens the sensor DB non-elevated:** TESTED — REAL WINDOWS ✅. Three consoles started with `admin=False` and the Database showed as "Available" (read-only fallback).
- **GUI smoke:** 76/76, non-elevated, real window offscreen. TESTED — REAL WINDOWS ✅.
- **Deep link:** **FAILED ❌** (B-3).
- **Console RAM:** **NOT TESTED**. The audit measured the venv launcher stub (5.9 MB), not the GUI interpreter (audit-tooling error, fixed but not re-run).

## IPC

- **Technology:** Windows named pipe `\\.\pipe\MoeSOC.Sensor`, message mode, JSON, ≤ 16 KB per message.
- **Commands (complete list):** `hello`, `status`, `wait_notifications`, `scan`, `get_prefs`, `set_prefs`.

| Test (real pipe, installed build, admin client) | Result |
|---|---|
| Authorized `hello` | ok |
| Malformed bytes | `{"ok":false,"error":"not a JSON message"}` |
| Unknown command (`run_powershell`) | `unknown command` |
| Oversized (20 KB) | `message too large` |
| Invalid preferences | `invalid preferences: medium must be true or false` |
| 3 concurrent long-poll clients + status | **2 of 3 refused (winerror 121), status refused** in the installed build. This is the known bug fixed in `d48a4bb`; the fixed build is not yet verified on real Windows. |
| Service unavailable | the client reports `sensor not reachable (winerror=2)` cleanly |

Automated: 23 tests (`test_sensor_ipc.py`), including multiple clients, a restart resync and internal errors. TESTED — AUTOMATED ✅.

**Can an unprivileged process make the sensor execute something? NO.**

- The dispatcher has no code path that runs a command, opens a file by name, touches the registry or a process, or stops the service.
- `scan` only triggers the same incremental catch-up, rate-limited to one per minute.
- Preferences are type- and range-checked.

The pipe access list is SYSTEM, Administrators and the service account full; INTERACTIVE read/write without create-instance; NETWORK denied; remote clients rejected (code review; not inspected with a tool on the live pipe). The worst an unprivileged local user can do is pause notifications for at most 24 h, request catch-ups, or hold the pipe instances to delay their own tray: local nuisance only.

## Database

| Check (real sensor DB) | Result |
|---|---|
| Journal mode | WAL |
| `busy_timeout` | 10 s (code) |
| `PRAGMA quick_check` | ok (twice) |
| Schema | 9 |
| Duplicate (channel, record) rows | 0 |
| Notification state rows | 0 (no notifiable finding occurred) |
| Concurrency | automated: 1 writer + 2 readers, then `integrity_check` ok (TESTED — AUTOMATED ✅). Real: the console read the DB while the sensor wrote (2026-10-11), no lock errors in the console log. |

## Telemetry Sources

| | Security | Sysmon | PowerShell | Defender |
|---|---|---|---|---|
| Channel | Security | Microsoft-Windows-Sysmon/Operational | Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-Windows Defender/Operational |
| Event IDs | 4624, 4625, 4634/4647 family, 4672, 4688, 4720, 4732, 1102 (`SUPPORTED_EVENT_IDS`) | 1, 3, 11, 13, … (`SYSMON_GROUPS`) | 4104 | 1116, 1117, … (`DEFENDER_GROUPS`) |
| Collector / parser / storage | ✓ / ✓ / ✓ | ✓ / ✓ / ✓ | ✓ / ✓ / ✓ | ✓ / ✓ / ✓ |
| Live in the sensor | **yes (real)** | not installed | **yes (real)** | **yes (real)** |
| Catch-up | yes | yes | yes | yes |
| Rules | DET-001…006, COR-001…003 | COR-003, COR-004 | DET-007 | DET-008, COR-003/004 |
| Real records seen | yes | no | yes (4104) | channel readable, 0 detections |
| Real positive | DET-001, DET-005, COR-001 (earlier phases) | no | no | no |

## Detection Rules

| Rule | Name | Source | Logic summary | MITRE | Sev / Conf | Real positive | Synthetic | Automated | Current |
|---|---|---|---|---|---|---|---|---|---|
| DET-001 | Multiple Failed Logins | Security 4625 | ≥ 5 failures for one resolved identity in the window | T1110 | MEDIUM / MEDIUM | ✅ (2026-10-07) | ✅ | ✅ | PASS |
| DET-002 | Password Spray Behavior | 4625 | one source, many account candidates | T1110.003 | MEDIUM / MEDIUM | – | ✅ | ✅ (15) | PASS |
| DET-003 | Security Log Cleared | 1102 | log cleared | T1070.001 | HIGH / HIGH | – | ✅ | ✅ (10) | PASS |
| DET-004 | Low-and-Slow Guessing | 4625 | sparse failures over hours, per identity and per source | T1110, T1110.001 | MEDIUM / LOW | – | ✅ | ✅ (20) | PASS |
| DET-005 | New User Account | 4720 | account created (context raises severity) | T1136.001 | LOW / HIGH | ✅ | ✅ | ✅ | PASS |
| DET-006 | Privileged Group Member Added | 4732 | member added to admin-equivalent group | T1098.007 | HIGH / HIGH | – (real 4732 parsed) | ✅ | ✅ | PASS |
| DET-007 | Suspicious PowerShell | 4104 | indicator score ≥ threshold | T1059.001 | MEDIUM / MEDIUM | – (41 real 4104, 0 FP) | ✅ | ✅ (18) | PASS |
| DET-008 | Microsoft Defender Detection | Defender 1116/1117 | Defender's own verdict | none (by design) | MEDIUM / HIGH | – | ✅ | ✅ (15) | PASS |

## Correlation Rules

| Rule | Name | Sources | Logic | MITRE | Sev / Conf | Real | Synthetic | Automated | Current |
|---|---|---|---|---|---|---|---|---|---|
| COR-001 | Possible Account Compromise | 4625 → 4624 | ≥ 5 failures then a success, same identity | T1110, T1078 | HIGH / MEDIUM | ✅ | ✅ | ✅ (8) | PASS |
| COR-002 | New Account Added to Administrators | 4720 → 4732 | new account added to admins | T1136.001, T1098.007 | HIGH / HIGH | – | ✅ | ✅ | PASS |
| COR-003 | Suspicious Activity After Failed Logons | Security + Sysmon/Defender | COR-001 session followed by suspicious activity (logon-ID links) | T1110, T1078 | HIGH / HIGH | – | ✅ | ✅ | PASS |
| COR-004 | Defender Detection Traced to Source | Defender + Sysmon | detection → file creation → process chain | per finding (T1105) | MEDIUM / HIGH | – | ✅ | ✅ (14) | PASS |

The rules' unit tests live in `test_rules`, `test_password_spray`, `test_log_cleared`, `test_low_and_slow`, `test_account_management`, `test_powershell`, `test_defender`, `test_cor001_confidence` and `test_cross_source`. All passed on Linux and Windows.

## Risk Engine

The base score comes from severity, plus explainable modifiers (A-7/A-8 fixes intact; 11 tests). TESTED — AUTOMATED ✅.

## Investigation Features

The following all exist and pass their tests and the GUI smoke checks (TESTED — AUTOMATED ✅):

- detections, evidence, raw XML, timeline with padding, pivots;
- process tree, stories, triage statuses, notes, history, verdicts;
- MITRE display, risk explanation, confidence explanation.

**Phase 27, full synthetic investigation walk-through:** covered by the existing automated flow (`test_triage`, `test_story`, `test_process_tree`, GUI smoke) and the 2026-10-08 audit. It was not repeated by hand in this audit: **PARTIALLY TESTED ⚠**.

## Tuning and Suppression

The following all exist and pass their 22 tests: rule enable/disable, integer parameters, suppressions with expiry and hit counts, removal kept in history, and the audit log. TESTED — AUTOMATED ✅.

## Reporting

The HTML report has redaction and escapes hostile input (no `<script>` or event handlers); 10 tests. TESTED — AUTOMATED ✅.

New sensor, tray and console logs on the PC were scanned:

- 0 host-name hits;
- 0 user-name hits;
- 0 user SIDs;
- `sensor.json` holds only the version, time, account type and binary path.

## Existing CLI

There are 16 commands:

- `health`, `scan`, `import-xml`, `events`, `detections`, `show`, `triage`, `note`;
- `timeline`, `process-tree`, `retention`;
- `suppress add|list|remove`, `rules list|enable|disable|set`, `audit`;
- `report`, `story`, `verify-evidence`.

Real Windows (`verify_windows.bat`):

- `health`, `events`, `detections` ran;
- `scan` without elevation → "Access denied … Run MoeSOC with administrator privileges", exit 2 (no traceback).

A-5 (broken pipe) automated test passes. Every command has automated coverage (`test_validation_and_cli` and per-feature tests). **TESTED — AUTOMATED ✅, partially real.**

When the sensor is installed, the CLI defaults to the sensor's database, read-only for non-administrators.

## Existing GUI

There are 9 pages; the smoke test loads each one:

| Page | Purpose |
|---|---|
| Overview | health and counts |
| Detections | list, detail, triage |
| Timeline | events around a finding or a pivot |
| Events | search and filters |
| Process Tree | ancestors and children of a process |
| Story | linked findings narrative |
| Tuning | rules, parameters, suppressions, audit log |
| Reports | HTML report |
| Settings | retention and health |

**GUI smoke: 76/76** (TESTED — REAL WINDOWS ✅, offscreen). In sensor mode, Live shows "Sensor" and Scan asks the sensor; this is code-reviewed only (NOT TESTED visually).

## Incremental Collection

17 tests. Real: the sensor's restarts caught up only the records written while it was stopped (2 records on 2026-10-10). TESTED — REAL WINDOWS ✅.

## Live Monitoring

| Check | Result | Status |
|---|---|---|
| Automated: initial drain, existing records, new signal, multiple per signal, none, stop while waiting, restart, between catch-up and subscribe (with and without a saved position), duplicate after catch-up, malformed, out of order, bounded drain, multi-channel | all pass (`test_subscription_source` 13, `test_live_monitor` 12, `test_sensor_core` 15) | TESTED — AUTOMATED ✅ |
| Real: natural Windows events arrive without Scan Now | **146 batches / 218 events over 19 h**, 0 duplicates | **TESTED — REAL WINDOWS ✅** |
| Real: deliberately generated event (audit run 1) | Windows **did write** the 4625 (record 580815). MoeSOC stored **0**, because the sensor had just been **stopped by the failed update (B-2)**. | **FAILED ❌ (EVENT GENERATED, SENSOR NOT RUNNING)**: a consequence of B-2, not evidence against the delivery path |
| Real: generated event with the sensor running | not achieved: blocked by B-1 and then by the pending UAC repair | BLOCKED BY USER INTERACTION |

Note: six `net use` attempts produced only **one** 4625, so this method cannot produce a real DET-001 (≥ 5).

## Notification Engine

The notification engine passed its 20 automated tests (TESTED — AUTOMATED ✅):

- defaults: LOW never, MEDIUM off, HIGH and CRITICAL on;
- a growing finding notifies once;
- escalation notifies;
- a correlation on top notifies;
- the cooldown works;
- the state survives a restart;
- paused notifications are recorded silently;
- the first start does not flood;
- the text is factual;
- many findings at once become 2 toasts + 1 summary.

## Notification Deduplication

Persisted `notification_state` (schema v9). Covered by the automated tests above. Real: 0 rows, because no notifiable finding occurred. **The real toast is NOT TESTED.**

## Deep Linking

| Case | Result | Status |
|---|---|---|
| Argument and request validation, elevation hand-through, frozen decision logic | 12 tests pass | TESTED — AUTOMATED ✅ |
| Console open + `app.py --finding <id>` (development start, real Windows) | **a second full console started** (console log: 3 starts at 12:24, 12:26, 12:27; 4 then 6 interpreter processes) | **FAILED ❌ (B-3)** |
| Invalid ID | the console opened (no crash); the status message was not inspected | PARTIALLY TESTED ⚠ |
| Packaged `MoeSOC.exe --finding` | NOT TESTED (needs UAC) | |

Root cause: not yet determined. The send side (`send_to_running_console`) returned False. A diagnostic (`audit\link_diag.bat`) is prepared but was not run.

## Startup Behavior

| Component | Mechanism | Real |
|---|---|---|
| Sensor | SCM auto start (delayed) | configured ✅; reboot NOT TESTED |
| Tray | `HKCU\…\Run\MoeSOC Tray` = `"C:\Program Files\MoeSOC Endpoint\MoeSOCTray.exe"` | ✅: the tray was running after today's sign-in (it locked files during the update) |
| Console | not in start-up | ✅ (checked Run key) |

## Privilege Model

The sensor runs as the virtual account `NT SERVICE\MoeSOCSensor` (Event Log Readers, `SeChangeNotifyPrivilege` only). The console and tray do not need elevation to view: the console ran with `admin=False` and opened the sensor DB. Real ACLs:

| Path | Access |
|---|---|
| `C:\Program Files\MoeSOC Endpoint` (and `_internal`, `MoeSOCSensor.exe`) | Users RX; Administrators, SYSTEM and TrustedInstaller full (inherited Program Files ACL) ✅ |
| `C:\ProgramData\MoeSOC`, `\data` | protected; service M, Users RX, Administrators F, SYSTEM F ✅ |
| Files inside, **after a second `install`** | **no access for anyone** (B-1) ❌ |

## Security Boundary

- **Unprivileged local user → privileged sensor:** no command execution path; the IPC is bounded (see IPC).
- **Code path:** the service binary is in Program Files (admin-only). `install` refuses user-writable code folders unless explicitly overridden.
- **DLL search:** PyInstaller loads from its own `_internal` (admin-only); the service runs from Program Files. No user-writable search path was found.
- **Data:** users read-only; the sensor writes only in its protected folder.

No local privilege-escalation path created by MoeSOC was found **in the supported configuration** (Program Files install). The development option `--allow-insecure-code-path` (LocalSystem running code from a user folder) would be one, and it is documented as such.

## Network Behavior

**NETWORK LISTENERS: none** found:

- code: no TCP/UDP/HTTP listener; the only listeners are the named pipe and the console's `QLocalServer`, also a local pipe;
- `netstat -ano`: tray 0 sockets, console 0 sockets. The sensor process was not running at the netstat moments (B-2/B-1), so its own netstat row is NOT TESTED; its code has no socket use.

**OUTBOUND CONNECTIONS: none** (no network code; no update, telemetry or analytics calls).

## Privacy

There are no identifiers in the new logs or config, and no telemetry upload. The git history still contains old screenshots with the real computer name (A-M6, unchanged).

## Performance

| Process / Mode | Idle CPU (avg) | Peak CPU | RAM (working set / private) | Threads | Handles | Notes |
|---|---|---|---|---|---|---|
| Sensor only | **0.0 %** (< 0.0005 %, 10 min) | 0.02 % (5 s window) | **36.5 → 36.6 MB / 23.2 MB**, flat | NOT TESTED | NOT TESTED | 2026-10-10, real, packaged build `d48a4bb`-1 (pre IPC fix); 241 writes / 0.6 MB in 10 min |
| Tray | 0.000 % (3 min + 2 min) | 0.00 % (10 s) | 31–33 MB / 19 MB | 2–5 | ~175 | real, 2026-10-11 |
| Sensor + Tray | sum of the above | | ≈ 68 MB working set | | | the sensor was not running at that moment (B-2), so the combined run was not measured together |
| Sensor + Tray + Console | NOT TESTED | | | | | console GUI RAM not measured (audit-tooling error, see Console) |

### Event Burst Performance

All figures are SYNTHETIC ⚠ (Linux sandbox, 2 CPUs).

**Batch benchmark** (`scripts/benchmark.py`, same machine back to back):

| Events | parse | store | detect | DB |
|---|---|---|---|---|
| 1,000 | 0.07 s | 0.04 s | 0.09 s | 1.9 MB |
| 10,000 | 0.63 s | 0.35 s | 0.72 s | 17.6 MB |
| 50,000 | 3.33 s | 1.94 s | 4.74 s | 87.7 MB |
| 100,000 | 7.21 s | 4.18 s | 11.40 s | 176 MB |

Baseline comparison at 100k, run consecutively:

| Commit | parse | store | detect |
|---|---|---|---|
| v1.0 (`a01cc7d`) | 6.60 s | 4.42 s | 9.42 s |
| Now (`7c845f4`) | 7.31 s | 4.53 s | 10.94 s |

That is **+16 % detect and +12 % in total**, the cost of the A-1/A-2/A-11 correctness work. The Always-On work did not change the batch pipeline. The benchmark process's peak RSS was 581 MB (it holds all events in memory; the sensor does not).

**Live burst through the sensor pipeline** (`sensor_benchmark.py burst`, batches ≤ 500):

| Records | Time | CPU | Peak memory | Notifications | Notification latency after last batch |
|---|---|---|---|---|---|
| 1,000 | 0.58 s | 0.55 s | 37.7 MB | 1 (COR-001) | 0.46 s |
| 10,000 | **17.1 s** | 16.7 s | 88 MB | 1 (COR-001) | 1.40 s |

Finding **P-1 (LOW–MEDIUM):** every live batch re-runs detection over the whole rule lookback, so a burst of N events inside the window costs roughly O(N²/batch). 10k records in a few minutes keep one core busy for about 17 s. Memory stays bounded, and nothing is lost or duplicated.

## Idle CPU

Measured 0.0 % average for 10 min (real). Code review confirms the idle loop:

- the monitor blocks in `WaitForMultipleObjects` with a 1 s timeout, only to check the stop flag;
- the main thread wakes hourly for the maintenance clock;
- the IPC threads block on the pipe.

There is no log rescan and no database query while idle. The tray long-polls every 30 s.

## Memory

The sensor stayed flat over 10 min (36.5 → 36.6 MB) and the tray stayed flat. There is no unbounded queue. Each drain is ≤ 1,000 records and each batch ≤ 500; the pull model leaves the backlog in Windows' log.

## SQLite Concurrency

See Database. There were no lock or corruption errors; `quick_check` was ok on the real DB.

## Failure Recovery

| Scenario | Status |
|---|---|
| Sysmon absent → "not installed", others live | TESTED — REAL WINDOWS ✅ |
| Security subscription failure → reconnect with back-off | TESTED — AUTOMATED ✅ |
| Malformed XML / render failure | TESTED — AUTOMATED ✅ |
| Database temporarily locked at start → retried | TESTED — AUTOMATED ✅ |
| Database permanently inaccessible (real, B-1) | the service shows **Running**, but there is no IPC, no catch-up and no monitoring ❌ (B-4) |
| IPC unavailable → the tray shows Offline | TESTED — AUTOMATED ✅ |
| Tray killed → sensor unaffected | by design; real measurement invalid (the sensor was down) |
| Sensor restart → no duplicates, no repeated notifications | TESTED — AUTOMATED ✅ + REAL (no duplicates) |

## Sleep / Resume

- **Automated:** the power-resume path → catch-up + resubscribe (`test_resume_and_manual_scan_catch_up_again`). TESTED — AUTOMATED ✅.
- **Real, indirect:** the service started 2026-10-10 14:13 and recorded a fresh catch-up at 2026-10-11 08:29, after the night, then kept delivering live batches. This matches a resume/restart path working, but the sensor log was not readable to confirm the trigger. **PARTIALLY TESTED ⚠.**

## Packaging

| Artifact | State |
|---|---|
| `MoeSOC.exe` | built; `--self-test` PASSED (version, 12 rules, schema, icon, pywin32, 9 GUI pages) |
| `MoeSOCSensor.exe` | built; runs as the service; no-argument start prints usage |
| `MoeSOCTray.exe` | built; runs at sign-in |
| Shared `_internal` | one folder for all three |
| Installer | **does not exist** (Inno Setup not installed) |
| Update path | **broken** (B-1, B-2) |

## Tests

| Test Area | Passed | Failed | Skipped | Real/Synthetic | Notes |
|---|---|---|---|---|---|
| Linux full suite | 609 | 0 | 2 | automated | skips: 2 tests need Windows |
| Windows full suite, non-elevated (2026-10-11 12:05) | 610 | 0 | 1 | automated on real Windows | skip: Security-log scan needs elevation ("access correctly reported as denied") |
| Windows full suite, elevated (2026-10-11, twice) | 611 | 0 | 0 | automated on real Windows | |
| Ruff check / format | clean | – | – | – | Linux 176 files, Windows 175 files |
| GUI smoke | 76 | 0 | – | real window, offscreen | |
| Service / SensorCore tests | 15 | 0 | 0 | automated | `test_sensor_core.py` |
| IPC tests | 23 | 0 | 0 | automated | `test_sensor_ipc.py` |
| Notification tests | 20 | 0 | 0 | automated | `test_sensor_notifications.py` |
| Tray / deep-link tests | 26 | 0 | 0 | automated | `test_tray_and_deeplink.py` |
| Sensor storage / concurrency | 4 | 0 | 0 | automated | |
| Live-monitor + subscription | 25 | 0 | 0 | automated | |
| Migration / schema | 10 | 0 | 0 | automated | |
| A-1…A-11 regression tests | all pass | 0 | 0 | automated | probes: D = 1 finding, B/C corrected, A-3 all "verified" |
| Packaged self-test | PASSED | | | real | |
| Real IPC hostile-input checks | 5 | 0 | – | real | |
| Real IPC concurrency (installed build) | – | 1 | – | real | known, fixed in code, not deployed |
| Real install/update | – | 2 | – | real | B-1, B-2 |
| Real deep link | – | 1 | – | real | B-3 |

## Real Windows Tests

Completed:

- 19 h unattended sensor run with live delivery;
- service configuration;
- 10 min idle measurement (2026-10-10);
- tray resources and sockets;
- non-elevated console on the sensor DB;
- IPC hostile inputs;
- DB integrity and duplicates;
- full test suites, non-elevated and elevated;
- GUI smoke;
- packaged self-test;
- the no-argument sensor exe;
- log privacy.

## Synthetic Tests

Synthetic only:

- every DET/COR positive except DET-001, DET-005 and COR-001;
- burst and load benchmarks;
- notification logic;
- the Sysmon live path.

## Manual Tests Still Required

1. **Repair the sensor on the PC (needed now):** double-click `audit\post_audit_c.bat` and approve UAC. It takes ownership for Administrators, resets the file permissions under `C:\ProgramData\MoeSOC` to the folder's protected ACL (no deletion), restarts the sensor and completes the remaining audit measurements.
   - Alternative: `scripts\sensor_uninstall.bat`, which keeps the data.
2. **Real notification:**
   1. Lock the screen and type a wrong password 6 times (below the lockout threshold).
   2. Sign in. Expected: one toast.
   3. Click the toast. Expected: the console opens on the finding.
3. **Reboot:** the sensor runs before sign-in, and the tray appears after sign-in.
4. **Sleep / resume** once; then check the sensor log for "Resume from sleep".
5. **Uninstall:** run it, and confirm the data is kept.

## Regressions Found

None in the original MoeSOC functionality. All 8 detections, 4 correlations, investigation, CLI and GUI tests pass, and the A-1…A-11 fixes hold.

## Bugs Found

| ID | Severity | Bug | Evidence | Impact | Recommended fix |
|---|---|---|---|---|---|
| **B-1** | **HIGH** | A second `install` (update) runs `icacls /inheritance:r /grant:r … /T` and `/setowner /T` over the **existing** files. Files the service created (DB, sensor.log) end with no usable access entries, owned by the service account; even Administrators are denied. `install` then crashes writing `sensor.json` (PermissionError). | real, 2026-10-11 (twice) | The service shows **Running** but cannot open its DB → **no monitoring**, no IPC, and no visible error to the user | Set the protected ACL only on the root folder (no `/T`), let children inherit; or `/reset` the children. Never `/inheritance:r` on existing files. Add a test for re-install. |
| **B-2** | **HIGH** | `install` on an existing service stops it first, then the copy fails when the tray (autostarted) or a console has files open. The service is **left stopped**, and `copytree` leaves a partly updated folder. | real, 2026-10-11 run 1 | Monitoring stops after a failed update | Stop the tray/console first (or copy to a new folder and swap); restart the old service on any failure; copy atomically |
| **B-3** | MEDIUM | The deep-link hand-over failed on real Windows: each `app.py --finding` start opened a new console | real, 2026-10-11 | Notification clicks can stack duplicate consoles | Run `audit\link_diag.bat` while a console is open; check the `QLocalServer` name/ACL and the send path; add a real-Windows test |
| **B-4** | MEDIUM | IPC starts only after the database opens. While the DB is unavailable, the sensor is unreachable and its health ("database error") cannot be read, which contradicts the architecture doc ("IPC reports the error") | code + real (`winerror=2` while the service ran) | The tray shows "offline" with no reason; silent outage | Start IPC before the DB loop, report `database: error` |
| B-5 | MEDIUM (fixed in code, not deployed) | Installed build: only one IPC client served at a time | real, reproduced | Tray and status calls block each other | Fixed in `d48a4bb`; verify after the B-1/B-2 fixes |
| P-1 | LOW–MEDIUM | Live batch detection re-runs over the full lookback; large bursts cost O(N²) | synthetic: 10k records → 17 s CPU | CPU spikes during heavy bursts; no loss | Detect only on identities and sources touched by the batch, or debounce |
| L-1 | LOW | Six `net use` attempts produce one 4625, so the documented `net use` test cannot make a real DET-001 | real | test-method limitation | Use the lock-screen method or a second machine |

### Audit-tooling errors (not MoeSOC)

1. Run 1 updated the service before closing the tray. This exposed B-2, but it also invalidated that run's live and resource measurements.
2. Console RAM was measured on the venv launcher stub.
3. The redaction of a short user name altered the word "Users" in the output.

## Known Limitations

- Toast click routing works only while the toast is visible.
- There is no installer.
- The Sysmon live path is synthetic only.
- Tray autostart is registered for the installing user only.
- The existing user database must be imported explicitly.
- Detection is 16 % slower than v1.0 at 100k events.

## Release Readiness

**Not ready** for a release of the Always-On feature: B-1 and B-2 break the update path and can silently stop monitoring. The v1.0 detection product without the sensor is unchanged and remains as ready as the previous audit stated.

## Portfolio Readiness

**Strong, if described honestly.** It shows:

- a least-privilege service design (virtual account, single privilege, protected data, a hardened IPC with an allow-list);
- a measured near-zero idle cost;
- a 19 h real unattended run.

The bugs found here are typical of real service work and make good "what I learned" material.

## Final Verdict

**PARTIAL.**

- **What works:** the architecture is correct and lightweight, the old functionality has not regressed, and live delivery works on real Windows over 19 hours.
- **What fails:** update/re-install (B-1, B-2), the deep link (B-3) and DB-failure visibility (B-4).
- **Still unproven on real hardware:** the real toast and click, reboot, sleep/resume, and the current build's IPC fix.

### Final verdict questions

1. **Does the Sensor work independently of the GUI?** Yes: 19 h with no console open (TESTED — REAL WINDOWS ✅).
2. **Does closing the Console stop monitoring?** No by design; the sensor ran for 19 h with no console. The close-and-reopen check during the audit was invalid (the sensor was down).
3. **Does closing the Tray stop monitoring?** No by design (no dependency; automated). Real check: invalid (sensor down).
4. **Does the Sensor start automatically with Windows?** Configured `AUTO_START (DELAYED)`; reboot NOT TESTED.
5. **Does the Tray start after login?** Yes: it was running after today's sign-in (TESTED — REAL WINDOWS ✅).
6. **Is real live event delivery proven?** Yes for natural events (146 batches, 0 duplicates). For a deliberately generated event: FAILED ❌ only because the sensor had been stopped by B-2; to be repeated after the repair.
7. **Is a real Windows notification proven?** No: BLOCKED BY USER INTERACTION.
8. **Does a notification click open the correct finding?** Not proven: the routing is automated-tested only, and the real hand-over failed (B-3).
9. **Does deduplication prevent spam?** Yes in automated tests; there was no real notifiable finding.
10. **Is the Sensor lightweight?** Yes when idle.
11. **Idle CPU:** 0.0 % average over 10 minutes (peak 0.02 %).
12. **Sensor RAM:** 36.6 MB working set, 23.2 MB private.
13. **Network listener?** None (code; tray and console netstat). The sensor's own netstat was not captured.
14. **Can an unprivileged user abuse IPC for privileged actions?** No.
15. **Database corruption or locking from Always-On?** No corruption (`quick_check` ok, 0 duplicates). But install B-1 makes the DB inaccessible: an access-rights defect, not corruption.
16. **Do all old detections still work?** Yes (automated; DET-001 and DET-005 real earlier).
17. **Do all old correlations still work?** Yes (automated; COR-001 real earlier).
18. **Did A-1…A-11 remain fixed?** Yes.
19. **Are all GUI pages working?** Yes (smoke 76/76).
20. **Is the CLI working?** Yes.
21. **Synthetic-only:** DET-002, DET-003, DET-004, DET-006, DET-007 and DET-008 positives; COR-002, COR-003 and COR-004; Sysmon live; burst performance.
22. **Untested:** real toast and click, reboot, uninstall, current-build IPC concurrency, console RAM, sensor thread and handle counts.
23. **Manual tests for you:** the repair (UAC), the toast demo, reboot, sleep/resume and uninstall (see the list above).
24. **Remaining bugs:** B-1 HIGH, B-2 HIGH, B-3 MEDIUM, B-4 MEDIUM, B-5 (fixed, undeployed), P-1, L-1.
25. **Safe for everyday local testing?** The detection console is. The always-on sensor is not yet: do not use `install` as an update until B-1/B-2 are fixed.
26. **Ready for GitHub?** The code is, as a work in progress; it is not a release, and the history privacy item is still open.
27. **Ready for your CV?** Yes, describing the sensor as in progress with measured results.
28. **Is v1.0 technically defensible?** For the detection console, yes. For the Always-On feature, no: it should ship as a pre-release (e.g. 1.1.0-beta) after the B-1/B-2 fixes.
