# MoeSOC Always-On Sensor Report

Milestone: the always-on, lightweight sensor. Date: 2026-10-10. Starting commit `c8be8a1`. No new detection rules, no new telemetry types, no cloud, no response actions.

Status labels: TESTED — REAL WINDOWS · TESTED — AUTOMATED · TESTED — SYNTHETIC · NOT TESTED · BLOCKED · MANUAL VALIDATION REQUIRED.

Design details: [ALWAYS_ON_ARCHITECTURE.md](ALWAYS_ON_ARCHITECTURE.md).

## Architecture Before

There was a single PySide6 application. Monitoring ("Live") ran inside the GUI process: closing the window stopped it, and there was nothing at sign-in. The GUI needed elevation to read the Security log, and its data lived in `%LOCALAPPDATA%\MoeSOC`.

## Architecture After

| Component | Process | Privilege | Lifetime |
|---|---|---|---|
| Sensor | `MoeSOCSensor.exe` (Windows service) | `NT SERVICE\MoeSOCSensor` + Event Log Readers, SeChangeNotifyPrivilege only | Windows start (auto, delayed) → shutdown |
| Tray | `MoeSOCTray.exe` (pywin32, no Qt) | signed-in user, not elevated | sign-in (`HKCU\…\Run`) |
| Console | `MoeSOC.exe` (existing GUI) | user; asks for UAC as before (declined = read-only viewing) | only when opened |

There is one detection pipeline. The sensor drives the existing `ScanService` and `LiveMonitor`.

## Windows Service

`moesoc/sensor/service.py` contains only the pywin32 `ServiceFramework` translation:

- start → SensorCore;
- stop/shutdown → stop event, wait hint 35 s;
- power resume → catch-up + resubscribe.

Registration (`sensor.py install` / `MoeSOCSensor.exe install`):

- automatic delayed start;
- restart after 60 s on the first two failures per day;
- required privileges limited to `SeChangeNotifyPrivilege`;
- `--copy-to-program-files` installs into `%ProgramFiles%\MoeSOC Endpoint`;
- `install` on an existing service updates it in place.

`uninstall` keeps all data. **TESTED — REAL WINDOWS** (`sc qc`/`qprivs`/`qfailure` output below).

## Sensor Core

`moesoc/sensor/core.py` runs this sequence: database open with retries → catch-up → subscriptions (Security required; PowerShell, Defender and Sysmon when present) → blocking wait → `ingest_live` → notification decision → hub.

- **Daily maintenance:** WAL checkpoint and `optimize`; retention only if the user chose a retention period.
- **Health:** monitor state, per-channel state, database, last event, catch-up, detection and maintenance times, events stored, batches, last batch size, parse failures, open HIGH/CRITICAL findings, IPC.

**TESTED — AUTOMATED** (15 tests, `tests/test_sensor_core.py`) and **TESTED — REAL WINDOWS** (service status below).

## Tray

`moesoc/tray/` has two parts:

- `controller.py`: the logic, tested without Win32;
- `app.py`: a `Shell_NotifyIcon` window, a long-poll thread and a queue into the window thread.

The menu:

- Open MoeSOC
- Status
- Recent finding
- Run Scan
- Pause notifications (1 h) / Resume
- Notification settings (MEDIUM / HIGH / CRITICAL, start at sign-in)
- Exit Tray (monitoring continues)

Exit only closes the tray, and Pause only pauses toasts. Tray states: Monitoring, Attention required, Limited telemetry, Starting, Sensor offline. Offline and Limited use the Windows warning icon.

**TESTED — AUTOMATED** (controller tests). Real tray: see Windows Validation.

## IPC

There is no network port: the transport is the named pipe `\\.\pipe\MoeSOC.Sensor`.

- **Pipe protections:**
  - remote clients are rejected, and NETWORK is denied;
  - INTERACTIVE gets read/write but cannot create pipe instances;
  - SYSTEM, Administrators and the service account have full control;
  - the first instance refuses a squatted name;
  - the client verifies that the server runs as SYSTEM or a service SID.
- **Messages:** 16 KB JSON with six allow-listed commands: `hello`, `status`, `wait_notifications`, `scan` (1 per minute), `get_prefs`, `set_prefs` (validated).
- **Never exposed:** commands, files, registry, processes or raw events.

**TESTED — AUTOMATED** (23 tests: invalid, oversized and unknown requests, internal errors, rate limit, prefs validation, resync after restart, long poll, several clients, unavailable sensor, server identity rule). **TESTED — REAL WINDOWS**: `status` over the pipe from an administrator prompt.

## Privilege Model

The service account is `NT SERVICE\MoeSOCSensor`, a member of *Event Log Readers* (`S-1-5-32-573`). That group can read the Security, PowerShell and Defender channels, which was shown on real Windows. LocalSystem is used only for a development checkout, because a virtual account cannot read a user profile. The code runs from Program Files, and install refuses code folders that a non-administrator can write to.

`%ProgramData%\MoeSOC` is protected, owned by Administrators, with these rights:

| Principal | Rights |
|---|---|
| SYSTEM, Administrators | full control |
| Service account | modify |
| Users | read |

The console and tray need no elevation to view.

## Notification Logic

Notifications are per finding, never per raw event.

| Severity | Default |
|---|---|
| LOW | never |
| MEDIUM | off (optional) |
| HIGH | on |
| CRITICAL | on (warning style) |

- At most 3 toasts per evaluation: the two most serious, then a summary.
- The text gives the rule title, the first sentence of the rule description, the severity and the risk. No alarmist wording, and no malware claim unless the finding is Defender's own.

**TESTED — AUTOMATED** (20 tests).

## Notification Deduplication

`notification_state` (schema v9, additive migration, tested from v8) records the severity, risk and time each finding was last notified about. A finding notifies again only when:

- its severity **escalates** (immediately); or
- its risk rises by ≥ 15 **after the cooldown** (60 min by default).

Behaviour:

- A growing burst gives one notification.
- A correlation on top gives its own notification.
- The state survives a restart.
- The first start does not announce old findings.
- A pause records decisions silently.

**TESTED — AUTOMATED**.

## Deep Linking

`MoeSOC.exe --finding <id>` behaves as follows:

- **Console closed:** it opens (UAC as usual; the elevated copy gets only a validated `--finding <number>`) and selects the finding. If the finding is closed, the filter switches to All.
- **Console open:** the request goes over a per-user local socket and the window comes to the front. There is no duplicate instance.
- **Invalid or unknown ID:** the console opens normally and the status line explains.

**TESTED — AUTOMATED** (argument and request validation, hand-over and elevation decisions). The real click is in Manual Validation Remaining.

## SQLite / Concurrency

- WAL mode, `busy_timeout` 10 s, one transaction per live batch; the sensor is the main writer.
- When the sensor is installed, the console's Scan asks the sensor and Live shows "Sensor".
- A console without write access opens the database read-only, and writes explain why they fail.

**TESTED — AUTOMATED** (one writer + two readers, then an integrity check; read-only fallback; import with backup and integrity check).

## Startup Behavior

- **Sensor:** `AUTO_START (DELAYED)`, verified with `sc qc`.
- **Tray:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MoeSOC Tray`, registered at install and toggled from the tray menu.
- **Console:** never in start-up.

**TESTED — REAL WINDOWS** (service start type). Sensor start at Windows boot and tray start at sign-in: **MANUAL VALIDATION REQUIRED** (needs a reboot).

## Service Recovery

| Situation | Status |
|---|---|
| Source absent (Sysmon) → reported, others continue | **TESTED — REAL WINDOWS** |
| Security subscription failure → RECONNECTING, back-off, resubscribe | TESTED — AUTOMATED |
| Database unavailable at start → retried | TESTED — AUTOMATED |
| Malformed record → counted and skipped | TESTED — AUTOMATED |
| Resume → catch-up + resubscribe | TESTED — AUTOMATED (simulated power event); real sleep: MANUAL |
| Restart → no duplicates, no repeated notifications | TESTED — AUTOMATED and **REAL WINDOWS** (stop/start/restart) |
| SCM failure actions | configured (`sc qfailure`); a real crash was not induced |

## Resource Usage

All figures are **TESTED — REAL WINDOWS** on Windows 11, 16 logical CPUs, packaged build, service running as the virtual account.

| Measure | Sensor (idle, 10 min) |
|---|---|
| Average CPU | **0.0 %** (rounded at 3 decimals, i.e. < 0.0005 % of the machine) |
| Peak CPU (5 s window) | **0.02 %** |
| Working set (first / last / peak) | **36.5 / 36.6 / 36.6 MB** |
| Private bytes (first / last / peak) | **23.2 / 23.1 / 23.2 MB** |
| Disk writes | 241 operations, 0.6 MB in 10 min (5 live batches of real events, the log) |
| Events processed | 5 live batches, 4 new events during the window (Windows' own logon events) |

**Verdict:**

- **CPU:** near idle.
- **Memory:** flat; no growth seen over 10 minutes.
- **Logs:** no repeated log scans; the sensor log shows one catch-up per start and nothing else.

| Process | Status |
|---|---|
| Tray (`MoeSOCTray.exe`) RAM | **NOT TESTED**: run `scripts\sensor_footprint.bat` with the tray running. It is expected to be small (pywin32 only, no Qt), but no number is claimed. |
| Full console (`MoeSOC.exe`) RAM | **NOT TESTED** in this milestone. The same script measures it separately when the console is open, so console RAM is never mixed with sensor RAM. |

## Idle Benchmark

The data is the table above: `scripts\sensor_benchmark.py watch --service MoeSOCSensor --minutes 10`, run by `scripts\sensor_validate.bat`. The service had just been installed, with the tray not yet running.

## Event Burst Benchmark

**TESTED — SYNTHETIC.** 1,000 generated logon records went through the sensor's real pipeline: `ingest_live` in 2 batches of ≤ 500, then the notification decision, in a throwaway database (`scripts\sensor_benchmark.py burst`).

| Measure | Linux sandbox |
|---|---|
| Processing time | 0.45 s (≈ 2,230 records/s) |
| CPU time | 0.43 s |
| Peak memory (whole process) | 37.7 MB |
| Notifications | 1 (COR-001 HIGH, new); the many DET-001 updates did not notify |
| Latency from last batch to notification decision | 0.35 s (the end-to-end tray latency adds ≤ 2 s batching plus one pipe round trip) |

The same burst on Windows is part of `scripts\sensor_footprint.bat`: **NOT TESTED** yet.

## Tests

| Run | Result |
|---|---|
| Linux pytest (final) | **609 passed, 2 skipped** (the 2 skips require Windows) |
| Windows pytest, non-elevated, `verify_windows.bat` (before the last two IPC/installer fixes) | **610 passed, 1 skipped, 0 failed** |
| New test files | `test_sensor_core.py` 15, `test_sensor_ipc.py` 23, `test_sensor_notifications.py` 20, `test_sensor_storage.py` 4, `test_tray_and_deeplink.py` 26, plus 1 in `test_subscription_source.py` |
| Ruff | check + format clean (Linux 175 files; Windows 173 files) |
| GUI smoke | **76/76** (Windows, real window offscreen) |
| Packaged build | `MoeSOC.exe`, `MoeSOCSensor.exe`, `MoeSOCTray.exe` built; console `--self-test` **PASSED** |

## Windows Validation

Done on the test PC (Windows 11, 16 logical CPUs) with the packaged build (`scripts\sensor_validate.bat`, UAC approved). **TESTED — REAL WINDOWS:**

- **Install:**
  - copied the build to `C:\Program Files\MoeSOC Endpoint`;
  - registered `MoeSOCSensor` as `NT SERVICE\MoeSOCSensor` (`AUTO_START (DELAYED)`, `PRIVILEGES: SeChangeNotifyPrivilege`, restart on failure 60 s × 2);
  - added the account to *Event Log Readers*;
  - set `C:\ProgramData\MoeSOC` to `NT SERVICE\MoeSOCSensor:(M)`, `Users:(RX)`, `Administrators:(F)`, `SYSTEM:(F)`.
- **Start:**
  - state ON in about 1 s;
  - the first catch-up stored 444 events;
  - live channels: Security, PowerShell/Operational, Windows Defender/Operational; Sysmon "not installed" (correct for this PC);
  - database schema v9.
- **Stop, start and restart:** all clean, with no duplicates. Each restart caught up only the records written while it was stopped (2 records).
- **Live delivery:** during the 10-minute idle window the service received **5 batches of real Security events through the subscription, without any scan**. This is real evidence for the earlier A-4 question (live delivery).
- **Idle resource use:** see Resource Usage.
- **IPC:** `MoeSOCSensor.exe status` from an administrator prompt, over the pipe.

**Found on real Windows and fixed:** the IPC instance access error (Bugs Found #2). The fixed build is compiled and its self-test passed. Applying it needs one more UAC approval for `scripts\sensor_update.bat`. **PENDING** at the time of this report: the PC's service still runs the build with the one-client limit.

## Manual Validation Remaining

1. **Reboot:** the sensor runs before sign-in, and the tray appears after sign-in (Monitoring).
2. **Harmless suspicious-authentication demo:**
   1. Lock the screen (Win+L) and type a wrong password 6 times, staying below your lockout threshold (Windows 11 default: 10).
   2. Sign in. Expected: DET-001 (MEDIUM, no toast) and COR-001 (HIGH) → **one** toast.
   3. Click the toast. Expected: the console opens on that finding, with evidence and timeline.
   4. Close the console. Expected: the tray still shows Monitoring.
3. **Sleep/resume:** put the PC to sleep for 1 minute, wake it. Expected: `sensor.log` shows "Resume from sleep", the status stays ON, and there are no duplicate events.
4. **Non-elevated console:** decline the UAC prompt. Expected: findings are visible (read-only); a triage change explains that it needs administrator rights.

## Security Review

The threat considered is an unprivileged local process trying to control or abuse the privileged sensor.

| Asset | Protection |
|---|---|
| IPC | No network listener. Remote clients rejected, NETWORK denied. No pipe-instance creation for users; first-instance check. Client verifies the server account. Six allow-listed commands with typed validation; 16 KB limit; rate-limited scan. No command, file, registry or process operations exist to abuse. |
| Service code | Program Files (admin-only). `install` refuses folders a non-administrator can write; the development override is explicit and printed. |
| Rules / config | Loaded from the install folder (admin-only). Notification preferences are the only user-settable values, all validated. |
| Database and logs | `%ProgramData%\MoeSOC` is protected: users read only; the service and admins write. The service never writes into user-writable folders (junction/link redirection). The console's database writes require elevation. |
| Service privileges | Virtual account, Event Log Readers, `SeChangeNotifyPrivilege` only. No SeSecurity, SeDebug or SeBackup. |

Accepted risks:

- A local user process can hold the four pipe instances and delay that user's own tray updates. Monitoring is unaffected.
- An administrator can do anything, by design.
- Toast click routing works only while the toast is shown.

## Known Limitations

- **Toasts:** these are `Shell_NotifyIcon` balloons shown as toasts. A click from the Notification Center later opens nothing specific (no registered COM activator, no extra dependency). Focus Assist can hide them.
- **Live sources:** optional channels subscribe from their saved position, or after the newest record seen before the catch-up. Sysmon is absent on the test PC, so its live path is automated-tested only.
- **Existing user database:** not migrated automatically. `MoeSOCSensor.exe import-user-data` copies it explicitly; the sensor database starts with the last 24 h of events.
- **Installer:** the Inno Setup installer is not built (Inno Setup is not installed). Install uses `MoeSOCSensor.exe install --copy-to-program-files` from an administrator prompt.
- **Single-user design:** the tray autostart is registered for the installing user.

## Bugs Found

1. **Lost-record race:** with no saved position, a record written between the catch-up and `EvtSubscribe` was lost, because the subscription started "from new events". Found by the first Windows run of the new tests (`test_resume_and_manual_scan_catch_up_again`).
2. **IPC instances:** pipe instances 2–4 failed with access denied when the service runs as the virtual account, so only one client was served at a time and the stop took 5 s. Found in the real service log.
3. **Re-install:** a second `install` failed on an existing service and a locked Program Files folder. Found while preparing the fix deployment.

## Bugs Fixed

1. Subscribe after the newest record seen before the catch-up when no position is saved (`545dcf0`). A regression test fails without the fix.
2. The service's own account gets full control of its pipe (`d48a4bb`).
3. `install` stops the service, copies over the files and updates the registration in place (`d48a4bb`).

## Final Verdict

The always-on architecture is in place: a service with no GUI, a separate small tray, the console only on demand, and one pipeline.

On real Windows the service is **lightweight when idle**: ~0 % CPU, 36.6 MB working set, flat memory, no repeated log scans. It delivered real events live without the console.

| Definition of done | Status |
|---|---|
| Sensor runs without GUI; closing the GUI does not stop monitoring | **TESTED — REAL WINDOWS** (the console was never open while the service ran) |
| Sensor starts with Windows | Configured and verified with `sc qc`; reboot: MANUAL VALIDATION REQUIRED |
| Tray starts at sign-in | Registered; MANUAL VALIDATION REQUIRED |
| No constant full-log polling | TESTED — REAL WINDOWS (log, CPU) |
| Existing detection engine reused | TESTED — AUTOMATED |
| One notification per high-severity finding; updates do not spam | TESTED — AUTOMATED; the real toast is MANUAL VALIDATION REQUIRED |
| Notification opens the correct investigation | TESTED — AUTOMATED (routing); the real click is MANUAL VALIDATION REQUIRED |
| No network port; IPC validates requests | TESTED — AUTOMATED; real pipe used |
| Clean service shutdown | TESTED — REAL WINDOWS |
| SQLite safe under sensor + GUI | TESTED — AUTOMATED |
| Idle usage measured | TESTED — REAL WINDOWS |
| Full tests, Ruff, GUI smoke | Linux 609 passed / 2 skipped. Windows 610 passed / 1 skipped (before the final two fixes, which touch only the pipe access list and the installer). Ruff clean. GUI smoke 76/76 |

**Not yet done:** the real toast-and-click demo, the reboot check and tray RAM. They need you at the PC and are listed under Manual Validation Remaining.
