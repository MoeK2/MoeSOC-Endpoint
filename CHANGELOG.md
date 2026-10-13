# Changelog

All notable changes. Versions follow semantic versioning.

## 1.1.0 — 2026-10-11

Always-on monitoring: a Windows sensor service, tray notifications and a
normal-user investigation console. Detection rules and logic are unchanged.

### Added
- MoeSOC Sensor Windows service (`MoeSOCSensor.exe`): virtual service account, live subscriptions to the Security, PowerShell and Defender logs (and Sysmon when installed), catch-up after start and resume, `install`, `uninstall`, `start`, `stop`, `restart` and `status` commands.
- MoeSOC Tray (`MoeSOCTray.exe`): status, Windows notifications, recent finding, pause and notification settings, start at sign-in.
- Finding-based notification engine: one notification per finding, again only on severity escalation or a material risk increase after a cooldown; the state is persisted.
- Notification deep link: clicking opens the finding in the running console or starts it.
- Local named-pipe IPC with a fixed command list, network clients denied and server verification.
- Console triage, notes and verdicts sent through the sensor when the console may only read the database.
- Rollback-safe update of the installed program folder.

### Changed
- With the sensor installed, the console runs as the signed-in user without a UAC prompt; its health view shows what the sensor collects.
- Data-folder access rights are set on the root and inherited; damaged rights from older installs are repaired.
- The sensor starts its IPC before the database, so a database failure is reported instead of hiding the sensor.

### Fixed
- A normal-user console could not read the sensor's database reliably: the sensor's idle connection never opened the WAL files, so they were deleted after each write.
- The deep link could open several consoles.
- Reinstall/update could break the data-folder access rights.
- A failed update could leave the sensor stopped and the program folder half replaced.
- A normal user's tray could not connect to the sensor pipe.
- Reinstalling right after an uninstall could fail while the closed tray was still exiting (bounded retry).
- The retention setting no longer says "saved" before the result is known.

### Validation
- Windows: 672 tests passed elevated, 671 non-elevated; Linux: 670 passed; GUI smoke 76/76.
- Real Windows: live delivery without a manual scan, one real notification and deep link, normal-user console, reboot, sleep/resume, update rollback, uninstall/reinstall with data kept; `quick_check` ok and 0 duplicate events throughout.
- Idle cost: sensor ≈ 0.009 % CPU and ≈ 37 MB; tray ≈ 33 MB.

### Known limitations
- Single endpoint; no automatic response; not an antivirus, EDR or SIEM.
- Sysmon must already be installed for Sysmon telemetry; Sysmon-based and most other detection positives are validated on synthetic events (real: DET-001, COR-001).
- Binaries are not code-signed; no installer (portable folder).
- Low: burst detection cost, Sysmon-missing logged at ERROR, a running tray stays open after uninstall, duplicate "resume" log line.

## 1.0.0 — 2026-10-08

The first complete release: four Windows telemetry sources, twelve explainable
rules and correlations, investigation workflow, tuning, reports and a Windows build.

### Collection
- Incremental, gap-aware collection with a record-ID watermark per channel and event group (bootstrap, incremental, recovery after a cleared or rolled-over log), saved in the same transaction as the events.
- Optional live monitoring with `EvtSubscribe` and automatic recovery (Security log).
- New Security events: 4672 (privileged-session context), 4688 (process creation, own budget), 4720 and 4732.
- Sysmon 1, 3, 11, 13, 22 when present (built-in or standalone Sysmon detected; MoeSOC never installs it).
- PowerShell script blocks (4104), with the Script Block Logging policy shown read-only in Health.
- Microsoft Defender 1116–1119.

### Detection
- Domain identities normalized with evidence-based aliases.
- DET-004 low-and-slow guessing; DET-005 new account; DET-006 privileged local group (by well-known SID, localized names); DET-007 suspicious PowerShell (explainable indicator score); DET-008 Microsoft Defender detection with remediation state.
- COR-002 new account added to administrators; COR-003 suspicious activity in a session opened after failed logons; COR-004 Defender detection traced to the process that wrote the file.
- Cross-source `ActivityGraph`: logon ID, ProcessGuid, file path, Defender Detection ID, PID and user+time links, each labelled with its strength.
- One explainable risk model for every finding (base + documented modifiers).

### Investigation
- Process trees (Sysmon GUID, 4688 PID with reuse protection).
- Investigation stories (finding + related findings, collapsed steps, data gaps, next steps).
- Search and pivots on every collected field, SQL-side and paginated.
- Self-contained HTML reports with optional consistent redaction.

### Operations
- Rule tuning and auditable suppressions (reason required, never hard-deleted, audit log).
- Data retention 7/30/90 days for MoeSOC's own database; never touches Windows logs.
- Benchmarks with real timings (1k–100k events) on the Windows PC and Linux.
- Original application icon; PyInstaller build with self-test; Inno Setup installer script.
- Explicit demo mode (`scripts/demo.bat`): a labelled synthetic attack story in a separate database; collection and Health disabled so real and synthetic data never mix.
- Windows CI workflow and a local mirror script.

### Fixed during development (found by tests and Windows checkpoints)
- Story page imported a helper from the wrong module (found by the Windows GUI smoke test; a static import check now covers GUI modules).
- Tuning offered event IDs as tunable and listed an unused parameter; scan look-back now follows tuned windows.
- Tuning page could show the list from before a change (dropped reload).
- Incremental recovery after a log reset with restarted record IDs never advanced.
- Real screenshots exposed the host name; GUI screenshots are now redacted automatically (host name and user folder).
- Report redaction gave one person two placeholders across domain spellings; users and domains are now redacted separately and consistently.

### Database
Schema v2 → v8, each migration additive and transactional: v3 account/group/process fields, v4 collection state, v5 Sysmon fields, v6 cross-source indexes, v7 settings, v8 suppressions, rule overrides and audit log.

## 0.2.0

Security-log foundation: authentication collection and parsing (4624, 4625, 1102), DET-001, DET-002, DET-003, COR-001 with explainable confidence, SQLite storage with triage, notes and history, event search, timelines, evidence verification, PySide6 console, CLI and the one-click launcher.
