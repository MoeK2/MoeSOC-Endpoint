# MoeSOC Endpoint: Final Independent Validation Report

**Audit date:** 2026-10-08, 10:59 to about 11:40 UTC.
**Version audited:** v1.0.0, commit `62ca4927fbd30058ff982836818ede6ade0ef43a` (tag `v1.0.0`).
**Scope:** test, inspect and document the project as it is. No product code was changed during this audit.

Every conclusion below comes from tests run, code read and probes executed during this audit. Existing project documents were used only for comparison. Personal identifiers are replaced with placeholders: `<HOST>` for the computer name, `<USER>` for the user name, `S-1-5-21-<LOCAL>` for local SIDs and `%USERPROFILE%` for the home folder.

### Status labels used in this report

| Label | Meaning |
|---|---|
| **TESTED — REAL WINDOWS** ✅ | Observed against genuine telemetry on the test PC during this audit |
| **TESTED — AUTOMATED** | Covered by an automated test that ran and passed during this audit |
| **TESTED — SYNTHETIC** ⚠ | Exercised only with fixtures or the labelled synthetic demo data |
| **PARTIALLY TESTED** | Part of the behaviour was observed; the rest is listed |
| **NOT TESTED** | No evidence either way |
| **BLOCKED BY ENVIRONMENT** | Not possible on this machine (software absent, no remote, …) |
| **BLOCKED BY USER INTERACTION** | Needs a human action that did not happen during the audit |
| **FAILED** | Observed to behave incorrectly |

---

## Executive Summary

MoeSOC Endpoint is a local, read-only Windows detection and investigation console for one computer. It is written in Python with a PySide6 GUI, a CLI and SQLite storage. It reads four Windows event-log sources (Security, Sysmon, PowerShell Operational, Microsoft Defender Operational) and stores normalized events. It then runs **8 detections and 4 correlations** with explainable evidence. On top of that it offers triage, timelines, process trees, investigation stories, search and pivots, tuning, suppressions, retention and HTML reports.

### What is solid (measured)

- **Engineering hygiene:**
  - 452 automated tests: 452/452 passed elevated on Windows, 451 + 1 skip non-elevated, and 450 + 2 skips three times in a row on Linux.
  - Ruff reports no problems.
  - All 76 GUI smoke checks passed in every run.
  - Migrations from every older schema version (v1 to v7) to v8 kept all data.
  - SQL is parameterized everywhere.
  - The HTML report escapes hostile input correctly.
  - Redaction removed every identifier tested.
- **Real Security-log collection works:**
  - The first elevated scan read 1,269 records, stored 515 new events and had **0 parse failures** (0.36 s).
  - An immediate rescan read 0 records and created 0 duplicates; incremental watermarks worked.
  - The stored evidence of every real finding (24 of 24 records) was **re-verified in the live Windows log**.
- **Real detections:** DET-001 (×2), COR-001 and DET-005 have fired on genuine events from this PC.

### What is weak (measured)

- **Most detection logic has never seen real positive telemetry.** 8 of 12 rules are **synthetic-only for positive cases**. Sysmon is not installed, Script Block Logging is off, and the Defender log contains **0** detection events. COR-004 cannot fire on this machine at all.
- **Live monitoring is unproven where it matters.** On real Windows it starts, stops and restarts correctly. During this audit it delivered **0 events in 36 s**. The restart's catch-up scan stored 1 new event; its channel was not determined, and it may be a PowerShell record, which the subscription does not cover. Receiving events in real time was **not demonstrated**.
- **Three real defects were found** (none blocked the audit, none fixed per instructions):
  1. **Duplicate findings in live mode.** Long campaigns produce many duplicates: one simulated 3-hour slow-guessing campaign produced **22 DET-004 findings** instead of 1.
  2. **Identity split on the domain field.** The domain field of Event 4625 is supplied by the client. Varying it splits one account into several identities. This **evades DET-001** and makes the activity look like a password spray (DET-002).
  3. **False tamper alarms in evidence verification.** Verification reports genuine, unmodified Sysmon, PowerShell and Defender evidence as **"mismatch"**. It only understands Security-log XML.
- **Release:**
  - No installer exists (Inno Setup is not installed).
  - No GitHub remote exists, so GitHub CI has never run.
  - There is no `LICENSE` file, although `pyproject.toml` declares MIT.
  - **Git history contains older screenshots that show the real computer name.**

### Verdict in one line

A well-engineered, honest, well-tested portfolio project with real Security-log validation. It is **not yet credible as "v1.0 detection coverage"**, because the advanced sources were never exercised with real positives and live monitoring has not been shown to receive events. It is ready for a CV once the history is cleaned. It is ready for GitHub after the four must-do items (see Release Readiness).

---

## Environment

| Item | Value | How obtained |
|---|---|---|
| Test PC OS | Windows 11 Pro, 10.0.26200 | `platform` on the PC |
| CPU | Intel64 Family 6 Model 191, 16 logical | benchmark header |
| Python (PC) | 3.13.15 | venv |
| PySide6 | 6.11.2 | `importlib.metadata` |
| pywin32 | 312 | `importlib.metadata` |
| PyYAML | 6.0.3 | 〃 |
| pytest / Ruff (PC) | 9.1.1 / 0.16.10 | 〃 |
| PyInstaller | 6.22.3 | 〃 |
| SQLite (PC) | 3.50.4 | `sqlite3.sqlite_version` |
| Elevated run | yes, via standard UAC prompt approved by the owner (11:08 UTC) | `is_admin()` |
| Sandbox | Linux x86_64, Python 3.13.16, Ruff 0.16.8, no PySide6 | `uname`, `python3 --version` |
| Security log | 20 MB max, no auto-backup, 24,968 records, oldest record 552,669 | `wevtutil gl/gli Security` |
| Sysmon | **not installed** (channel `Microsoft-Windows-Sysmon/Operational` does not exist, no service) | EvtQuery error 15007 |
| PowerShell Operational | readable; **1,561** Event 4104 records present | EvtQuery |
| Script Block Logging policy | **disabled** (only script blocks PowerShell itself flags are logged) | registry, read-only |
| Defender Operational | readable; **0** events with ID 1116–1119 | EvtQuery |
| Inno Setup 6 | **not installed** | file checks |

## Version / Git State

| Item | Value |
|---|---|
| Project version | `1.0.0` (`moesoc/__init__.py`, `pyproject.toml`, `packaging/MoeSOC.iss`) |
| Branch | `master` |
| Commit | `62ca4927fbd30058ff982836818ede6ade0ef43a` |
| Tag | `v1.0.0` (annotated, local only) |
| Commits | 78 total; 52 since the v0.2.0 baseline `87ee34d` |
| Working tree at audit start | **clean** (`git status --porcelain` empty) |
| Remote | **none configured** |
| Tracked files | 221 |
| Python source | 14,353 lines (product), 5,948 lines (tests), 42 test modules |
| Database schema | v8 |
| Packaged executable | `dist\MoeSOC\MoeSOC.exe`, reports `MoeSOC 1.0.0, Python 3.13.15, frozen=True` in its self-test |

### Existing databases on the PC (opened read-only, `mode=ro`)

| Database | Schema | Integrity | Events | Event IDs | Findings | Source of events |
|---|---|---|---|---|---|---|
| App default (`%LOCALAPPDATA%\MoeSOC`) | v8 | ok | 1,331 | 4104×50, 4624×1,253, 4625×18, 4672×8, 4720×1, 4732×1 | 4 (DET-001×2, DET-005, COR-001) | all 1,331 from the local host: **REAL** |
| Validation copy (`.verify-data`) | v8 | ok | 998 | 4624×980, 4625×18 | 3 (DET-001×2, COR-001) | all local host: **REAL** |
| CI mirror (`ci-data`) | v8 | ok | 0 | — | 0 | — |

---

## Product Description

MoeSOC is a single-computer, **observe-only** tool:

- It never blocks, kills, quarantines or changes system settings.
- It makes no network connections.
- It never installs Sysmon or changes audit or PowerShell policy.

A grep of `moesoc/`, `launcher/` and `app.py` for `shell=True`, `requests`, `urllib`, `http.client`, `socket.connect`, `TerminateProcess`, `auditpol` and `reg add` found none. The only `subprocess` use is the launcher starting MoeSOC with an argument list. The `Set-MpPreference` match is a DET-007 detection pattern, not an action.

It has three interfaces over one backend:

- **GUI** (PySide6) with 9 pages: Overview, Detections, Timeline, Events, Process Tree, Story, Tuning, Reports, Settings.
- **CLI** with 17 commands: `health, scan, import-xml, events, detections, show, triage, note, timeline, process-tree, retention, suppress, rules, audit, report, story, verify-evidence`.
- **Packaged executable** (PyInstaller one-folder build) with `--self-test`.

## Architecture

The pipeline as actually implemented:

```
Windows Event Log (EvtQuery / EvtSubscribe, pywin32)
  → collectors/   eventlog.py (only EvtQuery caller), security.py, sysmon.py, powershell.py,
                  defender.py, subscription.py (only EvtSubscribe caller)   [record-ID watermarks]
  → parsers/      windows_event.py (XML), security.py, sysmon.py, powershell.py, defender.py,
                  dispatch.py
  → core/         event.py NormalizedEvent (one schema for all sources), identity.py, domains.py
  → storage/      repository.py (INSERT OR IGNORE on host+channel+record), schema.py (v1→v8)
  → engine/       rules.py, account_rules.py, powershell_rules.py, defender_rules.py (detections)
                  correlation.py, cross_source.py + activity.py (correlations, ActivityGraph)
                  risk.py (one explainable risk model), validation.py (evidence re-check)
  → storage/      story.py, process_tree.py, event_search.py, report.py, tuning.py, retention.py
  → gui/ and cli.py (presentation only)
```

| Claim to verify | Result | Evidence |
|---|---|---|
| GUI contains no detection logic | **Mostly true.** No rule evaluation in `gui/`. Minor coupling: `gui/pages/detections.py` has rule-ID-specific explanation strings (`if rule.rule_id == "DET-007": …`) | code read |
| CLI and GUI share backend services | **True.** Both use `ScanService`, `search_events`, `build_story`, `build_process_tree`, `finding_report`, the tuning repository and the retention module | imports |
| Collectors separated from parsing | **True.** Collectors call the reader and pass XML to the parser functions | `ChannelCollector(reader, channel, groups, parse_fn)` |
| Event normalization exists | **True.** A single frozen `NormalizedEvent`; values are never invented (`None` when absent) | `core/event.py` |
| Rules separate from presentation | **True.** YAML holds metadata and parameters, Python holds the logic, both are in `engine/` | `rules/*/*.yaml` |
| SQLite persistence centralized | **True.** Every SQL statement is in `moesoc/storage/` (11 files); none in `gui/`, `cli.py` or `engine/` | grep |
| Migrations are safe | **True.** Each runs in one transaction. A newer-than-supported DB is refused untouched. Upgrades from v1–v7 tested (see Data Storage) | probe + tests |
| Evidence links findings to events | **True.** `detection_events(detection_id, event_pk)` plus `(hostname, channel, record_id)` references, re-verifiable in the live log | schema + probes |

**Architecture problems found**

1. **Rule wiring is hard-coded** in `RULE_FUNCTIONS` and special cases in `scanner.py` (DET-008 partner lookback, COR-004 file window). This is acceptable at this size, but adding a rule touches four places (YAML, engine function, scanner registry, GUI explanation string).
2. **Detection re-runs over a sliding window of stored events.** Finding identity is "rule + host + first record of the burst". When a burst is longer than the reload window, the first record changes and a duplicate finding is created (Bug A-1).
3. **Evidence verification is Security-only** (`parse_security_xml`) although evidence now comes from four channels (Bug A-3).
4. **Live monitoring covers only the Security log.** Sysmon, PowerShell and Defender are collected only by scans and catch-up.

---
## Telemetry Sources

| | Windows Security | Sysmon | PowerShell Operational | Microsoft Defender Operational |
|---|---|---|---|---|
| Channel | `Security` | `Microsoft-Windows-Sysmon/Operational` | `Microsoft-Windows-PowerShell/Operational` | `Microsoft-Windows-Windows Defender/Operational` |
| Event IDs collected | 1102, 4624, 4625, 4672, 4688, 4720, 4732 | 1, 3, 11, 13, 22 | 4104 | 1116, 1117, 1118, 1119 |
| Collector | ✅ two groups (core and 4688 process) with separate budgets and watermarks | ✅ five groups | ✅ | ✅ |
| Parser | ✅ | ✅ | ✅ (script text not exposed by default) | ✅ |
| Storage | ✅ | ✅ (schema v5 fields) | ✅ | ✅ |
| Used by detections | DET-001–006 | DET-007 (parent/command-line context) | DET-007 | DET-008 |
| Used by correlations | COR-001, 002, 003 | COR-003, COR-004, process tree | COR-003 | COR-003, COR-004 |
| Live subscription | ✅ (start/stop real; delivery unproven) | ❌ scans only | ❌ scans only | ❌ scans only |
| Fixture tests | ✅ AUTOMATED | ✅ AUTOMATED | ✅ AUTOMATED | ✅ AUTOMATED |
| **Real Windows** | **TESTED — REAL WINDOWS ✅** 1,269 records read, 0 parse failures | **BLOCKED BY ENVIRONMENT**: not installed (never installed by MoeSOC, by design) | **PARTIALLY TESTED — REAL**: real 4104 records collected and parsed, 0 parse failures; Script Block Logging is **disabled**, so no user-generated 4104 could be produced | **PARTIALLY TESTED — REAL**: channel read OK, **0** real 1116–1119 events exist; parser and rule synthetic-only |

Real-Windows evidence for the Security and PowerShell rows is from the elevated scan of the copied database (section *Real-Telemetry Validation*). After the scans, the copy held 1,515 events: 4104×41, 4624×1,429, 4625×20, 4672×9, 4688×14, 4720×1, 4732×1.

**Missing from Security coverage.** Present in this PC's Security log, but not collected:

- 4648 (explicit credentials)
- 4634 and 4647 (logoff)
- 4722, 4724, 4726 and 4738 (account enabled, password reset, account deleted, account changed)
- 4728, 4729 and 4733 (global-group add, global-group removal, local-group removal)
- 4798 and 4799 (group/user enumeration)

Persistence telemetry (7045/4697 service install, 4698 scheduled task) is not collected at all.

## Supported Event IDs

| Source | ID | Meaning | Parsed fields used |
|---|---|---|---|
| Security | 1102 | Audit log cleared | actor |
| Security | 4624 | Successful logon | target account and SID, logon type, logon ID, source IP, workstation, auth package |
| Security | 4625 | Failed logon | target account, status/sub-status, source IP, logon type |
| Security | 4672 | Special privileges (context only; SYSTEM/LOCAL/NETWORK SERVICE dropped as noise) | subject, logon ID |
| Security | 4688 | Process creation (needs process auditing; 14 real records stored) | process, parent, command line, PID, logon ID |
| Security | 4720 | User account created | new account and SID, actor, actor logon ID |
| Security | 4732 | Member added to local group | member SID, group SID (localized names handled), actor |
| Sysmon | 1 / 3 / 11 / 13 / 22 | Process create / network / file create / registry set / DNS | ProcessGuid, image, parent, command line, IPs, ports, path, query |
| PowerShell | 4104 | Script block | script block ID, part N of M, Windows "warning" flag, PID |
| Defender | 1116 / 1117 / 1118 / 1119 | Detected / action taken / action failed / critical failure | threat name, severity, path, process, user, Detection ID |

## Detection Rules

Real-validation status is the most important column. "Synthetic only" means the positive case has only been seen on fixtures or the labelled demo database.

| Rule | Name | Source / IDs | Logic (from code) | Defaults | Severity | Confidence logic | MITRE | Likely false positives | Evidence stored | **Real status** |
|---|---|---|---|---|---|---|---|---|---|---|
| **DET-001** | Multiple Failed Logins | Security 4625 | ≥ threshold failures for one *identity key* in a rolling window; overlapping windows merged into one burst | 5 in 5 min | MEDIUM | fixed MEDIUM | T1110 | mistyped or stale passwords, services with old passwords | count, first/last, IPs, workstations, logon types, reasons, record IDs, identity basis | **TESTED — REAL WINDOWS ✅** 2 real findings (8 "account does not exist", 7 "incorrect password", interactive, loopback); 15/15 evidence records re-verified today |
| **DET-002** | Password Spray | Security 4625 | one source (IP, else workstation) fails against ≥ N distinct identity keys in a window | 5 accounts / 30 min | MEDIUM | fixed | T1110.003 | shared PCs, scanners, jump hosts | source, accounts (capped list), not-found count | **SYNTHETIC ONLY ⚠** (also fires on a *single* account whose domain field varies; see Identity) |
| **DET-003** | Security Log Cleared | Security 1102 | every 1102 | — | HIGH | HIGH (that it happened) | T1070.001 | admin maintenance | actor, record | **SYNTHETIC ONLY ⚠** (no 1102 in the current log; clearing it was not attempted: destructive) |
| **DET-004** | Low-and-Slow Guessing | Security 4625 | identity mode ≥10/60 min, or source mode ≥15/60 min over ≥2 accounts; failures already in DET-001 or DET-002 bursts excluded; machine accounts ignored | 10 / 15 / 60 min | MEDIUM | LOW | T1110, T1110.001 | phones or services retrying old passwords | cadence, intervals | **SYNTHETIC ONLY ⚠**; **FAILED in live-ingest probe** (duplicates, Bug A-1) |
| **DET-005** | New User Account | Security 4720 | every 4720; MEDIUM when the name ends in `$` | — | LOW (→ MEDIUM) | HIGH | T1136.001 | admin onboarding, installers | new account, SID, actor, actor logon ID | **TESTED — REAL WINDOWS ✅** 1 real finding (LOW/HIGH, risk 20), evidence 1/1 re-verified |
| **DET-006** | Privileged Local Group Addition | Security 4732 | group recognised by well-known SID (S-1-5-32-544 and others; localized names safe); name fallback only without a SID → LOW confidence | — | HIGH (admin-equivalent) / MEDIUM | HIGH; LOW for name-only match | T1098.007 | admin granting rights | member SID, group SID and tier, actor | **PARTIALLY TESTED — REAL**: one real 4732 parsed; it did **not** fire (see *Real-Telemetry Validation*); positive case synthetic only |
| **DET-007** | Suspicious PowerShell | PowerShell 4104 (+ process context) | reassembles multi-part script blocks; sums indicator points (download+execute, encoded command, AMSI or Defender tampering, credential theft, obfuscation, unusual parent, hidden window, Windows-flagged); finding at ≥3, HIGH at ≥6 | 3 / 6 | MEDIUM / HIGH | MEDIUM / HIGH by score | T1059.001 (+ per-indicator) | admin and deployment scripts, security tools, red teams | indicators with points and excerpts; script stays in the local raw event | **PARTIALLY TESTED — REAL**: 41 real 4104 records collected, 0 parse failures, **0 findings** (no false positive on real script blocks); positive case **synthetic only ⚠** |
| **DET-008** | Microsoft Defender Detection | Defender 1116–1119 | each 1116 joined by Detection ID to 1117/1118/1119 (look back 7 days); severity from Defender; HIGH if remediation failed or allowed | 7 days | MEDIUM / HIGH | HIGH (that Defender recorded it) | none (by design) | EICAR, deliberate PUA, Defender false positives | threat, path, process, user, remediation state | **SYNTHETIC ONLY ⚠** (0 real Defender detections on this PC; EICAR test not performed without explicit approval) |

## Correlation Rules

| Rule | Sources | Keys and window | Identity / session logic | Confidence | Risk effect | Why related | False-positive risk | **Real status** |
|---|---|---|---|---|---|---|---|---|
| **COR-001** Possible Account Compromise | Security 4625 → 4624 | same identity key; ≥5 failures within 10 min before the success | identity resolver (SID ↔ DOMAIN\user, proven domain aliases); 4672 on the success session marks it privileged | points: +2 network or RDP success, −1 local interactive, +1 remote IP, +1 same IP as the failures, +1 many sources, +1 high volume, −1 same workstation and type with no remote address. LOW ≤0, MEDIUM 1–2, HIGH ≥3 | base 70; −10 if LOW; +10 if privileged | same account, failures directly precede the success | users who finally type the right password (the real case scored LOW for exactly this reason) | **TESTED — REAL WINDOWS ✅** 1 real finding (HIGH/LOW), evidence 8/8 re-verified |
| **COR-002** New Account Added to Administrators | Security 4720 → 4732 | same new-account SID, admin-tier group, within 30 min | SID only | HIGH; MEDIUM when the group was recognised by name only | base 70 | same SID created then elevated | planned admin accounts, LAPS-style scripts | **SYNTHETIC ONLY ⚠** |
| **COR-003** Suspicious Activity After Failed Logons | Security + Sysmon/4688 + PowerShell + Defender | ≥5 failures/10 min → success → activity in the **same logon ID** within 60 min; Defender by user and time | logon ID (exact); Defender links by user and time (weak) | HIGH; MEDIUM when only a weak Defender link matched | base 70, +5 when ≥2 logs | each chain step lists log, record and link strength | admin doing routine work after typos. **A weak user-and-time link still counts toward the "+5 corroborated" bonus** | **SYNTHETIC ONLY ⚠** |
| **COR-004** Defender Detection Traced to Its Source | Defender 1116 + Sysmon 11/1/22/3 | file path (exact) within 60 min before detection → writer ProcessGuid → its DNS and network; executed? | ProcessGuid (exact); PID+time (weaker) when the GUID is missing | HIGH; MEDIUM when the writer start was not collected | from Defender severity: −15 remediated, +10 failed, +10 executed, +5 multi-log | exact file path and GUID links | EICAR or test files, archives with samples | **SYNTHETIC ONLY ⚠**: **cannot run on this PC** (no Sysmon) |

All four correlations store an explicit `chain` with `link` and `link_strength` per step. This was verified in the demo database (COR-003: `logon_id: exact` ×3, `account`, and `user_time: weak` for the Defender step).

## MITRE ATT&CK Coverage

| Tactic | Techniques (rule) |
|---|---|
| Credential Access | T1110 (DET-001, DET-004, COR-001, COR-003), T1110.001 (DET-004), T1110.003 (DET-002) |
| Initial Access / Persistence / Privilege Escalation / Defense Evasion | T1078 Valid Accounts (COR-001, COR-003) |
| Persistence | T1136.001 (DET-005, COR-002), T1098.007 (DET-006, COR-002) |
| Defense Evasion | T1070.001 (DET-003) |
| Execution | T1059.001 (DET-007); T1204.002 per finding (COR-004, if the file ran) |
| Command and Control | T1105 per finding (COR-004, when a download was seen) |

That is **10 distinct techniques**, all mapped at rule or finding level. DET-008 deliberately has no technique (the classification is Defender's threat name).

There are no detections for Discovery, Lateral Movement, Collection, Exfiltration or Impact. Persistence coverage is limited to accounts: no services, scheduled tasks or Run keys, although Sysmon 13 registry events are collected.

**Display defect.** `cli show` for COR-004 prints an empty `MITRE:` line, while the finding's evidence holds `related_techniques: ['T1105']` (Bug A-6).

## Identity Resolution

**How it works** (`core/identity.py`, `core/domains.py`, read in full):

1. **SID first.** A reliable SID (`S-1-…`, not the NULL SID `S-1-0-0`) becomes the key `sid:<SID>`.
2. **DOMAIN\user.** Matching is case-insensitive (`str.casefold`). Domain `.` is replaced by the short host name. NetBIOS and DNS spellings (`CORP` / `corp.local`) are merged **only with evidence**: a shared authority SID (`S-1-5-21-A-B-C`) or this computer's own configuration. There is no string guessing. A name seen with two authority SIDs is marked ambiguous and never merged.
3. **HOST\user.** Used when no domain was recorded (key prefix `host:`).
4. **username only.** Used when neither domain nor host is known (key prefix `user:`).
5. **Name to SID upgrade.** A name-only identity (typical for 4625) is upgraded to the SID seen for exactly that DOMAIN\user in the same analyzed events, only when exactly one SID was observed.

**Probes run during the audit** (`build_identity` and the full pipeline through `ingest_live`):

| Case | Observed key | Assessment |
|---|---|---|
| SID present | `sid:S-1-5-21-1-2-3-1001` | ✅ |
| NULL SID + LAB\alice | `acct:lab\alice` (falls back to name) | ✅ |
| `ALICE`/`lab` vs `alice`/`LAB` | same key | ✅ case-insensitive |
| domain `.` vs domain = host name | same key `acct:ws01\alice` | ✅ |
| **empty domain** vs domain = host name | `host:ws01\alice` vs `acct:ws01\alice` | ❌ **split**. Six alternating failures produced **no DET-001** (3 + 3) |
| FQDN `lab.example` vs NetBIOS `LAB` without SID evidence | different keys | by design (no guessing); a split in practice |
| machine account `WS01$` | `acct:lab\ws01$` | ✅ kept distinct; DET-004 ignores machine accounts |
| SYSTEM | `sid:S-1-5-18` | ✅ (4672 for SYSTEM/LOCAL/NETWORK SERVICE dropped as noise) |
| Unicode `Straße` vs `STRASSE` | **same key** `acct:lab\strasse` | ⚠ **false merge**. `casefold` maps ß→ss; Windows treats these as different names. Rare |
| Turkish `İlker` vs `i̇lker` | same key | consistent with casefold; unlikely to matter |
| full-width `ａｌｉｃｅ` vs `alice` | different keys | ✅ (no NFKC normalization; correct for Windows) |

**Most important identity weakness (FAILED probe).** In Event 4625 the `TargetDomainName` field is **whatever the client supplied**. An attacker sent six failures for `alice` from one IP, each with a different domain string (`LAB`, `x1` … `x5`):

- **DET-001 did not fire** (six identities with one failure each).
- **DET-002 fired instead**, reporting a "password spray against 5 accounts" that was actually one account.

The attack is still surfaced, but misclassified and with a wrong account count. A 4625 identity for a non-domain-joined machine should fall back to the local SAM context, or DET-001 should also key on the user name alone (Bug A-2).

**Split cases:** empty domain vs host domain, FQDN vs NetBIOS without SID proof, attacker-chosen domain strings.
**Merge cases:** casefold Unicode equivalences. A name shared by two SIDs is correctly *not* merged.

## Data Storage

- **SQLite, schema v8.** 11 tables: `events, detections, detection_events, detection_history, detection_notes, scans, collection_state, settings, suppressions, rule_overrides, audit_log`. 20 indexes, including host+record, timestamp, process GUID, logon session, file path NOCASE, DNS, destination IP and target SID.
- **Duplicate protection.** `INSERT OR IGNORE` on `(hostname, channel, record_id)`. After migration from every old version, inserting a duplicate record was **rejected** (probe). The real-PC scan copy had **0 duplicate event rows** after 4 scans and 2 live runs.
- **Migration audit** (probe `probe_mig.py`). Databases were built at **v1, v2, v3, v4, v5, v6 and v7** with 50 events and 1 finding, then opened by the current code:

| From | To | Events kept | Findings kept | Evidence links | `integrity_check` | Re-initialize |
|---|---|---|---|---|---|---|
| v1 … v7 (each) | v8 | 50/50 | 1/1 | 2 (rebuilt from evidence) | ok | idempotent |

  - A database marked **v99** was refused with "created by a newer version … left untouched", and its `user_version` stayed 99.
  - Rollback on a failing migration is covered by `test_migration_v3_failure_rolls_back_completely` (TESTED — AUTOMATED).
- **Real databases.** Both real databases on the PC are v8 and pass `quick_check`. Event counts match the last known values (998 in `.verify-data`). No real database was modified by this audit; the scans ran on a backup-API copy.
- **Storage cost.** 1.76 KB per event (100,000 synthetic events = 176.0 MB on Windows).
- **Finding history quirk.** Findings created by an older rule version are preserved as-is and not re-scored. The same real COR-001 finding shows **risk 70** in `.verify-data` (created by rule v2.0 before the risk model) and **risk 60** in the app database (v2.2: 70 − 10 for LOW confidence). This is documented intent, but visible as inconsistency (Bug A-7).

## Incremental Collection

**TESTED — REAL WINDOWS ✅** (copy of `.verify-data`, elevated, 11:08–11:09 UTC):

| Scan | Mode reported | Records read | Normalized | New events | Parse failures | Findings (total) | Duration | Watermarks after |
|---|---|---|---|---|---|---|---|---|
| 1 | core, process, PowerShell: bootstrap; Sysmon: not installed | 1,269 | 684 | 515 | **0** | 3 → 4 | 0.36 s | Security core 577,636; process 577,150; PowerShell 167,076 |
| 2 (immediate) | incremental | **0** | 0 | **0** | 0 | 4 | 0.24 s | unchanged |
| 3 (after the logon attempts) | incremental | 1 | 1 | 1 | 0 | 4 | 0.23 s | core 577,638 |
| 4 | incremental | 0 | 0 | 0 | 0 | 4 | 0.23 s | unchanged |

- In scan 1, 1,269 records were read and 684 kept after the deliberate 4672 service-account noise filter. Of those 684, 169 were already in the copied database (ignored as duplicates) and 515 were new.
- **0 duplicate rows** in the events table after all scans.
- The fourth finding after scan 1 is the real **DET-005** (a 4720 written about 20 hours earlier, now inside the 24-hour look-back).
- Gap, rollover and reset recovery logic is covered by 17 tests in `test_incremental_collection.py` (TESTED — AUTOMATED). It was not exercised on real Windows, because that would need clearing or rolling the log.

**Inconclusive real event generation.** Six attempts of `net use \\127.0.0.1\IPC$ /user:moesoc-audit-nouser <wrong password>` all returned exit code 2 (failed as intended). The following scan read only **1** new record, and no DET-001 fired. The local SMB loopback attempts evidently did not produce six 4625 records the way a network logon from another machine would; the diagnostic in *Live Monitoring* looks for those rows. Fresh real brute-force validation therefore still needs **MANUAL VALIDATION REQUIRED** (failed logons typed at the lock screen or `runas` with a test account, as done on 2026-10-07).

## Live Monitoring

Design: catch-up scan → `EvtSubscribe` from the oldest group watermark (bookmark, strict) → batch → `ingest_live` → detect. Only the **Security** channel is subscribed.

| Check | Result | Status |
|---|---|---|
| Start (elevated): STARTING → ON | ON after **0.26 s** ("Monitoring the Security log after record 577150") | **TESTED — REAL WINDOWS ✅** |
| Receive new events | **0 batches in 36 s**, while six `net use` failures were generated. See the diagnostic below | **NOT DEMONSTRATED** |
| Stop | OFF; worker thread joined | **TESTED — REAL WINDOWS ✅** |
| Restart | ON after 0.24 s; the catch-up scan stored **1** new event (channel not determined: the catch-up also reads PowerShell and Defender, which the subscription does not cover) | **PARTIALLY TESTED**: restart works |
| Deduplication across restart | 0 duplicate rows | **TESTED — REAL WINDOWS ✅** |
| Non-elevated start | ERROR state with "administrator" message (GUI smoke, and screenshot 07) | TESTED — REAL WINDOWS ✅ |
| GUI toggle and status | 76/76 smoke checks incl. "live monitoring stops cleanly", "live toggle reflects state" (fake subscription source) | TESTED — AUTOMATED |
| Reconnect with back-off | 12 tests in `test_live_monitor.py` | TESTED — AUTOMATED |

**Code-level concern** (`collectors/subscription.py`). The signal is created **auto-reset and initially non-signalled** (`CreateEvent(None, False, False, None)`), and the loop waits on it before the first `EvtNext`. Microsoft's pull-subscription sample uses an initially signalled manual-reset event, so records already matching the bookmark are drained at once. With the current code, a backlog after the bookmark is not read until a new matching record arrives. The catch-up scan stores the backlog anyway, so this is not data loss. It does mean real-time delivery depends entirely on new events signalling correctly, which this audit could not demonstrate.

**Follow-up diagnostic: BLOCKED BY USER INTERACTION.** A non-elevated, read-only diagnostic (`audit\audit_live_diag.bat`) was prepared. It compares the product subscription with an initial drain and with an initially signalled event on the Application log, and lists which events the logon attempts produced. It could not be started: after the elevated run, a window the audit tooling could not see or move covered File Explorer, and the owner was not available to minimize it. Real-time delivery therefore remains **NOT DEMONSTRATED** (manual item M3).

**Bug A-1: duplicate findings in live mode (FAILED, synthetic probe through the real `ingest_live` code path).** Live batches reload only `max(rule window)` ≈ 70 minutes of stored events. A finding's identity is rule + host + **first record of the burst**. For a campaign longer than that window, the first visible record moves forward with every batch and a new finding is created each time.

| Probe | Result |
|---|---|
| 36 slow failures (one every 5 min, 3 h) delivered one per live batch | **22 DET-004 findings** for one campaign |
| Same 36 events delivered in one batch | 1 DET-004 finding |
| 90 fast failures over 30 min, one per batch | 1 DET-001 (campaign shorter than the window) |

Scheduled scans reload 24 hours and are only affected by campaigns longer than 24 hours. Severity: **MEDIUM**, because it floods the queue exactly when an attacker is patient.

## Investigation Workflow

Run on the synthetic demo database (TESTED — SYNTHETIC; triage on real findings deliberately not altered):

| Step | Command / view | Result |
|---|---|---|
| Open finding | `show 8` (COR-001) | severity, confidence with points, risk factors, MITRE, evidence, history |
| Evidence | `timeline 8` | 15 events, 7 marked as evidence |
| Pivot | `events --ip 203.0.113.66` | 7 events (6 failures + success) |
| Investigating | `triage 8 INVESTIGATING --note …` | status and history row written |
| Analyst note | `note 8 …` | stored with timestamp |
| Verdict | `triage 8 TRUE_POSITIVE` | verdict stored |
| Resolve | `triage 8 RESOLVED` | "Status Resolved · Verdict TRUE_POSITIVE" |
| Persistence after rescan | re-import of the same export | 0 new events, 0 new findings; status, verdict, 4 notes and 4 history rows unchanged |
| GUI equivalent | smoke checks "triage update saved in background", "note persists and is shown", "status shows Investigating" | TESTED — AUTOMATED (real window, synthetic data) |

## Process Tree

| Check | Result | Status |
|---|---|---|
| Parent and child, PID, integrity level | `process-tree 8` (demo): `WINWORD.EXE PID 12036 [recorded only]` → `powershell.exe PID 7420 LAB\alice High #8 ◀ selected` | TESTED — SYNTHETIC ⚠ |
| Sysmon ProcessGuid links | "guid" links rendered; GUID is the primary key for parent/child | TESTED — AUTOMATED (8 tests) |
| 4688 PID linking with reuse protection | covered by `test_process_tree.py` (PID reuse with a time bound) | TESTED — AUTOMATED |
| Non-process event | clear error: "A process tree needs a process-creation event (Sysmon 1 or Security 4688)" | TESTED |
| Real data | 14 real 4688 records stored; a real tree was not inspected (GUI page masked to the auditor; see GUI Review) | **NOT TESTED — REAL** |

## Investigation Stories

Tested on **SYNTHETIC** data (demo database, COR-003 #10):

- **Ordering.** Events are listed in time order. 6× failed 4625 (collapsed into one step) → 4624 → Sysmon 1 PowerShell from WINWORD → 4104 → 4720 `support$` → 4732 → Edge process → DNS → file write → Defender 1116 → 1117 ✅.
- **Entities and attribution.** Account `LAB\alice`, host, IPs and SIDs are correct. Each step lists the rules it supports (e.g. "COR-001, COR-003, DET-001") ✅.
- **Explainability.** The story lists related findings with the relation type ("this finding", "shares evidence", "same account, overlapping time"). It has "What the data cannot tell" and next steps ✅.
- **MITRE and risk.** Shown in the GUI story and the report ✅.
- **Over-inclusion risk.** The COR-004 story (an EICAR download through Edge) lists the unrelated brute-force findings (DET-001, COR-001) as "same account, overlapping time". The relation label is honest, but a reader can mistake breadth for causality. **The story does not invent links:** every relation is labelled, and weak links are labelled "weak" ✅.

## Risk Engine

The model (`engine/risk.py`, read in full) is one function applied to every finding. It starts from a base score for severity (LOW 20, MEDIUM 40, HIGH 70, CRITICAL 90) and adds modifiers:

| Modifier | Points |
|---|---|
| LOW confidence | −10 |
| privileged session (4672) | +10 |
| Defender remediated | −15 |
| remediation failed or allowed | +10 |
| file executed | +10 |
| ≥ 2 logs in the chain | +5 |

The result is clamped to 0–100, and the clamp is itself recorded as a factor. Every applied factor is stored in `evidence.risk_factors`. The endpoint score is the highest open finding.

| Check | Observation | Status |
|---|---|---|
| Base by severity | DET-001 40, DET-003 70, DET-005 20 (real) | TESTED — REAL WINDOWS ✅ |
| Confidence modifier | real COR-001 HIGH/LOW → 60 in the app DB (70 − 10) | TESTED — REAL WINDOWS ✅ |
| Privileged-context modifier | `test_privileged_sessions.py` (13 tests) | TESTED — AUTOMATED |
| Defender remediated −15 | demo DET-008 HIGH → 55; COR-004 70 − 15 + 5 = 60 | TESTED — SYNTHETIC |
| Multi-source +5 | demo COR-003 70 + 5 = 75 ("Corroborated by 3 logs (defender, security, sysmon)") | TESTED — SYNTHETIC |
| Caps and bounds | `test_risk.py` (7 tests) | TESTED — AUTOMATED |
| "Not a probability" stated | Overview card: "Prioritization only, not a probability of compromise"; reports: "Findings are leads for investigation, not proof of compromise" | ✅ |
| UI explains the score | Detections detail and report "Why this confidence and risk" table list each factor | TESTED — SYNTHETIC (GUI smoke + report) |

**Double counting (design weakness).**

- **DET-008:** severity is raised to HIGH *because* remediation failed or was allowed, and the same condition adds another +10.
- **COR-004:** severity is raised to HIGH when the file executed or was not remediated, and those conditions add +10 again.
- **COR-003:** a *weak* user-and-time Defender link still earns the +5 "corroborated by N logs" bonus.

None of these breaks the 0–100 bound, but the score is not a sum of independent factors as documented.

There is also no recency or decay factor, and no endpoint-level aggregation: ten MEDIUM findings still produce endpoint risk 40.

## Tuning and Suppression

Tested on throwaway databases (TESTED — SYNTHETIC / AUTOMATED):

| Check | Command | Result |
|---|---|---|
| Disable / enable | `rules disable DET-002 --reason "audit test disable"` | DISABLED shown; audit row `rule.disable` |
| Reason required | reason `x` | "Give a reason (at least 5 characters)" |
| Threshold 0 / 10,001 / `abc` | `rules set DET-001 threshold …` | rejected: "between 1 and 10,000" / argparse int error |
| Window above bound | `window_minutes 99999` | "between 1 and 1,440" |
| Unsupported field | `rules set DET-003 event_id 4625` | "DET-003 has no integer parameter 'event_id' (none)" |
| Unknown rule | `DET-999` | "Unknown rule DET-999." |
| Days bound | `partner_lookback_days 31` | "between 1 and 30" |
| Valid change logged | `threshold 6` | audit `rule.parameter {old 5, new 6, default 5}` with reason |
| Persistence | `rules` in a new CLI process after `disable` | `DET-002 v1.1 DISABLED` shown (stored in `rule_overrides`) |
| Suppression wildcard | `--value "*"` | rejected: "wildcards are not allowed" |
| Suppression reason | `--reason "no"` | rejected |
| Expiry bounds | `--days 400` / `--days 7` | rejected / accepted, expires in 7 days |
| Removal | `suppress remove 1 --reason …` | removed and "kept in the audit history"; audit row `suppression.remove {hits: 0}` |
| Suppression effect on scans | `test_tuning.py` (22 tests) | TESTED — AUTOMATED |

**Safety limitations:**

1. **Too broad.** A suppression without `--rule` applies to **all rules**, including correlations. With no `--days` it never expires. One `source_ip` suppression can therefore hide a later COR-003 chain from that address.
2. **No record of suppressed findings.** They are **not stored at all**; only a hit counter increments. An analyst cannot review what was hidden.
3. **Exact match only.** Values are case-insensitive exact matches, which is safe but makes "this service account on any host" impossible.

## Reporting

`report --finding N` / `--summary` with optional `--redact` writes a self-contained HTML file: no scripts, no external references.

| Check | Result | Status |
|---|---|---|
| Opens as HTML, sections present | header, data-source banner ("Imported event export(s) only…"), findings table, ordered timeline, "Why this confidence and risk", "What the data cannot tell", next steps, MITRE, analyst notes, triage history, footer | TESTED — SYNTHETIC |
| XSS escaping | events with user name `"><script>alert(1)</script><img src=x onerror=alert(2)>` and workstation `<b>WS</b>` → no raw `<script`, no `<img … onerror`, no `<b>`; escaped text present; **0 `<script` tags in the file** | ✅ TESTED |
| Redaction | with `--redact`: `alice`, `WS-LAB01`, `S-1-5-21`, `203.0.113.66`, `LAB\` and `Users\alice` all **absent**, replaced by `USER-1`, `HOST-1`, `DOMAIN-1`, `SID-n`, `IP-n` | ✅ TESTED |
| Not redacted (by design or limitation) | DNS query names (`downloads.example.net`), file names, process paths beyond the user folder, threat names | ⚠ a real DNS name can be personal |

## Privacy and Security

**Current tree (`git ls-files`, 221 files):**

| Check | Result |
|---|---|
| Real host name, owner name, e-mail, `C:\Users\<USER>` path | **0 matches** |
| SIDs | only synthetic (`S-1-5-21-1111111111-…`, `-7777777777-…`, `-1-2-3`) |
| IPs | only RFC 5737 documentation ranges, loopback, `10.0.0.5`, plus one false match (`1.457.160.0` is not an IP) |
| Database, log or `.evtx` files tracked | **none** (`.gitignore` covers `*.db`, `*.log`, `*.bundle`, output files and `docs/screenshots/real-*.png`) |
| Real-machine screenshots (`docs/screenshots/real-*.png`, 6 files) | present on disk, **untracked and ignored** ✅ |
| Tracked screenshots 01–12 and demo-1…5 | host shown as `WORKSTATION`, paths as `%USERPROFILE%`, synthetic accounts; they show this PC's genuine **health state** (not elevated, Sysmon absent), which is not identifying |
| Fixtures | synthetic accounts, documentation IPs |
| Benchmark JSON | no host name ("host name intentionally not recorded") |

**The current tree is safe to publish (privacy).**

**Git history is NOT safe to publish as is.** Screenshots added in commits `1390eb1`, `eff8a1c` and `d3b9be6` (before `815f8cc`, 2026-10-06/07) show the **real computer name** in the window header. This was verified by extracting and viewing `02-overview-findings.png` (from `1390eb1`), `04-timeline.png` (from `eff8a1c`) and `03-detections.png` (from the `d3b9be6` tree). Those blobs are still reachable from `master`. History was not rewritten (per instructions).

**Security review notes:**

- No network code; no `shell=True`.
- SQL is parameterized: all 14 `noqa: S608` sites interpolate only constant column lists or `?` placeholders. A hostile `--ip "1' OR '1'='1"` search returned no rows and no error.
- Event content is never executed.
- PowerShell script text is kept only in the local raw event, and `--text` search deliberately does not cover it.
- The launcher and the exe request elevation only through the standard UAC prompt.

## GUI Review

| Method | Result |
|---|---|
| GUI smoke test, **real window**, non-elevated (11:21 local) | **76/76 PASS** |
| GUI smoke test, offscreen (CI mode) | **76/76 PASS** |
| GUI smoke test, **elevated** (audit run, 14:09 local) | **76/76 PASS** |
| Demo screenshots regenerated during the audit (`demo.py --screenshots`, synthetic) | 5 screenshots, visually inspected: DEMO badge "DEMO - synthetic data, not from this computer", host `WORKSTATION`, Scan/Import/Live disabled |
| Manual inspection of the real GUI on real data | **BLOCKED BY ENVIRONMENT**: the desktop-control tool can only grant installed applications; `MoeSOC.exe` and the venv Python are not installed apps, so their windows were **masked** to the auditor |

The smoke test drives all 9 pages. It covers:

- **Data and states:** empty state, import on a background thread, Scan button disabled while busy, overview counts and risk.
- **Findings:** detection detail with confidence explanation and MITRE, triage, notes, story.
- **Navigation:** timeline with evidence highlighting, IP pivot, evidence drill-down, raw XML viewer, filtered search.
- **Investigation tools:** process tree, Tuning reload, Reports, Settings and retention preview.
- **Live and new sources:** live toggle and stop, live scan "without freezing", DET-007 and DET-008 detail, COR-004 chain.

**Observed from screenshots** (synthetic data):

- **Positive:** the honest health panel; a clear "Last scan Failed" with the access-denied reason.
- **Cramped detail pane:** the right-hand pane is narrow. The COR-004 activity chain wraps words mid-name ("downloads.exam/ple.net", "EventRecordID 20400" on four lines). The detections table needs a horizontal scrollbar at 1440 px.
- **Story density:** the Story page shows a dense table that needs scrolling.
- **Clean otherwise:** no fake values seen. The demo badge and the "Prioritization only" wording are present.

**Responsiveness.**

- Scan, import, search, triage, story and tuning run on worker threads; the smoke checks "live scan finishes without freezing" and "Scan button disabled while busy" passed.
- A real elevated scan inside the GUI was not observed directly, because the window was masked. The equivalent backend scan took 0.36 s on real data.

## CLI Review

All 17 commands are present (`--help`). They were exercised with real or synthetic data:

| Command | Data used |
|---|---|
| `health`, `scan`, `events`, `detections` | real |
| `show`, `triage`, `note`, `timeline`, `process-tree`, `story`, `report`, `suppress`, `rules`, `audit`, `retention`, `import-xml` | synthetic |
| `verify-evidence` | through the same function (`verify_detection_evidence`) on real findings |

Findings:

- **Event filters.** All 19 event filters work SQL-side, with counts:
  - `--event-id 4625` 11
  - `--user alice` 15
  - `--ip 198.51.100` (prefix) 5
  - `--logon-type 3` 12
  - `--parent WINWORD` 1
  - `--file eicar` 3
  - `--dns example` 1
  - `--threat EICAR` 2
  - `--logon-id 0x7a3f21` 4
  - combination `--user alice --event-id 4625 --ip 203.0.113.66`: 6
  - Paging `--limit 5 --offset 0/5/20` returned records #22–18, #17–13 and #2–1 (22 total), with no overlap and no gap.
- **`--text` scope.** `--text DownloadString` found nothing: `--text` searches normalized fields, not script content (intentional for privacy, but surprising to an analyst).
- **Broken pipe.** Piping output into `head` produces a **`BrokenPipeError` traceback** (`events`, `show`, `detections`, `timeline`) (Bug A-5, cosmetic).
- **Clear errors.** Wrong IDs and invalid input give readable messages, not tracebacks.

## Launcher Review

`Start MoeSOC.bat` → `launcher\MoeSOC.vbs` (wscript, so no console window) → `launcher\launch_moesoc.py` (pythonw): preflight check, UAC, single-instance mutex, log.

| Check | Evidence | Status |
|---|---|---|
| Normal start + UAC approval | `launcher.log` (51 lines): "Elevation requested through UAC; elevated launcher takes over" → "MoeSOC started (pid …)", 8 times on 2026-10-06…08 | **TESTED — REAL WINDOWS ✅** (historical log, owner's real use) |
| UAC rejection | log: "UAC prompt was declined or timed out; nothing started" (3×) and "UAC prompt was cancelled by the user; nothing started" | TESTED — REAL WINDOWS ✅ |
| Single instance | log: "MoeSOC is already running" (2026-10-06 20:03) | TESTED — REAL WINDOWS ✅ |
| Missing environment | VBS shows "MoeSOC environment is not installed" and offers setup; preflight unit tests | TESTED — AUTOMATED (15 launcher tests); not re-run on real Windows (would require removing the venv) |
| Launcher log | `%LOCALAPPDATA%\MoeSOC\logs\launcher.log`, rotating 256 KB × 3 | ✅ observed |
| No persistent console | wscript + pythonw | design verified; not observed (window masked) |

**Inconsistency:** if the user declines UAC, the **launcher starts nothing**, but **MoeSOC.exe opens in limited mode** (`frozen.decide`). The README describes the exe behaviour only.

## Packaging Review

| Check | Result | Status |
|---|---|---|
| PyInstaller one-folder build exists | `dist\MoeSOC\MoeSOC.exe` | ✅ |
| `MoeSOC.exe --self-test` (non-elevated, 11:23 local, `ci_local.bat`) | exit 0. PASS version (`MoeSOC 1.0.0, Python 3.13.15, frozen=True`), PASS rules (12), PASS database (schema v8), PASS icon (MoeSOC.ico 40,276 bytes), PASS pywin32 win32evtlog, PASS GUI (main window with 9 pages, offscreen). **SELF-TEST: PASSED** | **TESTED — REAL WINDOWS ✅** |
| Normal start, icon in the taskbar, pages visible | window opened during the audit run but was **masked** to the auditor | **NOT TESTED** (visual) |
| Second instance of the exe | `frozen.decide` logic: 9 unit tests (TESTED — AUTOMATED). The audit's real exe test step failed because of a quoting error **in the audit script itself** (not MoeSOC) | **BLOCKED BY USER INTERACTION** for the exe (a fixed script, `audit\audit_exe.bat`, is ready); the same single-instance mutex is proven for the launcher path by the real log |
| Installer `MoeSOC-Setup-x64.exe` | `packaging/MoeSOC.iss` exists (admin install, uninstall keeps `%LOCALAPPDATA%\MoeSOC` data); ISCC not found in any standard path | **BLOCKED BY ENVIRONMENT — INNO SETUP NOT INSTALLED** |
| Code signing | none | NOT DONE (expect SmartScreen warnings) |
| Checksums | generated only by the CI `build` job (never run) | NOT DONE |

## CI Review

`.github/workflows/ci.yml` parses as YAML, with jobs `test` and `build`:

- **`test`** (`windows-latest`): Ruff, pytest, CLI scan of the runner's logs, GUI smoke (offscreen), screenshot artifact.
- **`build`**: PyInstaller, exe self-test (fails the job on a non-zero exit), optional Inno Setup, zip + SHA256SUMS, artifact upload.

The workflow is read-only (`permissions: contents: read`), with concurrency cancel. Actions are pinned to major versions (`@v4`/`@v5`), not to SHAs.

| Check | Result | Status |
|---|---|---|
| Local mirror (`scripts\ci_local.bat`, 11:23 local) | Ruff clean; **451 passed, 1 skipped**; CLI ok; offscreen smoke 76/76; exe self-test PASSED; no "STEP FAILED" lines | TESTED — REAL WINDOWS ✅ |
| GitHub Actions | no remote, never pushed | **GITHUB CI NOT ACTUALLY RUN** |

Caveat for the first real run: the `test` job reads the runner's real Security log and uploads GUI screenshots as artifacts. The screenshots are redacted, but the artifacts would still be visible to anyone who can see the repository.

## Test Results

| Run | Where | Collected | Passed | Failed | Skipped | Duration |
|---|---|---|---|---|---|---|
| pytest #1 | Linux sandbox | 452 | 450 | 0 | 2 (Windows-only) | 11.49 s |
| pytest #2 (repeat, nondeterminism check) | Linux sandbox | 452 | 450 | 0 | 2 | 11.25 s |
| pytest #3 (repeat) | Linux sandbox | 452 | 450 | 0 | 2 | 11.65 s |
| `verify_windows.bat` | Windows, **non-elevated**, 11:21 local | 452 | 451 | 0 | 1 (Security log access correctly denied) | 13.15 s |
| `ci_local.bat` | Windows, non-elevated, 11:23 local | 452 | 451 | 0 | 1 | 12.38 s |
| audit run | Windows, **elevated**, 14:08 local | 452 | **452** | 0 | 0 | 13.82 s |
| GUI smoke (real window / offscreen / elevated) | Windows | 76 checks | 76 / 76 / 76 | 0 | — | — |

Slowest tests (elevated): `test_ten_thousand_events_search_and_detect` 2.16 s and `test_internal_from_imports_resolve` 1.24 s; everything else ≤ 0.16 s. Across 6 full runs there were **no flaky tests**.

Test distribution: 452 tests in 42 modules. The largest are domains 25, account management 25, identity 23, tuning 22 and low-and-slow 20. **Only 2 tests touch the real Windows Event Log**, and both are for the Security/Application channels. No test reads a real Sysmon, PowerShell or Defender channel.

### Ruff

| Where | Version | Lint | Format | Errors | Warnings |
|---|---|---|---|---|---|
| Linux sandbox | 0.16.8 | All checks passed | 144 files already formatted | 0 | 0 |
| Windows, elevated audit run | 0.16.10 | All checks passed | 143 files already formatted (audit kit excluded) | 0 | 0 |

The 144 vs 143 file count reflects the two checkouts' different untracked contents; both were clean.

## Windows Integration Results

| Test | Standard user | Administrator |
|---|---|---|
| `test_application_log_is_readable` | PASSED | PASSED |
| `test_security_log_scan_or_clear_access_error` | SKIPPED, with the correct "Not elevated: access correctly reported as denied" | **PASSED** (real read) |
| CLI `scan` | exit code 2, "Access denied … Run MoeSOC with administrator privileges" | 1,269 records read, 0 parse failures (copy DB) |
| Health | Admin Limited; Security Unavailable; Sysmon Unavailable; PowerShell Limited; Defender Available; DB Available (v8) | Admin Available; **Security Available**; rest unchanged |
| GUI smoke | 76/76 | 76/76 |

Administrator runs used the normal UAC prompt, approved by the owner during the audit (no bypass).

## Real-Telemetry Validation

> **REAL WINDOWS TELEMETRY.** Everything in this section came from the test PC's own event logs.

### Existing real findings

From the application database and `.verify-data`, all evidence from the local host. Identifiers are omitted; all four were produced by the owner's deliberate test logons with a dedicated local test account on 2026-10-07.

| # | Rule | Event type | Severity | Confidence | Risk | Evidence | Timeline (UTC) | Evidence re-verified today |
|---|---|---|---|---|---|---|---|---|
| R1 | DET-001 | 8 × 4625, interactive, source loopback, "Account does not exist" | MEDIUM | MEDIUM | 40 | 8 | 2026-10-07 14:57:02 → 14:58:18 | **8/8 verified** |
| R2 | DET-001 | 7 × 4625, interactive, loopback, "Incorrect password" (identity basis: SID) | MEDIUM | MEDIUM | 40 | 7 | 15:01:34 → 15:01:51 | **7/7 verified** |
| R3 | COR-001 | 7 × 4625 + 1 × 4624 (same SID) | HIGH | **LOW** (local interactive success, no remote address) | 60 (app DB) / 70 (older copy, Bug A-7) | 8 | 15:01:34 → 15:02:03 | **8/8 verified** |
| R4 | DET-005 | 1 × 4720 (test account created) | LOW | HIGH | 20 | 1 | 15:01:00 | **1/1 verified** |

The evidence verification used MoeSOC's own `verify_detection_evidence` against the live Security log, elevated: **24 verified, 0 missing, 0 mismatch, 0 log rolled or cleared, 0 other failures.** The oldest record in the live log (552,669) is still below every evidence record. The 20 MB log holds about 25,000 records, so this evidence will roll off within days on a normally busy PC; **after that, verification will (correctly) report MISSING.**

### Real negatives (also evidence)

- **4104:** 41 real script blocks collected and parsed, 0 DET-007 findings.
- **4672:** 9 records stored as privileged-session context; the SYSTEM noise filter is active (684 of 1,269 records kept).
- **4688:** 14 records parsed.
- **4732:** 1 real record, **no DET-006**. The diagnostic below shows the group.
- **Defender:** 0 events, so DET-008 had nothing to see. That is a correct non-finding, not a validation.

The group of the real 4732 record was not extracted, because the diagnostic that reads it was blocked as described above. The test account was created with `net user … /add`, which adds new accounts to *Users* (S-1-5-32-545, not privileged), so no DET-006 is the expected result. This is an inference, **not verified**.

## Synthetic-Only Validation

> **SYNTHETIC / FIXTURE TELEMETRY.** Nothing in this section has been observed on a real machine.

| Component | Synthetic evidence | Why not real |
|---|---|---|
| DET-002 Password Spray | fixtures + demo (5 accounts from 198.51.100.23) | needs failures for ≥5 accounts from one source |
| DET-003 Log Cleared | fixtures + demo | clearing the Security log is destructive (not done) |
| DET-004 Low-and-Slow | 20 tests + live probe (which **failed** with duplicates) | needs ≥10 failures over an hour |
| DET-006 / COR-002 | fixtures + demo (`support$` → Administrators, localized "Administratoren") | needs a test account added to Administrators |
| DET-007 positive | demo: Word → `powershell -enc`, download cradle, score 8 | Script Block Logging off; a real suspicious script was not run |
| DET-008 | fixtures + demo EICAR 1116 → 1117 Quarantine | needs the EICAR test (not approved) |
| COR-003 | demo chain across 3 logs | depends on DET-006/007/Sysmon |
| COR-004 | demo Edge → DNS → file → 1116 → 1117 | **Sysmon not installed** |
| Sysmon 1/3/11/13/22 parsing and process tree with GUIDs | fixtures | Sysmon not installed (not installed by policy) |
| Live ingestion of findings | `ingest_live` probes | the subscription delivered nothing during the audit |

## Performance Benchmarks

Measured on the Windows test PC during the audit (`audit_bench.py` runs `scripts/benchmark.py` once per size in a fresh process). The data is synthetic, generated in memory. These are real timings.

| Events | Parse s | Store s | Detect s | Total (parse + store + detect) s | Search s | Story s | Report s | Findings | DB MB | KB/event |
|---|---|---|---|---|---|---|---|---|---|---|
| 1,000 | 0.05 | 0.04 | 0.06 | 0.15 | 0.015 | 0.002 | 0.002 | 2 | 1.9 | 1.9 |
| 10,000 | 0.50 | 0.35 | 0.57 | 1.42 | 0.057 | 0.003 | 0.003 | 10 | 17.6 | 1.8 |
| 50,000 | 2.55 | 2.48 | 3.28 | 8.31 | 0.268 | 0.005 | 0.006 | 50 | 87.7 | 1.8 |
| 100,000 | 5.23 | 5.87 | 7.39 | **18.49** | 0.417 | 0.008 | 0.008 | 104 | 176.0 | 1.8 |

Scaling is roughly linear: about 5,400 events/s end-to-end at 100k. Throughput for the real scan was **1,269 records in 0.36 s** (incremental scans 0.23–0.24 s).

Memory: **NOT TESTED**. The audit's peak-working-set probe passed a truncated process handle and recorded 0.0 MB, which is a defect in the audit script, not MoeSOC. The corrected probe (`audit_exe.bat`) could not be run (same blocked window). At 100k events the database file is 176 MB; process memory is unmeasured.

Context: the default per-scan budget is 50,000 events and the look-back 24 hours, so a full first scan of a busy log costs about 8 s. Detection re-runs over the reload window on every live batch (≈ 70 min of events).

## Bugs Found During Audit

Probe scripts are described in *Appendix: audit method*. None of these bugs prevented the audit, and no product code was changed, as the owner instructed.

| ID | Severity | Area | Defect | Reproduction / evidence |
|---|---|---|---|---|
| **A-1** | **MEDIUM** | Detection storage, live mode | One long campaign produces **many duplicate findings**. Finding identity is the first record of the burst, and live batches reload only about 70 min of events | 36 failures, one every 5 min, one per `ingest_live` batch → **22 DET-004 findings**; the same events in one batch → 1 |
| **A-2** | **MEDIUM** | Identity | The 4625 `TargetDomainName` is client-supplied, and empty vs host-name domains give different keys. One account splits into several identities: **DET-001 evaded**, DET-002 misfires as a spray | 6 failures for `alice` with domains LAB, x1…x5 → only DET-002; alternating empty/host domain → no finding |
| **A-3** | **MEDIUM** | Evidence integrity | `verify-evidence` parses every record with `parse_security_xml`. **Genuine, unchanged Sysmon, PowerShell and Defender evidence is reported as `mismatch`** (a false tamper signal) | stub reader returning the identical XML: DET-007 2/2 mismatch, DET-008 2/2, COR-004 5/5, COR-003 2 of 11; Security-only rules verified |
| **A-4** | **MEDIUM (unconfirmed)** | Live monitoring | Real-time delivery not demonstrated (0 batches in 36 s, although the generated logons may not have produced matching records); the subscription signal is auto-reset and initially non-signalled, so the backlog is not drained at start | real elevated run; code read |
| A-5 | LOW | CLI | `BrokenPipeError` traceback when output is piped into `head` | `events \| head -1` |
| A-6 | LOW | CLI display | COR-004 `show` prints an empty `MITRE:` line, although the evidence has `related_techniques: ['T1105']` | `show 11` (demo) |
| A-7 | LOW | Risk consistency | Findings from older rule versions keep pre-risk-model scores; the same real COR-001 shows 70 in one DB and 60 in another | real databases |
| A-8 | LOW | Risk model | Double counting (DET-008/COR-004 severity and modifier from the same condition); a weak user-and-time link earns the corroboration bonus | code + demo COR-003 |
| A-9 | LOW | Launcher vs exe | Declining UAC: the launcher starts nothing, the exe opens in limited mode | launcher log vs `frozen.decide` |
| A-10 | LOW | Docs / metadata | `pyproject.toml` says `license = MIT` but **no LICENSE file** exists; `docs/benchmarks/*.json` record `"moesoc": "0.2.0"`; README "verified on Windows 11" reads broader than the evidence (only DET-001, DET-005 and COR-001 have real positives) | file inspection |
| A-11 | LOW | Unicode identity | `casefold` merges `Straße` and `STRASSE`, which Windows treats as different names | identity probe |

## Bugs Fixed During Audit

**None.** The owner's instruction for this audit was "Do not modify product code … only test, inspect, analyze and report", and no defect blocked a test from running.

One defect was in the **audit's own script**: an unescaped parenthesis in `audit_run.bat` broke the exe second-instance step. It was fixed in a separate non-elevated script, `audit_exe.bat`. The audit scripts live outside the repository, in the PC folder `audit\`, and are not part of MoeSOC.

## Known Limitations

- **Single host.** Data stays local; there is no fleet view or central collection.
- **Live monitoring is Security-only.** The other three sources arrive only through scans or catch-up.
- **Persistence and lateral movement are not covered:**
  - no service install (7045/4697), scheduled task (4698), Run-key rule, WMI or RDP-session events;
  - Sysmon 13 registry events are collected but not used by any rule;
  - Security events 4648, 4728/4756 (global and universal group additions) and 4738/4724 are not collected.
- **Telemetry depends on Windows configuration.** DET-007 needs Script Block Logging for full coverage. COR-004, the network/DNS context and GUID process trees need Sysmon. 4688 needs process auditing (enabled on this PC: 42 records in the log).
- **Short evidence life.** The 20 MB default Security log keeps about 25,000 records here, so evidence verification works only for a few days.
- **`--text` search** does not include PowerShell script content.
- **Suppressions** can be global and permanent; suppressed matches are not stored.
- **No code signing, no installer.**

## Manual Validation Still Required

Each item is added to `docs/manual_validation_queue.md` (section *Final independent audit*).

| # | Item | Why manual | Status |
|---|---|---|---|
| M1 | Real brute force → DET-001 / COR-001 from **another machine** (network logon type 3) | needs a second device; loopback `net use` did not produce the expected 4625 records | MANUAL VALIDATION REQUIRED |
| M2 | Real DET-006 / COR-002 (test account added to Administrators, then removed) | changes local group membership; owner's decision | MANUAL VALIDATION REQUIRED |
| M3 | Real live-monitoring delivery: start Live in the GUI (elevated), then lock the screen and type a wrong password 3× | interactive logon events | MANUAL VALIDATION REQUIRED |
| M4 | Enable Script Block Logging (owner decision), run a harmless test script with a download-cradle string that is never executed, confirm DET-007 | policy change | BLOCKED BY USER INTERACTION — REAL 4104 VALIDATION BLOCKED — SCRIPT BLOCK LOGGING DISABLED |
| M5 | EICAR test file → Defender 1116/1117 → DET-008 | needs explicit approval | REAL DEFENDER DETECTION VALIDATION PENDING |
| M6 | Install Sysmon with a reviewed config (owner decision) → COR-004, Sysmon process trees | software install | NOT AVAILABLE ON TEST MACHINE |
| M7 | Visual GUI review of all pages with real data, and an elevated scan from the GUI | window masked to the auditor's tooling | MANUAL VALIDATION REQUIRED |
| M8 | Inno Setup install → build and test `MoeSOC-Setup-x64.exe` (install, start, uninstall keeps data) | software install | BLOCKED BY ENVIRONMENT |
| M9 | First GitHub Actions run | no remote | BLOCKED BY ENVIRONMENT |

## Release Readiness

| Prerequisite | State | Notes |
|---|---|---|
| Clean git tree | **READY** | clean at the audit start; this audit adds 3 docs + queue update + 5 screenshots in one commit |
| Version consistency | **READY** | 1.0.0 in package, pyproject, ISS, exe self-test |
| Tag | **PARTIAL** | `v1.0.0` exists locally; it points to the pre-audit commit and was not pushed |
| README | **PARTIAL** | accurate in detail; headline "verified on Windows 11" overstates validation; no known-bugs section |
| CHANGELOG | **READY** | present for 1.0.0 |
| License | **NOT DONE** | no LICENSE file (pyproject claims MIT) |
| Installer | **BLOCKED** | Inno Setup not installed |
| Checksums | **NOT DONE** | only generated by CI, which has never run |
| Release notes | **READY** | `docs/release/v1.0.0.md` |
| Privacy, current tree | **READY** | no identifiers found |
| Privacy, git history | **BLOCKED** | old screenshots show the real computer name; history rewrite or a fresh repository needed |
| CI | **PARTIAL** | workflow present; local mirror passes; **never run on GitHub** |
| Demo | **READY** | `scripts\demo.bat`, labelled synthetic, regenerated during the audit (22 events → 11 findings) |
| Screenshots | **READY** | redacted; real ones ignored |
| Known critical bugs | **PARTIAL** | A-1…A-4 open (MEDIUM) |

**Is the installer or release actually ready?** No:

- There is no installer.
- No release has been published.
- No CI run exists.
- The license is missing.
- The history needs cleaning.

The **portable build** (`MoeSOC.exe` one-folder) is technically ready: self-test PASSED.

## Portfolio Review

Reviewed as a SOC hiring manager would read the repository.

**What will impress:**

- The **honesty discipline** is rare in student projects. "Not proof of compromise", confidence factors that can go *negative*, "What the data cannot tell", labelled synthetic demo, real-vs-fixture separation in the docs.
- **Windows depth** beyond the usual 4625 counter:
  - logon types, NULL SID handling, sub-status reasons;
  - localized group names solved with well-known SIDs;
  - 4672 noise filtering and separate budgets for 4688;
  - EventRecordID watermarks with rollover recovery;
  - Defender Detection-ID joins and ProcessGuid linking.
- **Engineering quality:** 452 passing tests, clean lint, transactional migrations, auditable tuning, a working packaged exe.

**What a sharp interviewer will find:**

- **Validation gaps.** Only 3 of 12 rules have ever fired on real data, and all three come from the owner's own lock-screen typos.
- **Bugs A-1 and A-2**, the classic weaknesses of brute-force detection: duplicate alert floods, and identity normalization on an attacker-controlled field.
- **Live monitoring** that has not been shown to receive an event.
- **No persistence detections** at all, in an endpoint tool.

## Scores

Scored 0–10 against "junior SOC / detection-engineering portfolio project", not against commercial EDR.

| Area | Score | Reason |
|---|---|---|
| Architecture | **8** | Clean layering (collector → parser → normalized event → storage → engine → presentation), centralized SQL, shared services for CLI and GUI. Minus: hard-coded rule wiring, sliding-window finding identity (A-1), Security-only live path |
| Windows knowledge | **8** | Logon types, NULL SID, sub-status, well-known SIDs, localized groups, 4672 noise, record-ID watermarks, EvtQuery/EvtSubscribe, UAC. Minus: misses 4648/4728/7045/4698; client-controlled domain field not handled (A-2) |
| Detection engineering | **6** | Explainable, tuned and documented, with FP lists and confidence logic. Minus: 3/12 real positives, mostly authentication rules, no persistence/lateral detections, evasion via the domain field |
| Correlation | **6** | Correct join keys with labelled link strength (logon ID, GUID, file path, Detection ID). Minus: COR-003/004 never seen on real data; COR-004 impossible on the test PC; weak links can raise risk |
| Investigation workflow | **8** | Triage states, verdicts, notes, history, timeline, pivots, stories, process tree, evidence re-verification; persistence verified. Minus: story over-inclusion; verification false alarm on non-Security evidence (A-3) |
| Testing | **7** | 452 tests, deterministic over 6 runs, migrations, XSS, GUI smoke with 76 checks. Minus: only 2 real-log tests; missed A-1/A-2/A-3, all of which needed only simple probes |
| Code quality | **8** | Ruff clean, typed dataclasses, readable, no dead features found. Minus: rule-specific GUI strings, CLI broken pipe |
| Security / privacy | **7** | Observe-only, no network, parameterized SQL, escaped reports, redaction, ignored real screenshots. Minus: **identifying screenshots in git history**, global permanent suppressions, unredacted DNS names in redacted reports |
| UI/UX | **6** | Honest status, demo badge, responsive (background threads, 76 checks). Minus: cramped detail pane and wrapped chain text, horizontal scroll at 1440 px; a real-data visual review was not possible in this audit |
| Documentation | **8** | Extensive and mostly accurate (validation, detections, collection, manual queue, learning notes). Minus: headline overstatement, LICENSE missing, stale benchmark version string |
| Real-world validation | **3** | Real Security collection, incremental scans and evidence verification are proven; real positives exist for 3 rules only, and live delivery and three of the four sources are unproven |
| Packaging | **5** | Exe builds and self-tests. Minus: no installer, no signing, no checksums, UAC behaviour differs between launcher and exe |
| **Portfolio value** | **7** | Clearly above the typical "log parser" project, with thoughtful SOC reasoning. It becomes an 8–9 once the real-validation and A-1/A-2 gaps are closed and the history is cleaned |

## Top Strengths

1. **Explainability everywhere.** Confidence points, risk factors, link strengths and "what the data cannot tell" are stored with each finding and shown in GUI, CLI and reports.
2. **Reliable real Security-log collection.** 0 parse failures on 1,269 real records, incremental watermarks, 0 duplicates, real evidence re-verified 24/24.
3. **Disciplined honesty about data provenance.** Synthetic demo is isolated and badged; docs separate real from fixture.
4. **Engineering hygiene.** 452 deterministic tests, clean lint, safe migrations v1→v8, parameterized SQL, XSS-safe reports.
5. **Analyst workflow depth.** Triage, verdicts, notes, history, timelines, pivots, stories, process trees, auditable tuning.

## Top Weaknesses

1. **Real-world validation is thin.** 9 of 12 rules have never fired on real telemetry, Sysmon and Defender are 0% real, and Script Block Logging is off.
2. **Duplicate-finding flood** in live mode for long campaigns (A-1).
3. **Identity split** on the attacker-controlled 4625 domain field (A-2), which evades DET-001.
4. **Live monitoring not shown to deliver events** (A-4); the evidence check gives false alarms on non-Security evidence (A-3).
5. **Release hygiene.** Identifying screenshots in history, no LICENSE file, no installer, CI never run.

## Recommended Next Actions

In order:

1. **Clean the history.** Start a fresh public repository from the current tree, or rewrite history to drop the pre-`815f8cc` screenshots. Add a `LICENSE` file.
2. **Fix A-1.** Give findings a stable identity that survives the window: extend an open finding for the same rule, identity and source when the new burst overlaps or adjoins it. Add a regression test that replays the 36-batch probe.
3. **Fix A-2.** Key 4625 failures on the user name scoped to the host for non-domain logons (or add a username-only DET-001 pass), and record the claimed domains as evidence. Add tests for empty and varied domains.
4. **Fix A-3.** Dispatch verification through `parse_any_xml`. Add tests with Sysmon, PowerShell and Defender evidence.
5. **Prove live monitoring.** Signal-initialized subscription or an initial drain, plus one real test (M3).
6. **Real positives** for DET-006/COR-002 (M2), DET-007 (M4), DET-008 (M5), and Sysmon + COR-004 (M6). Record them in `docs/validation.md` with sanitized evidence.
7. Run GitHub Actions once; publish a checksum-signed portable zip; build the installer if Inno Setup is added.

## Final Verdict

**Audit status: completed**, with the blocked and manual items listed above.

MoeSOC v1.0.0 is a **careful, honest and well-engineered** single-host Windows detection console:

- Its Security-log pipeline, storage, investigation workflow, tuning, reporting and packaging behave as documented on real Windows.
- Its claims are generally truthful, and it labels synthetic data clearly.

Its **detection credibility is not yet at "v1.0" level**:

- Only authentication and account-creation logic has seen real positives.
- Live monitoring has not been shown to receive an event.
- Three MEDIUM defects (A-1, A-2, A-3) sit in exactly the areas a SOC reviewer probes first.

| Question | Answer |
|---|---|
| Ready for GitHub? | **Not yet**: clean the history and add a LICENSE first (hours of work) |
| Ready for a junior SOC portfolio / CV? | **Yes**, after the history clean-up, provided it is described honestly ("validated on real Security-log authentication events; Sysmon/Defender paths verified on synthetic data") |
| Is the installer/release ready? | **No.** The portable exe is ready; installer, CI run, checksums and published release are not |

---

### Appendix: audit method and artifacts

- **Sandbox** (`/tmp/.../scratchpad/audit`, not in the repository):
  - `probe_identity.py`, `probe_engine.py`: identity keys, domain split, live-ingest duplicates.
  - `probe_report.py`: XSS.
  - `probe_ret.py`: retention 7/30/90.
  - `probe_mig.py`: v1–v7 → v8.
  - `probe_verify.py`: evidence verification per source.
- **PC** (`<project>\audit\`, outside git, outputs sanitized):
  - `audit_run.bat` (elevated, one UAC prompt) with `audit_collect.py` and `audit_bench.py`.
  - `audit_live_diag.bat` (non-elevated subscription diagnostic).
  - `audit_exe.bat` (non-elevated exe checks).
  - Outputs in `audit\out\`. The scan database `audit\out\scan-copy\moesoc.db` contains **real** events and must not be published.
- **Retention tested on a synthetic database:**
  - Events aged 100, 40, 20 and 3 days.
  - **Preview deletes nothing.** 7 days: 6 deletable, 6 kept as evidence. 30 days: 3 deletable, 6 kept. 90 days: 3 deletable.
  - **Apply needs consent.** `--apply` without `--yes` is refused; `--apply --yes` deleted exactly 3 events (15 → 12).
  - Windows logs are untouched; the code only issues `DELETE` on MoeSOC tables.
- **New sanitized screenshots** (synthetic demo, regenerated on the PC during the audit): `docs/screenshots/audit/demo-*.png` (identical copies are published as `docs/screenshots/demo/demo-*.png`).
