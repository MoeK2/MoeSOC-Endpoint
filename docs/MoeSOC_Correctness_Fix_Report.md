# MoeSOC Correctness Fix Report

Session: Oct 9–10, 2026. Scope: fix and prove audit defects A-1 to A-4, then the low-risk items A-5 to A-11. No new detections, telemetry sources, GUI features or scope changes. Nothing was published or pushed, and no history was rewritten.

Status labels: TESTED — REAL WINDOWS, TESTED — AUTOMATED, TESTED — SYNTHETIC, PARTIALLY TESTED, NOT TESTED, BLOCKED.

## Baseline

| Item | Value |
|---|---|
| Starting commit | `a01cc7d` (docs: final independent validation audit), on top of tag `v1.0.0` (`62ca492`) |
| Working tree | clean |
| Ruff | clean |
| pytest, Linux | 450 passed, 2 skipped (452 collected) |
| pytest, Windows | 451 passed + 1 skipped (non-elevated); 452 passed (elevated) |
| GUI smoke | 76/76 |
| Schema | v8 |

The four code paths inspected were:

- `engine/rules.py` `build_detection` and `storage/repository.py` `upsert` (A-1);
- `core/identity.py` and `core/domains.py` (A-2);
- `engine/validation.py` (A-3);
- `collectors/subscription.py` and `engine/live.py` (A-4).

A-1, A-2 and A-3 were reproduced with the audit probes before any change. The before and after numbers below come from the same probe run against a worktree of `a01cc7d` and against `HEAD`.

## A-1 Duplicate Findings

### Reproduction Before

The probe sent 36 failed logons for one account, one every 5 minutes for 3 hours, as one event per `ingest_live` batch. It produced **22 DET-004 findings**. The same 36 events in one batch produced 1 finding.

### Root Cause

The dedup key was `rule|host|first record of the visible burst`. Live detection reloads only the rule window, about 70 minutes of stored events. As the window slides, the oldest visible event changes, so the key changes and a new finding is created.

### Fix

Burst rules (DET-001, DET-002, DET-004) attach a **campaign key** to each detection: `identity:<resolved account>` or `source:<ip|workstation>`, plus the mode. They also attach a **continuation gap**, which equals the rule window. `DetectionRepository.upsert` then works as follows:

1. **Same dedup key, same rule version** → extend that finding.
2. **Otherwise, a stored finding with the same rule, rule version, host and campaign key whose time range overlaps or lies within the gap** → extend it.
3. **Otherwise** → create a new finding.

Extending a finding works as follows:

- first_seen keeps the earliest time and last_seen takes the newest.
- Evidence links become the union, with each event linked once.
- Severity, confidence, risk and evidence are refreshed.
- **Status, verdict, notes and history are never touched.**

Detection reloads stored events from the first event of any still-active campaign, capped at 24 h, so the anchor and the evidence stay complete. DET-004 source mode got its own dedup key, because it could share an anchor with identity mode and overwrite that finding (found by the new tests).

A rule-version change still starts a new finding and leaves the old one as it was. There was no schema change: the campaign key is stored in the evidence JSON.

### Tests

`tests/test_campaign_continuity.py`: **9 tests, all passed.**

1. The audit reproduction (36 events, one per batch) gives 1 finding.
2. The same 36 events in one batch give 1 finding.
3. Two campaigns separated by a quiet gap give 2 findings.
4. Repeated ingestion adds no finding and no duplicated evidence.
5. Out-of-order arrival extends the same finding.
6. The scheduled import path still gives 1 finding.
7. DET-001 long live brute force gives 1 finding, and separate bursts stay separate.
8. Different accounts are never merged into one campaign.
9. Triage status, verdict, notes and history survive extension.

### Result

Audit probe D: **22 findings before → 1 after.** Probe E (one batch) gives 1 finding before and after. **Status: TESTED — AUTOMATED / SYNTHETIC.** There is no real long-running campaign on the test PC.

## A-2 Identity Split

### Reproduction Before

The probe sent six 4625 events for `alice` with the claimed domains LAB, x1, x2, x3, x4 and x5:

- DET-001 did **not** fire.
- DET-002 reported a password spray against several "accounts".

Mixing an empty domain with the host name also gave **no** DET-001, because `host:` and `acct:` keys split.

### Root Cause

In Event 4625, `TargetDomainName` is whatever the client sent. The identity key used it directly, so each claimed domain became a separate identity. DET-002 counted distinct identity keys.

### Security Impact

This was an evasion path for an attacker. Varying a free-text field hid a brute force from DET-001, and it made a single-account attack look like a spray, which misleads triage.

### Fix

The **claimed** domain is kept separate from the **resolved** identity authority. A failed logon without a usable SID resolves as follows:

- An empty domain, `.`, `-`, or the computer's own name (NetBIOS or FQDN) resolves to the **local account** (host + user).
- A **verified** authority resolves to `DOMAIN\user`. A domain counts as verified when it was seen with an account SID or in a successful 4624, or when this computer's own configuration names it.
- An unverified claim on a computer **proven standalone** resolves to the local account. A computer counts as standalone when every account SID seen on it belongs to its own SAM and no Entra ID account was seen, or when its own configuration says it is not domain-joined.
- Otherwise the identity stays as claimed. Accounts are never merged on the user name alone.

The following still hold:

- A reliable SID wins over any claimed domain.
- Two verified domains with the same user name (`CORP\admin`, `OTHER\admin`) stay separate.
- FQDN and NetBIOS forms merge only with SID proof.

The claimed domain, the resolution and whether the claim was verified are stored in the evidence. DET-001 and DET-004 list `claimed_domains`. DET-002 and DET-004 source mode count *account candidates*, so one user name under several unverified domains counts as one account.

A-11, done later, changed name folding from `casefold` to Windows-style simple uppercase mapping.

### Tests

`tests/test_failed_logon_identity.py`: **18 tests, all passed.** They cover:

- the exact audit probe, three ways: a standalone host, local-SID evidence, and the scanner with local configuration. In each, DET-001 fires and there is no spray;
- empty, `.`, `-` and host-name domains, which give one identity;
- the computer's FQDN, which resolves to the local account;
- arbitrary domains, which merge only with standalone evidence;
- unknown authority, where claims stay apart but the spray count is not inflated;
- two verified domains, which stay separate;
- a verified domain, which never merges with an unverified claim;
- a domain member, which is never treated as standalone;
- Entra ID accounts, which prevent standalone resolution;
- NetBIOS vs FQDN, which merge only with SID proof;
- standalone facts, which apply only to their own computer;
- a reliable SID, which wins;
- local failures, which link to the local success SID.

The following are covered in `tests/test_identity.py`, `tests/test_password_spray.py` and the existing identity tests:

- NULL SID;
- name → SID upgrade;
- machine accounts and SYSTEM;
- Unicode and case (including `Straße` ≠ `STRASSE`).

### Result

| Probe | Before | After |
|---|---|---|
| B: same user, varied domains, no authority evidence | false DET-002 "spray" | no false spray. DET-001 does not fire (unknown authority: no guessing) |
| B on a standalone computer (regression tests) | DET-001 evaded | **DET-001 fires, no DET-002** |
| C: empty / host-name domain mix | no finding (split) | **DET-001 fires** |

**Status: TESTED — AUTOMATED / SYNTHETIC.**

## A-3 Evidence Verification

### Reproduction Before

A stub reader returned unchanged XML for Sysmon, PowerShell 4104 and Defender evidence (DET-007, DET-008, COR-003, COR-004). The result was **mismatch** for every non-Security record.

### Root Cause

`verify_detection_evidence` re-parsed every live record with `parse_security_xml`. For Security records it compared only the event ID, record ID and time.

### Fix

Each record is re-read from its own channel. Both the live XML and the stored raw XML are normalized by `parse_any_xml`, the same dispatcher the collectors use.

**Comparison strategy:**

- Every field of the normalized event is compared except the raw XML text. That covers hostname, channel, record ID, event ID, timestamp and the source-specific canonical fields (accounts, process, command line, script block hash, threat fields and so on).
- So a re-rendered event that differs only in white space **verifies**, while any changed value is a **mismatch**. The mismatch names the fields that differ, never their values.

The statuses are:

| Status | Meaning |
|---|---|
| verified | every compared field matches |
| mismatch | a value differs, the record came from another channel, or a record ID was reused |
| missing | the record rolled out of the log, or the channel was removed |
| unreadable (new) | access denied, or malformed live XML; reported clearly instead of crashing |
| not_local | as before |

### Tests by Source

`tests/test_evidence_sources.py`: **23 tests, all passed.** They are parametrized over real-shaped fixtures for Security 4625, Sysmon, PowerShell 4104 and Defender:

- unchanged → verified;
- re-rendered white space → verified;
- changed value → mismatch;
- rolled out → missing;
- malformed live XML → unreadable;
- a record from another channel never verifies;
- a reused record ID → mismatch;
- a removed channel → missing and access denied → unreadable.

The existing Security tests (`tests/test_validation_and_cli.py`) still pass.

### Result

All four sources verify with their own parser. **Status: TESTED — AUTOMATED.** In the audit, real Security evidence was 24/24 verified. Real Sysmon and Defender evidence does not exist on the test PC: Sysmon is not installed and the Defender log has 0 detection events.

## A-4 Live Monitoring

### Previous State

On real Windows the monitor started (ON in 0.26 s), stopped and restarted without duplicates, but **0 events were delivered** in the audit.

### Root Cause / Findings

The source created an auto-reset, non-signalled event and **waited for the signal before its first `EvtNext`**. Records that already existed after the bookmark, such as one written between the catch-up scan and `EvtSubscribe`, were read only after some *later* matching record signalled. Microsoft's pull-subscription sample drains before waiting, using an initially signalled event.

The rest was checked against the installed pywin32 (312) API and found correct:

- `EvtCreateBookmark` with the rendered bookmark XML;
- `StartAfterBookmark | Strict`;
- the `EvtNext` drain until `ERROR_NO_MORE_ITEMS`.

### Fix

The first `wait()` after `open()` drains without waiting. Each later wait blocks on the auto-reset signal and drains until empty, so records written during a drain re-signal. The catch-up scan → watermark → subscription → batch → store → detect → GUI chain is unchanged. `WindowsSubscriptionSource` accepts injected pywin32 modules for tests.

### Automated Tests

**Source level.** `tests/test_subscription_source.py`: **12 tests, all passed**, against a fake `EvtSubscribe` / `EvtNext` / `WaitForSingleObject`:

- backlog after the bookmark delivered without a signal;
- no records and no signal;
- a new record on a signal;
- several records behind one signal;
- records written during a drain arrive with the next wait;
- only subscribed event IDs are delivered;
- future-only subscription;
- restart resumes without repeats;
- a stale bookmark fails loudly and releases its handles;
- one unrenderable record does not lose the others;
- an event written between catch-up and subscription is stored once, end to end through `LiveMonitor` and the real `ScanService`;
- monitor restart never duplicates stored events.

**Monitor level.** The existing tests in `tests/test_live_monitor.py` cover:

- stop while waiting;
- reconnect with backoff;
- permanent errors;
- batching;
- unexpected errors.

Out-of-order arrival is covered by A-1 test 5.

### Real Windows Validation

`scripts/validate_live_delivery.bat` runs elevated and read-only, with a separate database. It ran once on the fixed code (2026-10-09):

- **Run 1:** ON in 0.26 s, stopped cleanly.
- **Run 2:** restarted, ON in 0.18 s, stopped cleanly.
- 179 events were stored, with **0 duplicate rows**.

The script reported "FAILED", but inspecting the test database showed **no Event 4688 at all**. Windows never wrote a record for `whoami.exe`/`where.exe`, because process-creation auditing is currently off. The script had only checked for *old* 4688s, so there was nothing to deliver and the run is **inconclusive**, not a delivery failure. The script now reads the live log to confirm that Windows wrote the trigger record before judging, and reports INCONCLUSIVE otherwise (commit `83df7cf`).

**Status: A-4 IMPLEMENTED / AUTOMATED TESTED — REAL DELIVERY VALIDATION PENDING (MANUAL VALIDATION REQUIRED).**

The manual procedure (A-M2 in `manual_validation_queue.md`) needs no policy change, no account creation, and MoeSOC types no password:

1. Start MoeSOC elevated and switch Live on. Note the event count.
2. Lock the screen (Win+L), type a wrong password twice, then log in.
3. Within about 10 s, without pressing Scan, two new 4625 events must appear, exactly once.
4. Switch Live off and on: the count must not change. Repeat step 2: the new events must arrive once.

### Remaining Limitations

- Real delivery is unproven until A-M2 is done.
- Only the Security channel is subscribed. Sysmon, PowerShell and Defender are collected by the catch-up scan, as before.

## Secondary Fixes

| ID | Fix | Commit | Status |
|---|---|---|---|
| A-5 | CLI exits quietly on a closed pipe (`moesoc-cli … \| more`) | `09667f0` | TESTED — AUTOMATED |
| A-6 | `show` and HTML reports list per-finding `related_techniques` (COR-004 → T1105); a rule with no mapping says so | `09667f0` | TESTED — AUTOMATED |
| A-7 | "Risk at detection time: 70/100. The current model would score 60/100." in CLI, GUI and report. Stored rows are not changed, no migration | `746b629` | TESTED — AUTOMATED |
| A-8 | DET-008 and COR-004 record which conditions raised severity; the risk model does not add them again as modifiers. The +5 multi-log bonus counts only strongly linked logs, so a weak COR-003 Defender link no longer raises risk | `dbb7bb3` | TESTED — AUTOMATED |
| A-9 | A declined UAC prompt opens limited mode from both the launcher and the exe. The single standard UAC request is unchanged | `c9fe74e` | TESTED — AUTOMATED |
| A-10 | MIT `LICENSE` added; benchmark JSON version set to 1.0.0; README status narrowed to what was actually validated | `ad01338`, `1c966c2` | NOT TESTED (metadata) |
| A-11 | Account names are compared like Windows (per-character simple uppercase), not with `casefold`. `Straße` ≠ `STRASSE`; ASCII keys are unchanged, so stored identity keys stay valid | `ee7aace` | TESTED — AUTOMATED |

The resolver cache added in `1c966c2` limits the cost of A-2 and A-11. On 100k synthetic events (Linux), the detect stage took 8.88 s before the fixes, 13.8 s uncached, and **10.1 s** now.

## Regression Results

| Run | Code | Result |
|---|---|---|
| Linux pytest, full | `HEAD` (`83df7cf`) | **520 passed, 2 skipped** (the 2 skips require Windows) |
| Linux targeted | `HEAD` | campaign 9, failed-logon identity 18, evidence sources 23, subscription source 12, risk 11, validation/CLI 7: all passed |
| Windows pytest, non-elevated | code through A-4 (`a978dae`), 2026-10-09 | **514 passed, 1 skipped, 0 failed.** pytest then crashed in session cleanup on a temp folder left by an elevated run. Fixed in `dbb7bb3` (private `--basetemp`) |
| Windows pytest on the final code (`verify_windows.bat`, non-elevated, 2026-10-10) | final code (product identical to `HEAD`) | **521 passed, 1 skipped, 0 failed** (18.3 s). The skip requires elevation. Session cleanup finished normally |
| Migration / schema tests (`-k migrat`: 3; `-k "schema or version or newer or upgrade"`: 7) | `HEAD`, Linux | all passed. No new migration |

## Ruff

- `ruff check .`: **All checks passed.**
- `ruff format --check .`: **152 files already formatted** (Linux, `HEAD`).

Windows, final code: **All checks passed; 153 files already formatted.** The earlier Windows run of 2026-10-09 reported 19 errors and 3 unformatted files, all in the local `audit\` scratch folder (outside git). `pyproject.toml` now excludes `audit`, `live-validation-data` and `.verify-data`.

## GUI Smoke

**76/76 PASSED, 0 failed** on Windows (non-elevated, real window offscreen), 2026-10-10, on the final code. This includes the DET-007/DET-008 detail pages and the COR-004 chain. The 2026-10-09 run on code through A-4 was also 76/76. PySide6 is not available in the Linux sandbox.

## Windows Integration

- **Done:** non-elevated integration tests passed in the final run (1 test is skipped without elevation). The non-elevated CLI scan gives the clear "Access denied … administrator privileges" message (exit 2), as designed.
- **Done:** the elevated live-delivery script ran (see A-4): start, stop and restart OK, 0 duplicates, delivery inconclusive.
- **Not done this session:** an elevated real Security scan and the exe `--self-test`. The audit's results (1,269 records, 0 parse failures, 0 duplicates; self-test PASSED) predate these fixes. The exe was not rebuilt.

## Database Safety

- **No schema change**: still v8. The campaign key lives in the evidence JSON. A-7 is display only.
- All probes used throwaway databases or the separate `live-validation-data` folder.
- **The real MoeSOC database was not opened for writing.**
- Existing findings keep their dedup keys. A rescan matches them by key as before, and campaign extension never changes status, verdict, notes or history (A-1 test 9).

## Known Remaining Issues

See `docs/known_issues.md`.

1. **A-4 real delivery is unproven.** Manual check A-M2.
2. **A-2 limit:** on a computer whose account authority MoeSOC cannot prove (for example, logs imported from another machine), invented domains stay separate claims. DET-001 does not fire there, and DET-002 is not inflated.
3. **The exe self-test and the elevated real Security scan were not re-run on the final code.** They need a rebuild and a UAC approval.
4. **Detection is about 14% slower** on 100k events.
5. Earlier manual items remain: A-M1, A-M3, A-M4 and owner decisions A-M5 to A-M7 (history privacy before publishing, installer).

## Real vs Synthetic Validation

| Area | Real Windows | Synthetic / automated |
|---|---|---|
| A-1 campaign continuity | — | yes |
| A-2 identity resolution | — | yes |
| A-3 verification | Security only (audit, 24/24) | all four sources |
| A-4 subscription | start, stop, restart, 0 duplicates; delivery **inconclusive** | yes (fake pywin32) |
| DET-001, DET-005, COR-001 | yes (earlier phases) | yes |
| All other rules | no | yes |

## Recommended Next Step

1. Run `scripts\elevated_scan.bat` (approve UAC).
2. Do the 2-minute A-M2 lock-screen check to close A-4.

Only after that should coverage work begin.
