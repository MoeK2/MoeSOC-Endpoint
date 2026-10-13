# Testing

```powershell
ruff check .
ruff format --check .
pytest            # all unit tests; Windows integration tests auto-skip off Windows
pytest -m windows # only the read-only Windows integration tests
```

## Strategy

- **No system modification.** The tests never write to the Windows event log, change audit policy or create accounts.
- **Fixtures** (`tests/fixtures/`) are sanitized and use RFC 5737 documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`) and fictional names.
- **`FakeReader`** (`tests/conftest.py`) implements the same `query()` protocol as the real `WindowsEventLogReader`. The whole pipeline (collector → parser → SQLite → rules → findings) runs in the tests with a temporary database.
- **Generated sequences** for detection tests are built by filling an XML template and running it through the *real* parser, so the tests exercise the same code path as production.

## Coverage

| Area | File | Cases |
|---|---|---|
| Parsing | `test_security_parser.py` | valid 4624/4625, local (no-network) logon, missing fields, unexpected fields, malformed XML, DTD rejected, unsupported ID, missing record ID, IP representations (IPv4, mapped IPv6, IPv6, loopback, bracketed, invalid), 7-digit timestamps |
| Collection | `test_security_collector.py` | XPath construction, a malformed record does not stop the scan, cap and truncation, access denied, Win32 error → readable message |
| Storage | `test_storage.py` | idempotent migrations, full-field round trip, duplicate ingestion, counts, rollback on error, newer-schema protection, detection upsert |
| Rules | `test_rules.py` | thresholds, window boundaries, account separation, case-insensitivity, burst merging, separate bursts, unordered input, COR-001 positive and negative cases, same/different source |
| Pipeline | `test_scanner.py` | end-to-end scan, re-scan idempotency, a failed scan is recorded, `wevtutil`-style import |
| Dashboard | `test_overview.py` | no fake values on an empty DB, counts match stored data, a clean scan has risk 0 |
| Identity | `test_identity.py` | same username in different domains, local vs domain, case and Unicode case, missing domain (host-scoped), `.` domain, NULL/missing SID, SID preference, NULL-SID failure linked to SID success, ambiguous names not merged, machine accounts, SYSTEM / ANONYMOUS; DET-001 and COR-001 never merge domains or hosts |
| COR-001 confidence | `test_cor001_confidence.py` | user-typo pattern → LOW, remote RDP from the failing source → HIGH, loopback is not remote, many sources and high volume, full evidence fields, out-of-order input, window boundary, point scale |
| Password spray | `test_password_spray.py` | threshold, below threshold, inclusive/exclusive window boundary, brute force is not spray, case variants, domains distinct, separate sources, IPv4-mapped IPv6 same source, workstation fallback, no source skipped, non-existent accounts, long spray = one finding, out-of-order, duplicates |
| Log cleared (1102) | `test_log_cleared.py` | UserData extraction, EventData unaffected, 1102 normalization, empty and nested UserData, malformed XML, DET-003 evidence, scan and import pipelines |
| Triage | `test_triage.py` | NEW + history + evidence links, full status workflow with verdict and resolved_at, notes persistence and validation, rescans keep analyst work, older rule versions preserved, closed findings excluded from risk, **v1 → v2 migration of a real v1-shaped database** |
| Search and timeline | `test_event_search.py` | every filter, composition, LIKE wildcard escaping, time range, pagination, column whitelist, detection timeline (evidence flagged, context included, other host and out-of-window excluded), drill-down, pivots, explanations, **10,000-event dataset** |
| Verification and CLI | `test_validation_and_cli.py` | evidence verified / missing / reused-record mismatch / other computer; CLI import → triage → show → timeline → events → close |
| Windows | `test_windows_integration.py` | read-only: channel probe; Security scan, or a correct access-denied message |
| Domains | `test_domains.py` | domain aliases only with evidence (shared authority SID, local configuration), ambiguous names never aliased, well-known SIDs ignored |
| Low and slow | `test_low_and_slow.py` | DET-004 identity and source modes, exclusion of DET-001/002 coverage, cadence, dedup |
| Accounts | `test_account_management.py` | 4720/4732 parsing (localized names), schema v3 migration and rollback, DET-005, DET-006 tiers by SID, COR-002 ordering and window |
| Privileged sessions | `test_privileged_sessions.py` | 4672 ↔ 4624 by logon ID and UAC linked ID, time skew, noise filtering, COR-001 context and risk |
| Process creation | `test_process_creation.py` | 4688 fields, elevation and integrity, missing command line, own collection budget |
| Incremental collection | `test_incremental_collection.py` | bootstrap, incremental, recovery after clear/rollover/restarted IDs, forward-only watermarks, atomic save, budgets |
| Live monitoring | `test_live_monitor.py` | catch-up, bookmark subscription, batching, back-off and reconnect, access denied, never dying on errors |
| Sysmon | `test_sysmon.py`, `test_sysmon_context.py`, `test_health_sysmon.py` | Event 1/3/11/13/22 parsing, logon ID join, collection groups, built-in vs standalone detection, context never alerts |
| Process trees | `test_process_tree.py` | GUID links, PID reuse, other hosts, cycles, node limits, CLI |
| PowerShell | `test_powershell.py` | 4104 parsing without text in normalized fields, indicators, fragment reassembly, process context, privacy of evidence, policy health |
| Defender | `test_defender.py` | 1116–1119 parsing (multi-resource paths), remediation states, severity, Detection-ID dedup across scans |
| Cross-source | `test_cross_source.py` | activity graph links, COR-003 session follow-ups, COR-004 file tracing, schema v6 indexes, key-based enrichment |
| Stories | `test_story.py` | related findings, collapsed steps, data gaps, privacy, notes, CLI |
| Risk | `test_risk.py` | base + every modifier, clamping explained, overview risk driver |
| Search | `test_search_filters.py` | every new filter, wildcard escaping, paging in SQL, pivots |
| Retention | `test_retention.py` | plan vs apply, open findings keep evidence, confirmation required, no Windows-log code, CLI |
| Tuning | `test_tuning.py` | suppression scope/expiry/removal/validation, hits, disabled and tuned rules, bounds, event IDs never tunable, every parameter read, audit log, CLI |
| Reports | `test_report.py` | self-contained HTML, escaping of hostile values, no command lines or script text, redaction, data origin, CLI |
| Packaging | `test_frozen.py` | packaged start-up decisions (UAC once, declined, already running, lock race), self-test reporting |
| Static checks | `test_static_imports.py` | every internal `from … import` resolves (GUI modules included), icon sizes, version strings in sync |

## GUI smoke test (`scripts/gui_smoke.py`)

Drives the real window against a throwaway database and a synthetic export (brute force + success, a 5-account spray, a 1102, and a Sysmon process chain). 76 checks, including:

- the empty state shows "Unavailable"; 17 events and 4 active detections after the import;
- the confidence explanation, MITRE IDs, Start Investigation and a note in the detail panel;
- the story page (narrative, data gaps, related finding, note) and back navigation;
- the timeline highlights 7 evidence events; the IP pivot and evidence drill-down show exactly the right events with raw XML;
- the IP filter, the "More filters" parent-process filter and port validation;
- the process tree built from Sysmon GUIDs, with the uncollected parent shown;
- Suppress… from a finding (prefilled), the suppression listed, a rule disabled, both in the audit log;
- finding and summary reports exported (redacted and plain);
- retention preview with nothing deleted;
- live monitoring starts or explains that administrator rights are needed; a live scan never freezes;
- DET-007, DET-008 and COR-004 detail panels render their structured evidence and activity chain.

It also saves the screenshots in `docs/screenshots`.

## Real-event validation

See [validation.md](validation.md): a dedicated-test-account procedure, `scripts/validate_real_auth.bat` (scan + re-verifies each evidence EventRecordID in the live log) and `scripts/validate_real_gui.bat` (checks the GUI shows exactly those records). **Result, Oct 7, 2026: DET-001 and COR-001 TESTED on real logons; 7/7 and 8/8 evidence records verified; 19/19 GUI checks passed.**

## Quick manual test on your own machine

Generate failed logons **against your own machine only**:

1. Lock the screen (Win+L), choose **password** sign-in (not PIN or Windows Hello, which may not produce 4625), enter a wrong password 6 times, then sign in correctly.
   Alternatively, in a normal terminal: `runas /user:%COMPUTERNAME%\%USERNAME% cmd` with a wrong password 6 times, then the right one.
2. In an **elevated** terminal: `python -m moesoc.cli scan`, then `python -m moesoc.cli detections`.
3. Expected: DET-001, and COR-001 if the success happened within 10 minutes. The evidence should show your account and logon type 2 (interactive) or 7 (unlock).

Note: account lockout policy may lock your account after N failures. Check `net accounts` first and stay below the lockout threshold.
