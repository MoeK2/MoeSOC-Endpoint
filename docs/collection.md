# Collection: incremental, gap-aware

MoeSOC reads the Windows Security log with `EvtQuery` and a server-side XPath filter. Since schema v4 it remembers where it stopped, per event group, and reads only new records on the next scan.

## What pywin32 really offers (checked, not assumed)

`scripts/check_eventlog_api.bat` (read-only, Application log) was run on the Windows 11 development PC on Oct 7, 2026, with pywin32 for Python 3.13:

| API | Result |
| --- | --- |
| `EvtQuery`, `EvtNext`, `EvtRender`, `EvtSeek` | present |
| `EvtCreateBookmark`, `EvtUpdateBookmark`, `EvtRenderBookmark` | present; a rendered bookmark is `<Bookmark Channel='Application' RecordId='53711' …/>` |
| `EvtSubscribe`, `EvtSubscribeToFutureEvents`, `EvtSubscribeStartAfterBookmark` | present (used by live monitoring) |
| XPath `EventRecordID>N`, `EventRecordID=N`, `TimeCreated[@SystemTime>='…']` | all return the expected records |

## Design: a record-ID watermark instead of an opaque bookmark

A bookmark contains exactly the channel and the EventRecordID. MoeSOC stores those values directly in `collection_state` (channel, group, record ID, its timestamp, and the set of event IDs it was built for). That makes the position visible, testable without Windows, and easy to validate. Behaviour is the same as resuming from a bookmark.

**Trade-off.** A bookmark can be passed to `EvtSubscribe` to resume a live subscription exactly. Live monitoring therefore converts the watermark into a bookmark XML string when it subscribes; no information is lost.

## Modes (per group, per scan)

| Mode | When | What is read |
| --- | --- | --- |
| bootstrap | No saved position (first run or deleted database), an invalid one (record ID ≤ 0, timestamp in the future), or the collected event IDs changed in an upgrade | The last `lookback_hours` (24 h), newest first, up to the budget. If the budget is hit, the scan is marked as capped |
| incremental | The saved record still exists with the same timestamp | `EventRecordID > saved`, oldest first, up to the budget. If the budget is hit, the next scan continues from there; nothing is skipped |
| recovery | The saved record is gone or different (log cleared, rolled over, or recreated with restarted record IDs) | Everything since the saved timestamp, oldest first. The scan records that events removed before it ran cannot be recovered |

- **Groups:** `core` (authentication, account changes, log clearing, 4672) and `process` (4688) have separate positions and budgets. Optional sources use the same logic on their own channels: `sysmon_process`, `sysmon_network`, `sysmon_file`, `sysmon_registry`, `sysmon_dns`, `powershell_scriptblock` (4104) and `defender_detection` (1116-1119). A missing optional channel is recorded as `not installed`, not as an error.
- **Atomic:** the new position is saved in the same transaction as the events and findings. If storing fails, the next scan reads the same records again.
- **Duplicates:** overlapping reads are harmless; the unique key `(host, channel, record ID, timestamp)` ignores repeats.
- **Visible:** the scan record stores the mode (`core: incremental, process: bootstrap`) and any notes; the CLI prints them and the Overview shows them on the Last Scan card.
- **Never silent:** a gap is written into the scan message. A log clear also produces Event 1102, which DET-003 reports.

## Not validated on a real machine

Recovery after a real log clear or rollover is covered by unit tests only. Clearing the Security log to test it would destroy audit evidence, so it is deliberately not part of the manual validation queue.

## Live monitoring (`engine/live.py`, `collectors/subscription.py`)

The **Live** button in the header (states OFF, STARTING, ON, RECONNECTING, ERROR) runs this loop on its own thread:

1. **Catch up** with a normal incremental scan, so everything written since the last scan is stored first.
2. **Subscribe** with `EvtSubscribe` (pull model): starting after the saved position via a bookmark built from it, with `EvtSubscribeStrict` so a stale bookmark fails loudly; with no saved position, only future events. The query covers every supported Security event ID.
3. **Wait** on Windows' signal event (a blocking wait with a 1-second timeout, only to notice a stop request; no busy polling). Records arriving within 2 seconds of each other are handled as one batch (at most 500).
4. **Ingest** the batch: parse (a malformed record is counted, not fatal), store (duplicates ignored), run the rules over the stored events in the rule window, upsert findings by their stable key (so a growing burst updates one finding instead of raising a new alert), and move the positions forward (never backward).
5. **Recover:** any transient error → RECONNECTING, wait 2 s, 4 s, … up to 60 s, then catch up again and resubscribe. Access denied or a non-Windows host → ERROR (no retry). Unexpected exceptions are logged and treated as transient; they never kill the thread.

| Tested how | What |
| --- | --- |
| Unit tests (fake subscription) | state sequence; bookmark start; batch gathering; one finding updated, not duplicated; duplicates and malformed records; forward-only position; reconnect with catch-up of events written during the outage; access denied is permanent |
| GUI smoke test on Windows (standard user) | the button reaches ERROR with "administrator" in the message and switches itself off |
| Real subscription (`EvtSubscribe` on the Security log) | **not yet**: needs an elevated session (manual queue) |
