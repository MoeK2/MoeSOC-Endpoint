# Always-On Architecture: Sensor, Tray, Console

MoeSOC runs as three separate processes. Monitoring no longer depends on a window being open.

| Process | Runs as | Session | Starts | Does |
|---|---|---|---|---|
| **MoeSOC Sensor** (`MoeSOCSensor.exe` / `sensor.py`) | Windows service: `NT SERVICE\MoeSOCSensor` (or LocalSystem, see below) | 0 (no desktop) | Automatically with Windows (delayed start) | Collects, stores, detects, correlates, decides notifications, keeps health |
| **MoeSOC Tray** (`MoeSOCTray.exe` / `tray.py`) | The signed-in user, not elevated | User | At sign-in (`HKCU\…\Run`) | Icon, status, toasts, opens findings |
| **MoeSOC Console** (`MoeSOC.exe` / `app.py`) | The signed-in user; no UAC prompt when the sensor is installed (B-7) | User | Only when opened | The existing investigation GUI |

## Data flow

```
Windows logs: Security · Sysmon · PowerShell 4104 · Defender
        │  EvtSubscribe (pull model; one thread blocks on all channel signals)
        ▼
MoeSOC Sensor ── catch-up (incremental watermarks) on start, resume, manual scan, daily
        │  ScanService.ingest_live → parse → normalize → SQLite (INSERT OR IGNORE)
        │  → the same detection + correlation rules → findings upserted (campaigns)
        ▼
NotificationEngine  (changed findings only: detections.updated_at)
        │  new? escalated? material risk increase after cooldown?
        ▼
NotificationHub ──named pipe \\.\pipe\MoeSOC.Sensor──► Tray ── toast ── click
                                                                          │
                              MoeSOC.exe --finding <id>  ◄────────────────┘
                              (or hand-over to the open console window)
```

There is **one** detection pipeline. The sensor calls the same `ScanService` (`run_live_scan` for catch-up, `ingest_live` for live batches) and the same `LiveMonitor` as the console did. The sensor only adds a host, IPC and a notification decision.

## Sensor

`moesoc/sensor/core.py` (`SensorCore`) contains everything that is not Windows-service glue. It is tested on Linux with fake event logs.

- **Start:** open and migrate the database (retried with back-off), then catch-up, then subscriptions.
  - Security is required. Sysmon, PowerShell and Defender are added when the channel exists. A missing optional channel is reported, never fatal.
- **Idle:** one monitor thread blocks in `WaitForMultipleObjects` on the subscriptions' Windows events. It wakes once per second to check the stop flag; it does not read logs or the database.
  - The main thread sleeps and wakes hourly to check whether the daily maintenance is due.
  - The IPC threads block on the pipe.
- **New records:** `EvtNext` drains at most 1,000 records per wait. Records arriving within 2 s are batched, up to 500. `ingest_live` stores them in one transaction, detects, and moves the watermarks forward.
  - Then the notification engine looks only at findings changed since its last check.
- **Resume from sleep / manual scan / daily maintenance:** the same restart path is used: catch up incrementally, then resubscribe. Records already stored are ignored, so nothing is duplicated.
- **Daily maintenance:** `PRAGMA wal_checkpoint(TRUNCATE)` and `PRAGMA optimize`.
  - Retention runs only if the user has chosen a retention period. MoeSOC never deletes Windows logs.

### Live sources (honest status)

| Source | Live subscription | Fallback |
|---|---|---|
| Security | yes (required) | catch-up |
| Sysmon, PowerShell 4104, Defender | yes, when the channel exists and is readable | catch-up on start, resume, manual scan, daily |

An optional channel that MoeSOC has never stored a record from is subscribed "from new events". A record written between its catch-up and that subscription is picked up by the next catch-up.

### Backpressure and memory

The pull model is the backpressure. Records wait in Windows' own log, not in a MoeSOC queue.

- One wait returns at most 1,000 records and one batch is at most 500, so memory per batch is bounded.
- There is no thread per event.
- Nothing is dropped by MoeSOC. If records arrive faster than they are processed for long enough that the log wraps, the next catch-up reports the gap (the existing collector notes).

## Windows service host

`moesoc/sensor/service.py` adapts SCM events to SensorCore:

- **start** → `run`;
- **stop / shutdown** → set the stop event. The current batch finishes, subscriptions and handles close, and the database is left consistent. The wait hint is 35 s.
- **power resume** → `on_resume`.

The service runs in session 0 and shows nothing.

Management is always explicit (`sensor.py <command>` or `MoeSOCSensor.exe <command>`):

| Command | Effect |
|---|---|
| `install` | Registers the service (auto start, delayed; restarts after 60 s twice on failure), sets the folder access, registers tray autostart. Run again from a new build, it is the **update** (see below). Options: `--copy-to-program-files`, `--account virtual\|system`, `--allow-insecure-code-path`, `--no-tray`, `--no-start` |
| `start` / `stop` / `restart` / `status` | Service control. `status` also prints the sensor's own health over IPC |
| `uninstall` | Stops the service, removes its registration, the Event Log Readers membership and the tray autostart. **Data is kept** |
| `run` | Runs SensorCore in the foreground for diagnostics |
| `import-user-data` | Copies `%LOCALAPPDATA%\MoeSOC\moesoc.db` into the sensor folder. Uses SQLite's backup API, checks integrity and migrates the copy; the original is not changed. An existing target is kept as a backup and replaced only with `--force` |

Scripts on the PC:

- `scripts\sensor_validate.bat`: elevated; installs from `dist\MoeSOC`, checks the lifecycle and measures the idle sensor.
- `scripts\sensor_uninstall.bat`
- `scripts\start_tray.bat`
- `scripts\sensor_footprint.bat`

## Privilege boundary

### Service account

The default is the virtual account **`NT SERVICE\MoeSOCSensor`**, which the install step adds to the built-in **Event Log Readers** group.

- The Security channel's access list grants that group read access (`S-1-5-32-573`), and the other three channels grant it by default.
- The service's privileges are reduced to `SeChangeNotifyPrivilege`, which is required to traverse folders.
- The group membership is the only system change. Install prints it, and uninstall reverts it.

**LocalSystem** is used only when the code lives in a user profile (a development checkout): a virtual account cannot read another user's profile. That configuration is for development only (see the next section).

### Code that a privileged process runs

A service must not load code or rules that an ordinary user can modify.

- `install` checks the owner and access list of every folder it loads from, and refuses when a non-administrator can write there.
- `--copy-to-program-files` copies the packaged build to `%ProgramFiles%\MoeSOC Endpoint`, which only administrators can change. This is the supported setup.
- `--allow-insecure-code-path` exists for a single-user development machine. It is printed as a warning: with it, any process running as that user could take over the service.

### Update (re-running install) is rollback safe

`MoeSOCSensor.exe install --copy-to-program-files`, run from a new build, follows these steps (fixes B-2):

1. Leftovers of an interrupted update are recovered or removed.
2. The new build is copied to `MoeSOC Endpoint.new` and checked for completeness. The service is not touched.
3. The tray is asked to exit with its own WM_CLOSE path, and is started again afterwards. If a MoeSOC console runs from the program folder, the update stops here; nothing has changed and the sensor keeps running.
4. Stop the service, rename the live folder to `.old`, rename `.new` to live, start the service, then health-check it over IPC.
5. If any of that fails, the previous folder is put back and started again. If the new version does not answer, it is moved to `.failed` and the old one is restored.
6. `.old` is deleted only after the new version answered.

Directory renames mean the folder is always either completely old or completely new.

The folder rights are set on the root only, and children inherit them (fixes B-1). Re-running install never touches the rights of existing files. Files damaged by an older install (protected, or with no inherited entry) are detected, given back to Administrators, and reset to inherit. Their contents are untouched.

### State the service writes

The service writes to `%ProgramData%\MoeSOC` (`data\`, `logs\`, `sensor.json`). Install sets that folder to:

- protected: not inherited, because users may create files in `ProgramData` by default;
- owned by Administrators;
- SYSTEM and Administrators: full control; the service account: modify; Users: read.

The service never writes into a user-writable folder. A privileged writer in such a folder can be redirected with junctions into overwriting system files. This is why the sensor does **not** use `%LOCALAPPDATA%`.

### Console and tray

- **Viewing:** the console needs no administrator rights. A console without write access reads the sensor's database with `mode=ro`. This works only while the `-wal` and `-shm` files exist, because a normal user may not create them in the data folder. The sensor therefore keeps one idle "keeper" connection that has run one read and holds no transaction. Before B-7 the keeper never ran a statement, so SQLite never opened the files for it, the last writer deleted them, and a normal user got "unable to open database file".
- **Triage, verdicts and notes from a normal-user console:** these are sent to the sensor over the existing pipe (`set_triage`, `add_note`). The sensor validates them, saves them with the same repository code and logs them with the client's process and session ID. The sensor stays the only writer. The console finds out once whether it may write the file, by asking for write access to it. SQLite opens a non-writable file read-only without an error, and on Windows its `BEGIN IMMEDIATE` succeeds on such a WAL connection.
- **Suppressions, rule changes and retention** stay administrator-only by design, because they change what is detected or kept. A normal-user console says so plainly. Use "Run as administrator" for these.
- **Start-up:** with the sensor installed, the console starts as the signed-in user and shows no UAC prompt, also when opened from a notification. Without a sensor it asks for elevation as before.
- **The tray** never needs elevation.

### What is deliberately not protected in this milestone

An administrator can change anything, including the database and tuning; that is by design. An ordinary user cannot change the sensor's database, rules, code or configuration.

## Local IPC

The transport is one named pipe, `\\.\pipe\MoeSOC.Sensor`. There is **no TCP/UDP listener**.

- **Remote clients:** `PIPE_REJECT_REMOTE_CLIENTS`, plus an explicit deny for the `NETWORK` SID.
- **Access list:**
  - SYSTEM and Administrators: full control.
  - `INTERACTIVE` (users signed in at this computer): read, write data and write attributes, **without** `FILE_CREATE_PIPE_INSTANCE`, so they cannot add a rogue instance.
- **Squatting:** the first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so the sensor refuses to serve if another process already holds the name. The client checks that the pipe server process runs as SYSTEM or a service SID (`S-1-5-80-*`) before trusting it.
- **Protocol:** one JSON object per message, at most 16 KB.
- **Allow-listed commands:** `hello`, `status`, `wait_notifications` (long poll ≤ 30 s), `scan` (rate-limited to one per minute), `get_prefs`, `set_prefs` (validated: three booleans, cooldown 5–1440 min, pause ≤ 24 h).
  - Anything else gets an error reply. Malformed or oversized input never stops the sensor; the tests prove this.
- **Never exposed:** command execution, files, registry, processes, stopping the service, or raw event content.
- **Known limit:** the pipe has 4 instances with blocking I/O. A local user process that holds all four open can delay that user's own tray updates. Monitoring is unaffected.

## Notifications

Notifications are based on findings, never on raw events.

| Severity | Default |
|---|---|
| LOW | never |
| MEDIUM | off (can be switched on) |
| HIGH | on |
| CRITICAL | on (shown with the warning style) |

A finding notifies:

- the **first time** it is open and its severity is enabled;
- again only when its severity **escalates** (immediately), or its risk rises by **≥ 15** after the **cooldown** (60 min by default).

Other rules:

- A growing DET-001 burst (5 → 7 → 9 → 12 failures) is one finding and one notification.
- A correlation on top of it (COR-001) is a new finding and notifies if its severity is enabled.
- Closed findings never notify.
- **Pause** (1 h from the tray, ≤ 24 h) records decisions silently; collection never pauses.
- **First start:** existing findings are not announced; the sensor starts counting from that moment.
- **Bursts of findings:** at most 3 toasts per evaluation: the two most serious, then "N more findings need review".
- **State:** stored in `notification_state` (schema v9, additive migration), so a restart neither repeats nor forgets notifications.

The toast text is the rule title, the first sentence of the rule description, and "Severity: HIGH · Risk: 70". It never says "hacked", and it never names malware unless the finding is Defender's own detection.

**Toasts:** the tray uses `Shell_NotifyIcon` balloons, which Windows 10/11 show as toast notifications. This needs no extra dependency.

- Clicking the toast while it is shown opens the finding.
- Clicking it later from the Notification Center only opens the toast's app. This is a known limit: the deep link would need a registered WinRT toast activator and an extra dependency.
- If Focus Assist / Do Not Disturb is on, Windows may suppress toasts.

## Deep link

`MoeSOC.exe --finding <id>` (or `app.py --finding <id>`):

- **Console closed:** it starts as the signed-in user (no UAC prompt while the sensor is installed; it receives only a validated `--finding <number>`), loads the data, selects the finding on Detections and switches the filter to *All* if the finding is closed.
- **Console open:** the new process sends `{"cmd":"open","finding":id}` to the running console's per-user local socket and exits. The window comes to the front (the tray first allows the foreground switch) and shows the finding. No second instance is created.
- **Unknown or invalid ID:** the console opens normally and says so in its status line.

## SQLite / concurrency

The sensor is the only process that writes heavily. A normal-user console only reads, and its triage and notes are written by the sensor. An elevated console may also write directly.

- WAL mode, `busy_timeout` 10 s, and short transactions: one per live batch.
- Retention and checkpoints run daily.
- When the sensor is installed, the console's *Scan* asks the sensor over IPC instead of collecting itself, and *Live* shows "Sensor".
- The tests run a writer with two concurrent readers and finish with an integrity check.

## Failure modes

| Problem | Behaviour |
|---|---|
| Sysmon / PowerShell / Defender absent or unreadable | That source is "not installed" / "unavailable"; the others continue |
| Security subscription error (log service restart, stale bookmark) | RECONNECTING with back-off (2 s doubling to 60 s), then catch-up and resubscribe; tray shows Limited |
| Security access denied | ERROR (permanent), tray shows Limited, reason in `status` and `sensor.log` |
| Database locked, missing rights, corrupt, too new, any storage exception | IPC is started **before** the database (B-4); `status` reports `state: ERROR`, `monitoring: false`, `last_error`; the tray shows "Sensor error (not monitoring)" with the reason; retried (2, 5, 15, 30, 60 s) until repaired |
| Malformed record | Counted as a parse failure, skipped; the batch continues |
| Sleep / resume | Power event → catch-up + resubscribe |
| Sensor crash | SCM restarts it after 60 s (twice per day, then stays stopped and visible) |
| Tray closed | Monitoring continues; the tray starts again at the next sign-in |
| Console closed | Monitoring continues |

## Logs

Logs rotate at 1 MB × 5, and they contain no event content:

- `%ProgramData%\MoeSOC\logs\sensor.log`
- `%LOCALAPPDATA%\MoeSOC\logs\tray.log`
- `%LOCALAPPDATA%\MoeSOC\logs\moesoc.log` (console)

## Performance design

- Event-driven: there is no `while True: scan()` loop.
- Catch-up reads only records after the saved watermark.
- Notification checks query findings changed since the last check (indexed `updated_at`), only after a batch that produced findings.
- The tray long-polls every 30 s over a local pipe and does not load Qt.

The measured numbers are in [MoeSOC_Always_On_Report.md](MoeSOC_Always_On_Report.md). The design goal is near-idle CPU and flat memory when nothing happens, not "zero resources".
