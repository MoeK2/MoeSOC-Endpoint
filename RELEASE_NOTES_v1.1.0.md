# MoeSOC Endpoint v1.1.0

**Always-on, local-first Windows detection and investigation platform.**

v1.1.0 turns MoeSOC from a console you open and scan into an always-on endpoint sensor with notifications. The detection rules and their logic are unchanged from v1.0.0.

## Highlights

### Always-On Sensor Service
- `MoeSOCSensor.exe` runs as a Windows service under a **virtual service account** (`NT SERVICE\MoeSOCSensor`), a member of Event Log Readers with only `SeChangeNotifyPrivilege`. It is not LocalSystem.
- Automatic (delayed) start, restart on failure, clean stop at shutdown.
- **Live subscriptions** to the Security, PowerShell and Defender logs, plus Sysmon when it is installed. A gap-aware catch-up runs after every start and wake-up.
- Detection, correlation and scoring run in the service; the console no longer has to be open.

### Tray and Windows notifications
- `MoeSOCTray.exe` runs as the signed-in user and starts at sign-in. It shows the sensor state and the most recent finding, with pause and notification settings.
- **Finding-based notifications:**
  - raw events never notify;
  - a finding notifies once, and again only if its severity escalates or its risk grows materially;
  - HIGH and CRITICAL are on by default;
  - the state survives restarts.
- Clicking a notification opens that finding. An open console is reused, not duplicated.

### Normal-user investigation console
- With the sensor installed, the console runs **without administrator rights** and shows no UAC prompt.
- It reads the sensor's database read-only.
- Triage, notes and verdicts are saved **through the sensor**, which stays the only writer and logs each change with the client's process and session.
- Suppressions, rule changes and retention deliberately need an administrator console.
- In sensor mode, the health view shows what the sensor actually collects.

### Local IPC
- One local named pipe (`\\.\pipe\MoeSOC.Sensor`). There is no TCP/UDP listener and no network access.
- The access list denies network logons, and users cannot create a rogue pipe instance.
- Messages are size-limited JSON from a fixed command list, and the client verifies that the server is the service.

### Safe update and rollback
- Re-running `install --copy-to-program-files` updates in place. The new build is staged and validated, then the program folders are swapped as whole directories.
- After the swap, the sensor must answer over IPC. Any failure puts the previous version back and restarts it.
- Data-folder access rights are set once on the root and inherited. Re-installing never breaks them, and damaged rights from older installs are repaired.

### Reliability (validated on real Windows)
- **Reboot persistence:** the sensor starts without sign-in, catches up on what happened while it was down, and the tray reconnects.
- **Sleep/resume recovery:** catch-up and resubscription after wake-up, without duplicate events.
- **Uninstall/reinstall:** the service and tray startup entry are removed. `C:\ProgramData\MoeSOC\data` is kept, and old findings, notes and history are readable after reinstall.
- **Degraded health:** if the database fails, the sensor stays reachable and reports the error instead of disappearing.

## Validation

On a real Windows 11 PC with the packaged build. Full report: `docs/MoeSOC_AlwaysOn_Final_Report.md`.

| Check | Result |
|---|---|
| Windows tests, elevated / non-elevated | 672 / 671 passed, 0 failed |
| Linux tests | 670 passed, 0 failed |
| GUI smoke test | 76 / 76 |
| Live delivery without Scan Now | real failed logons → DET-001 + COR-001 |
| Real notification and deep link | 1 notification; the right finding opened; console reused |
| Reboot, sleep/resume, update rollback, uninstall/reinstall | passed |
| Database | `quick_check` ok, 0 duplicate events, analyst data intact |
| Network exposure | 0 TCP / 0 UDP sockets |
| Idle cost | sensor ≈ 0.009 % CPU, ≈ 37 MB; tray ≈ 33 MB |

The real-Windows validation ran on the same code as this release, before the version number changed from 1.0.0 to 1.1.0. The release binaries were rebuilt from the tagged source and passed the packaged self-test.

## Download

`MoeSOC-Endpoint-v1.1.0-win-x64.zip` is a portable folder, not an installer. Verify it with `SHA256SUMS.txt`. The executables are **not code-signed**, so Windows SmartScreen may warn on first run. Setup steps are in the README.

## Known limitations

- A single Windows endpoint. Not an antivirus, and not a full EDR, XDR or SIEM. No automatic containment or response.
- Sysmon telemetry needs Sysmon to be **already installed**. It was not installed on the validation PC, so Sysmon-based detections are proven on synthetic events only.
- Real positives exist for DET-001 and COR-001. DET-002 to DET-008 and COR-002 to COR-004 are validated on synthetic events.
- The "normal user" was tested as the signed-in account without elevation, not as a separate standard account.
- Low-severity items:
  - Detection cost during large live bursts.
  - A missing optional Sysmon log is logged at ERROR level.
  - Uninstall leaves a running tray open until sign-out.
  - Wake-up from sleep can be logged twice.
