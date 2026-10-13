# MoeSOC Endpoint: Portfolio Copy

Facts used below are from the v1.1.0 final validation report. MoeSOC is a single-endpoint portfolio project, not an enterprise product. Do not describe it as deployed in production.

## A. One-line description

MoeSOC Endpoint is an always-on, local-first Windows detection and investigation platform. A least-privilege sensor service turns Windows security telemetry into explainable, correlated findings with notifications and an analyst workflow.

## B. CV (3 bullets)

- Built **MoeSOC Endpoint**, a Windows detection and investigation platform in Python (PySide6, SQLite, Windows Event Log API). It has 8 detection rules and 4 cross-event correlation rules with MITRE ATT&CK context, explainable confidence and risk scoring, timelines, investigation stories and triage.
- Designed an always-on architecture:
  - a least-privilege Windows service (virtual service account, read-only log access);
  - a normal-user tray and console linked by a secured local named pipe;
  - finding-based notifications, rollback-safe updates and no network listener.
- Validated it on real Windows: 670+ automated tests, live delivery of real attack-pattern events, notification deep links, and reboot, sleep and reinstall resilience. Found and fixed 8 reliability and security defects, including a SQLite WAL issue that blocked non-admin access.

## C. LinkedIn: Projects section

**MoeSOC Endpoint: always-on Windows detection and investigation platform**

MoeSOC is a personal security-engineering project. It turns Windows event-log telemetry (Security, PowerShell, Microsoft Defender and, when installed, Sysmon) into a small number of explainable findings on a single endpoint.

A Windows service subscribes to the logs live. It runs eight detections and four correlations: for example, failed logons followed by a success, or activity in the same logon session. Each finding is scored with a confidence that explains its evidence. Important findings raise a Windows notification that opens the investigation console on that finding. The console offers evidence, a timeline, process trees, an investigation story, triage, notes, verdicts and HTML reports.

It is local-first: no cloud, no telemetry upload, no network listener. The sensor runs with minimal privileges, and the tray and console run as a normal user, connected by a hardened local named pipe.

I validated it on a real Windows 11 PC: live delivery, real notification and deep link, reboot, sleep/resume, update rollback and uninstall/reinstall with data preservation. It has 670+ automated tests and a GUI smoke test.

Tech: Python 3.13, PySide6, SQLite (WAL), pywin32 (EvtSubscribe, named pipes, Windows services), PyInstaller, pytest, Ruff, GitHub Actions.

## D. LinkedIn launch post (short)

I just published **MoeSOC Endpoint v1.1.0**, an always-on, local-first Windows detection and investigation platform I built to learn detection engineering end to end.

🔹 A least-privilege Windows service watches Security, PowerShell and Defender telemetry live (and Sysmon when installed).
🔹 8 detections + 4 correlations with MITRE ATT&CK context and explainable confidence and risk.
🔹 One notification per finding → click → the investigation console opens the evidence, timeline and story.
🔹 Everything stays on the machine: no cloud, no network listener.

The most valuable part was the validation on real Windows. Reboots, sleep, updates and reinstalls each surfaced a real bug. A few examples:
- file permissions that broke on reinstall;
- an update that could leave the service stopped;
- a SQLite WAL detail that silently blocked non-admin users.

Each one is fixed and covered by a regression test.

It's a single-endpoint portfolio project, not an EDR. Feedback is very welcome.

🔗 <repository link>

#cybersecurity #blueteam #detectionengineering #windows #soc #python

## E. Interview: "What is MoeSOC?"

"MoeSOC is a Windows endpoint detection and investigation tool I built on my own. It has three parts.

A small Windows service runs with minimal privileges. It subscribes to the Windows event logs live, normalizes the events into SQLite and runs detection rules on them. Examples are a burst of failed logons, a password spray, a cleared Security log, suspicious PowerShell, or a Defender detection.

On top of that, correlation rules link events across logs and logon sessions. The clearest one is failed logons followed by a success for the same account, which becomes 'possible account compromise'. Every finding explains its evidence, how confident that evidence is and why it got its risk score.

When something important happens, a tray app shows one Windows notification. Clicking it opens the console on that finding, where an analyst can look at the evidence, a timeline and a narrative 'story', then triage it, add notes and record a verdict.

It's deliberately local-only and observe-only: no cloud, no network listener, no automatic response. It's for one machine. I'm clear that it's not an EDR, but it covers the detection-to-investigation loop end to end."

## F. Interview: "What was the hardest engineering problem?"

"Making the always-on architecture both secure and reliable on real Windows. The detection logic was the easier part.

The design splits privilege. The service runs as a virtual service account that can read event logs and write its own database. The tray and console run as the normal user. That raises three questions:
- How does a normal user read the data?
- How do they save triage?
- How do the processes talk without opening a network port?

For the communication I used a named pipe with an explicit access list:
- network logons are denied;
- users cannot create a rogue pipe instance;
- requests are a short list of JSON commands;
- the client checks it is really talking to the service.

The hard part was what only real Windows testing showed. My first real test as a normal user failed: the console couldn't open the database while the sensor was running. The root cause was subtle. SQLite in WAL mode needs its `-wal` and `-shm` files to exist for a read-only reader. The service kept a 'keeper' connection to hold them open, but that connection never ran a query, so SQLite never opened the files for it. They were deleted after every write, and a normal user isn't allowed to recreate them.

Then a second surprise: SQLite silently opens a non-writable file read-only, and on Windows its write-lock probe still succeeds. So the console couldn't even tell it was read-only.

The fix:
- the keeper does one read;
- the console checks the file's actual access rights;
- triage writes go to the service over the pipe instead of loosening file permissions.

I reproduced each step with small experiments before changing anything, and added regression tests.

The same discipline found other bugs. Reinstalling broke ACLs on inherited files. A failed update could leave the service stopped, so I made it a staged swap with rollback. Reinstalling right after an uninstall raced with the tray process still exiting. Each became a test. That's what I'd point to: designing for least privilege, and then proving it on the real platform rather than trusting unit tests alone."
