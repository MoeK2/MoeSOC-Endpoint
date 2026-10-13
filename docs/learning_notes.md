# Learning notes

One section per roadmap phase: what was built, why SOC analysts care, how it works, the Windows events involved, false positives, and one interview question with a strong answer.

---

## Phase 1: Real-event validation of DET-001 and COR-001

**What was built.** Proof that the authentication rules fire on events Windows itself wrote: a dedicated test account, 7 wrong passwords and 1 correct one through `runas`, then `validate_real_auth.bat` (scan + `verify-evidence`) and `validate_real_gui.bat` (the GUI shows exactly the evidence records).

**Why SOC analysts care.** A rule tested only on synthetic data is a hypothesis. Analysts need to trust that a finding points at real, re-findable records; `verify-evidence` re-reads each EventRecordID from the live log and compares the raw XML.

**How it works.** Windows writes 4625/4624 → collector reads them with an XPath query → parser normalizes → SQLite → rules run over stored events → the finding stores the record IDs → verification re-queries the live log by EventRecordID.

**Important Windows events.** 4625 (failed logon; Status/SubStatus give the reason, e.g. 0xC000006A wrong password, 0xC0000064 no such account); 4624 (successful logon; LogonType 2 interactive, 3 network, 10 RDP).

**False positives.** A user mistyping a password and then succeeding locally produces exactly this sequence; COR-001 therefore scored it LOW.

**Interview question.** "Your brute-force-then-success correlation fired. Is the account compromised?"

**Strong answer.** "Not by itself. I check the logon type and source: a local type-2 success on the same workstation is consistent with a user's typos, so confidence is low. A network or RDP success from the address that was failing is much stronger. I'd confirm with the user, then look at what that logon session did next."

---

## Phase 2: Domain identity normalization

**What was built.** `DomainMap` (`moesoc/core/domains.py`): decides when two domain spellings, such as `CORP` and `corp.local`, are the same Windows authority. It is built once per scan, shared by every rule through `DetectionContext`, and recorded in the finding's evidence (`domain_aliases`, `account_spellings`).

**Why SOC analysts care.** Windows logs the same domain under its NetBIOS name in some events and its DNS name in others. If they are never matched, a brute force split across both spellings stays under the threshold. If they are matched by guesswork, unrelated accounts merge and findings become wrong. Both failures cost analyst trust.

**How it works.**

1. An account SID `S-1-5-21-A-B-C-RID` contains its authority SID `S-1-5-21-A-B-C`.
2. If accounts recorded under `CORP` and under `corp.local` share an authority SID, the names are the same domain.
3. This computer's own NetBIOS/DNS domain and host names (read-only Windows API calls) are added as known facts.
4. Identity keys use the canonical domain; the display keeps what Windows recorded.

**Important details.** Only `S-1-5-21-…` SIDs count: SYSTEM (`S-1-5-18`) appears as both `NT AUTHORITY\SYSTEM` and `WORKGROUP\PC$`, which proves nothing. A name seen with two authority SIDs is ambiguous and never aliased. A renamed computer keeps its machine SID, so the old and new names are correctly linked.

**False positives / risks.** Over-merging is the dangerous failure: it would combine different accounts. Hence no string similarity, no "first DNS label equals NetBIOS name" rule.

**Interview question.** "Why can't you just assume `CORP` is `corp.local`?"

**Strong answer.** "Because the NetBIOS domain name is configured independently of the DNS name; they often match, but not always, and a wrong merge combines different accounts. I'd rather use evidence: accounts in both spellings sharing the same domain SID, or the machine's own domain configuration. Without evidence I keep them separate and accept a possible missed correlation over a false one."

---

## Phase 3: DET-004 Low-and-Slow Authentication Guessing

**What was built.** A rule that finds password guessing spread over an hour: 10+ failures for one account, or 15+ from one source over 2+ accounts, in 60 minutes. Failures already reported by DET-001 (or DET-002 in source mode) are not counted again.

**Why SOC analysts care.** Attackers who know about lockout (Windows 11 default: 10 bad attempts in 10 minutes) and burst rules slow down to one guess every few minutes. Without a long-window rule that activity is invisible.

**How it works.** Group 4625 events by identity (and by source), drop events already inside a DET-001 burst, then slide a 60-minute window over the rest. The finding records the cadence (median/min/max gap and whether the gaps are regular).

**Important Windows events.** 4625 with SubStatus 0xC000006A (wrong password) or 0xC0000064 (no such account); account lockout itself is 4740 (not yet collected).

**False positives.** The big one is stale saved credentials: a phone mail app or mapped drive retrying an old password, often at a perfectly regular interval. That is why confidence is LOW and the cadence is in the evidence.

**Interview question.** "How would you catch password guessing that stays under the lockout threshold?"

**Strong answer.** "Use a longer window than the burst rule, for example 10 failures per account per hour, and exclude what the burst rule already reported so one attack isn't two alerts. Then triage by cadence and failure reason: a perfectly regular interval from the user's own device is usually an old saved password; irregular attempts from an unknown source, or 'no such account' failures, look like guessing."

---

## Phases 4–6: Account creation (4720), privileged groups (4732) and COR-002

**What was built.** Collection of Event 4720 (user account created) and 4732 (member added to a local group), schema v3 for the new fields, DET-005 (new account), DET-006 (account added to a privileged local group) and COR-002 (new account added to administrators within 30 minutes).

**Why SOC analysts care.** Creating a local account and adding it to Administrators is one of the most common persistence moves after an intrusion (`net user x /add` + `net localgroup administrators x /add`). It is also everyday admin work, so the finding has to show who did it, from which logon session, and how quickly the two steps followed each other.

**How it works.** 4720 gives the new account's SID (`TargetSid`). 4732 gives the group (`TargetUserName`/`TargetSid`) and the member (`MemberSid`). Groups are recognised by **well-known SID** (S-1-5-32-544 is Administrators in every language). COR-002 joins the two events by member SID on the same computer, creation first.

**Important Windows events.** 4720 user created; 4732 added to a security-enabled *local* group; 4728/4756 are the global/universal domain-group equivalents (not collected yet); 4741 is a *computer* account created; 4726 user deleted.

**False positives.** Planned onboarding, break-glass admin accounts, LAPS or deployment scripts. DET-005 is LOW by default for this reason; severity rises only with explainable context (a `$`-suffixed name).

**Interview question.** "How do you detect a new local admin account, and why not just match the group name 'Administrators'?"

**Strong answer.** "Correlate 4720 with a 4732 for the same SID shortly after, on the same host. Match the group by its well-known SID S-1-5-32-544, because the name is localized — on German Windows it's 'Administratoren' — and an attacker could create a custom group called 'Administrators'. Then check who did it and from which logon session, and confirm with them."

---

## Phase 7: Event 4672 privileged-session context

**What was built.** Parsing of Event 4672 ("special privileges assigned to new logon") and a session index. When COR-001's successful logon received special privileges, the finding shows which ones, links the 4672 record, and its risk rises from 70 to 80 with the reason written down. 4672 alone never alerts; routine 4672 for SYSTEM/LOCAL SERVICE/NETWORK SERVICE are dropped at collection and counted.

**Why SOC analysts care.** A guessed password for a normal user and a guessed password for an administrator are very different incidents. 4672 tells you the session had admin-level rights (SeDebugPrivilege, SeTakeOwnershipPrivilege…), which changes how fast you respond.

**How it works.** 4624's `TargetLogonId` (the new session) equals 4672's `SubjectLogonId`. Match on computer + logon ID + timestamps within 60 s, because logon IDs repeat after a reboot.

**Important Windows events.** 4624 (logon, with `TargetLogonId` and `ElevatedToken`), 4672 (special privileges for that logon), 4634/4647 (logoff, same logon ID; not collected yet).

**False positives.** None as an alert — that is the point: 4672 fires for every admin and service logon, so alerting on it alone would be pure noise.

**Interview question.** "What is Event 4672 and would you alert on it?"

**Strong answer.** "It's logged when a new logon gets sensitive privileges — basically an admin-equivalent session. I wouldn't alert on it alone, every admin and service logon generates one. I'd use it as context: join it to the 4624 by logon ID and raise the priority of a suspicious logon that turned out to be privileged."

---

## Phase 8: Event 4688 process creation

**What was built.** Parsing of Event 4688 into process name/path, PID, parent PID and path, the creating account and its logon ID, token elevation, integrity level and (if enabled) the command line. Process events are read with their own query and budget so they cannot crowd out logon events. No alert fires on 4688 alone.

**Why SOC analysts care.** "What ran after the suspicious logon?" is the next question after any authentication alert. 4688 answers it from the Security log even without Sysmon, and the logon ID ties each process to the session that started it.

**How it works.** `SubjectLogonId` of 4688 = `TargetLogonId` of the 4624 that started the session. `NewProcessId`/`ProcessId` are hex PIDs (parent-child links). `TokenElevationType` %%1937 means "run as administrator"; `MandatoryLabel` S-1-16-12288 means High integrity.

**Important Windows events and settings.** 4688 needs "Audit Process Creation"; command lines need the separate "Include command line in process creation events" policy. 4689 is process exit (not collected).

**False positives / pitfalls.** PIDs are reused, so a parent-child link also needs time and host. Command lines may contain passwords; don't copy them into logs or summaries.

**Interview question.** "Your logon alert fired. How do you find what the attacker ran?"

**Strong answer.** "Take the logon ID from the 4624 and look for 4688 events with that SubjectLogonId on the same host, in time order. Check parent-child chains like explorer → cmd → powershell, token elevation and integrity level. If command-line auditing is on, read the command lines; if not, note it's unavailable rather than guessing, and look at Sysmon or EDR data instead."

---

## Phase 9: Incremental collection

**What was built.** A saved position (EventRecordID + timestamp) per event group, so each scan reads only new records. Three modes: bootstrap (first run or unusable state), incremental (`EventRecordID > saved`), and recovery (saved record gone: read by time and report the possible gap). The position is saved in the same transaction as the events.

**Why SOC analysts care.** Re-reading 24 hours every time is slow and still misses anything older than 24 h if the tool wasn't run for a day. Worse, a SIEM that silently loses events after a log clear gives false confidence. Telemetry gaps must be visible.

**How it works.** EventRecordID only grows within one log. A pywin32 bookmark is literally `Channel + RecordId` (checked on the real PC), so MoeSOC stores those values itself. Before trusting the position it re-reads that record and compares the timestamp; if it is gone or different, the log was cleared, rolled over or recreated.

**Important Windows events.** 1102 (Security log cleared) explains most resets; the log's maximum size and retention ("overwrite as needed") explain rollovers.

**Pitfalls.** Reading newest-first with a cap is fine for a first look but would skip records in incremental mode, so incremental reads go oldest-first and continue next scan when the budget is hit. After a clear, record IDs can restart at 1, so the old position must not be reused.

**Interview question.** "How would you make sure your collector doesn't miss or duplicate events?"

**Strong answer.** "Keep a watermark — the last EventRecordID and its timestamp — and read forward from it, saving the new watermark atomically with the stored events so a crash means re-reading, not skipping. Deduplicate on host + channel + record ID + time. Before trusting the watermark, check that record still exists; if not, the log was cleared or rolled over, so read by time and report the gap instead of hiding it."

---

## Phase 10: Live monitoring

**What was built.** An optional Live mode: catch up with an incremental scan, subscribe to the Security log with `EvtSubscribe` starting after the saved position, store and detect each batch of new events, and reconnect automatically with backoff. States: OFF, STARTING, ON, RECONNECTING, ERROR.

**Why SOC analysts care.** Detection latency matters: a brute force that succeeds at 02:00 should be visible at 02:00, not at the next manual scan. But a live feed that silently drops events after a service restart is worse than a scheduled scan, so recovery must catch up, not just resubscribe.

**How it works.** Pull subscription with a signal event: the thread sleeps on the kernel event (no busy polling), drains records with `EvtNext`, batches records that arrive together, and upserts findings by a stable key so the same burst never creates a second alert. The subscription starts from a bookmark (Channel + RecordId) with `EvtSubscribeStrict`.

**Pitfalls.** Without the strict flag a stale bookmark can silently start elsewhere; without catch-up after a reconnect, events written during the outage are lost; a GUI that does this work on the UI thread freezes.

**Interview question.** "How would you build a reliable real-time collector for Windows events?"

**Strong answer.** "Persist a position per channel, catch up from it on start, then subscribe from that position. On any failure, back off, catch up again from the saved position, and resubscribe, so restarts never create gaps. Store and update the position in the same transaction, dedupe events, and make alerts idempotent with stable keys so replays don't duplicate them. Keep it off the UI thread and surface its state."

---

## Phase 11: Sysmon detection and setup support

**What was built.** The Health check now distinguishes "Sysmon log readable", "service stopped", "service without log" and "not installed", names the variant (standalone Sysinternals or built-in Windows feature, inferred from the service binary path), and points to `docs/sysmon.md`. MoeSOC never installs or reconfigures Sysmon.

**Why SOC analysts care.** The Security log shows *who logged on*; Sysmon shows *what ran, what it connected to, which domains it resolved*. Knowing whether that visibility exists on an endpoint is part of every investigation ("absence of evidence" vs "no telemetry").

**How it works.** Read-only: probe the `Microsoft-Windows-Sysmon/Operational` channel, and query the `Sysmon64`/`Sysmon` service status and binary path with the Service Control Manager.

**Important facts.** Built-in Sysmon is an optional feature in recent Windows 11 / Server 2025, disabled by default, enabled with DISM then `sysmon -i`; standalone Sysmon must be removed first. Both write to the same channel. Configuration decides volume and value.

**Interview question.** "Why wouldn't your tool just install Sysmon if it's missing?"

**Strong answer.** "Installing a kernel driver and choosing what gets logged is a change-management decision with performance and privacy impact. A monitoring tool should report the gap clearly and document the options, not silently change the endpoint or overwrite an existing config someone tuned."

---

## Phase 12: Sysmon Event 1 (process create)

**What was built.** A Sysmon parser and collector. Event 1 is normalized (user, logon ID, process and parent GUID/PID/image, command line, integrity, hashes, plus details), stored with schema v5 columns for GUIDs, and collected incrementally beside the Security log. Missing Sysmon is recorded, not an error.

**Why SOC analysts care.** Sysmon Event 1 is richer than Security 4688: hashes for reputation checks, parent command line, and a process GUID that survives PID reuse, which makes process trees reliable.

**How it works.** The generic `ChannelCollector` runs the same bootstrap/incremental/recovery logic on any channel; Sysmon gets one group per event family. Sysmon's `LogonId` is reformatted to the Security log's spelling so a process joins the 4624 that created its session.

**Pitfalls.** The event's `System/Security/@UserID` is the Sysmon service (SYSTEM), not the process user — use the `User` field. Hashes depend on the Sysmon config. Volume depends on the config too.

**Interview question.** "Sysmon Event 1 or Security 4688 — which would you rather have, and why?"

**Strong answer.** "Sysmon 1 if I can: it has hashes, the parent command line, and ProcessGuid, which identifies a process uniquely even when Windows reuses the PID — so process trees don't link the wrong parent. 4688 is built in and still valuable, especially with command-line auditing on, but it only has PIDs and no hashes."

---

## Phase 13: Process tree

**What was built.** Ancestors and descendants of any process event, built in SQLite from Sysmon GUIDs (exact) or Security 4688 PIDs (weaker, PID-reuse aware), shown in a Process Tree page and the `process-tree` CLI, with pivots to raw event, process, user and time.

**Why SOC analysts care.** Parent-child chains tell the story: `winword.exe → cmd.exe → powershell.exe` is a classic macro chain; `services.exe → cmd.exe` suggests a service. The analyst decides; the tool shows the evidence.

**How it works.** Sysmon: join `ParentProcessGuid` to `ProcessGuid`. 4688: the parent is the most recent process with that PID that started **before** the child on the same host; children are verified the same way, so a reused PID never adopts someone else's children.

**Pitfalls.** PIDs are reused quickly; the parent may have started before collection began (shown as "parent not collected"); inconsistent data could create loops (cut).

**Interview question.** "Why is a 4688-based process tree less reliable than a Sysmon one?"

**Strong answer.** "4688 links processes by PID, and Windows reuses PIDs, so a child can be attached to the wrong parent unless you also use time and host. Sysmon gives every process instance a ProcessGuid and records the ParentProcessGuid, so the link is exact. I'd label PID-based links as weaker and confirm with timestamps."

---

## Phases 14–17: Sysmon network (3), file (11), registry (13) and DNS (22)

**What was built.** Parsing and incremental collection of the four Sysmon context events, each family with its own budget, timeline summaries, an OBJECT column in Events, and an IP filter that also matches connection destinations. No rule fires on these events alone.

**Why SOC analysts care.** After "which process ran", the next questions are "what did it talk to, what did it write, did it persist, which domains did it resolve". Run-key writes (Event 13) and downloads to Temp (Event 11) are classic persistence and staging traces; DNS (22) ties a process to a domain even when the connection itself is encrypted.

**How it works.** Every Sysmon event carries the ProcessGuid of the process that caused it, so context joins the process tree exactly. DNS results are parsed into IP addresses so a later connection to that IP can be linked back to the lookup.

**False positives.** Endless: browsers connect, installers write Run keys, updaters create files. That is why these are context, scored only inside a correlated story (Phase 21+).

**Interview question.** "Would you alert on every outbound connection from PowerShell?"

**Strong answer.** "No — admin scripts and module installs do that all day. I'd keep it as context and raise it only in combination: a PowerShell process spawned from an unusual parent, shortly after a suspicious logon, resolving a rare domain and then connecting to it. The correlation explains why it matters; a single connection doesn't."

---

## Phase 18: PowerShell Script Block Logging (4104) and DET-007

**What was built.** Collection of PowerShell Event 4104 (incremental, its own budget), a parser that keeps identity, hash and length but **not** the script text, reassembly of split scripts, and DET-007, which scores explainable indicators plus the PowerShell process's parent and command line.

**Why SOC analysts care.** Attackers love PowerShell because it is on every machine. Script Block Logging records the code **after** decoding, so `-EncodedCommand` and many obfuscation layers no longer hide what ran.

**How it works.** Fragments with the same ScriptBlockId are joined in MessageNumber order, then matched against indicator patterns; each adds points with a reason. The PowerShell PID is joined to Sysmon 1 / Security 4688 to add the parent and command line. Findings carry short excerpts and the SHA-256, never the whole script.

**Important facts.** 4104 records the user's SID, not the name. Without the policy, Windows PowerShell 5.1 still logs "suspicious" blocks at Warning level. PowerShell 7 logs to a different channel. Script blocks can contain passwords and tokens: treat them as sensitive data.

**False positives.** Installers downloaded and run by admins, Defender exclusions set by IT, security tools that mention AMSI, red-team exercises.

**Interview question.** "An attacker runs `powershell -enc <base64>`. What can you see, and where?"

**Strong answer.** "Process creation (Sysmon 1 or 4688 with command lines) shows the encoded command and the parent — `winword.exe → powershell -enc` is already suspicious. Script Block Logging (4104) shows the decoded script itself, so I can read whether it downloads and executes something, touches AMSI or Defender, or dumps credentials. I'd score those behaviours together rather than alert on `-enc` alone, and I'd keep the script text local because it may contain secrets."

---

## Phases 19–20: Microsoft Defender detections (1116) and remediation correlation (1117–1119)

**What was built.** Collection and parsing of Defender's detection and action events, and DET-008: one finding per Defender Detection ID, joined with the latest action, with a clear remediation state (remediated, action failed, allowed, action recorded, no action recorded).

**Why SOC analysts care.** "Defender caught it" is not the end of the story. The first question is "did the remediation work?" A quarantined download is routine; a failed removal or an allowed threat means the threat may still be present and needs hands-on work. The second question is "how did it get there?" (user, process, origin).

**How it works.** Every Defender event carries the Detection ID GUID, so the join is exact, not time-based. Actions can arrive later than the detection, so the scanner loads earlier Defender events with the same ID (up to 7 days) and the finding is keyed by the Detection ID, so it is updated rather than duplicated.

**Important facts.** Field names contain spaces. `Path` lists several resources (`file:_`, `containerfile:_`, `webfile:_…|URL|…`, `process:_pid:…`). Severity comes from Defender (Low/Moderate/High/Severe). The EICAR test file is detected as `Virus:DOS/EICAR_Test_File` — a harmless standard test string.

**False positives.** Test files, admin tools flagged as hacking tools or PUA, Defender false positives on new software.

**Interview question.** "Defender logged 1116 for a Trojan on a workstation. What do you check first?"

**Strong answer.** "Whether remediation succeeded: is there a 1117 with a successful quarantine or removal for the same Detection ID, or a 1118/1119 failure? Then where it came from — the path, the origin (internet, USB, share), the user and the process that wrote it — and what happened around that time in the process tree. A successful quarantine of a download is low urgency; a failed action or an executed file is an incident. I'd report it as Defender's verdict, not my own."

---

## Phase 21: Cross-source correlation engine (COR-003, COR-004)

**What was built.** An activity graph that links events across the Security, Sysmon, PowerShell and Defender logs by shared identifiers (logon ID, ProcessGuid, file path, Defender Detection ID, PID), plus two correlations that use it: COR-003 (failed logons → success → suspicious activity in the same session) and COR-004 (Defender detection → the process that wrote the file → its DNS and connections → whether the file ran). Each finding shows the chain step by step with the link used and its strength.

**Why SOC analysts care.** Single events are noisy; attacks are sequences. The analyst's real question is "what happened next, in that same session or process?" Following identifiers across logs answers it without guessing from timestamps.

**How it works.** Windows already gives the join keys: 4624's TargetLogonId reappears as SubjectLogonId in 4688/4720/4732 and as LogonId in Sysmon; every Sysmon event carries the ProcessGuid of its process; Defender names the file path, which Sysmon 11 recorded when it was written. Where only weaker keys exist (PID, user + time) the finding says so and confidence drops.

**Pitfalls.** Logon IDs repeat after a reboot (bound by time and computer). SYSTEM/service logon IDs (0x3e7, 0x3e4, 0x3e5) are shared by everything and must never be treated as a session. Sysmon network/file data is huge, so it is fetched by key, not loaded wholesale.

**Interview question.** "How would you prove that suspicious PowerShell was run by the attacker who just brute-forced an account, rather than by the real user?"

**Strong answer.** "I can't prove intent from logs, but I can tie the events together exactly: the 4624 after the failures has a TargetLogonId; the PowerShell process (Sysmon 1 or 4688) carries the same logon ID; its PID matches the 4104 script block. That chain shows the script ran in the session that the suspicious logon created. Then I'd check the source address and ask the user — the logs show linkage, the investigation establishes who."

---

## Phase 22: Investigation Stories

**What was built.** A Story view (GUI page and `story` CLI command) that combines a finding with related findings — those that share evidence events, or concern the same account at overlapping times on the same computer — and tells their evidence in time order. Repeated events collapse into one step, each step names the findings it supports, and the story ends with what the data cannot tell, next steps (from the rules) and analyst notes.

**Why SOC analysts care.** Analysts hand incidents over and write tickets. A story answers "what happened, in what order, and how sure are we?" in one place, instead of five separate findings that each show a slice. Stating the gaps ("no Sysmon on this host, so process activity is unknown") prevents the classic mistake of reading missing telemetry as "nothing happened".

**How it works.** Built on demand from SQLite: related findings via the shared `detection_events` links, evidence events by primary key, coverage by checking which sources recorded anything for that computer around the story. Nothing is cached, so it always reflects current triage state and notes. Summaries reuse the one-line explanations, which never contain command lines or script text.

**Interview question.** "Your tool raised a brute-force alert and a new-admin-account alert on the same host. How do you present that to the incident lead?"

**Strong answer.** "As one story, not two alerts: the failed logons, the successful logon, and the account creation in that same logon session, in order, with the identifiers that link them. Then what we don't know — for example, without process telemetry we can't see what else ran — and the next steps: confirm with the user, check the source IP, disable the new account. The lead needs sequence, confidence and gaps, not a list of rule IDs."

---

## Phase 23: Explainable risk engine

**What was built.** One risk model applied to every finding after the rules run: a base from severity plus a short list of documented modifiers (low confidence, privileged session, Defender remediation outcome, executed file, multi-log corroboration), clamped to 0–100, with each factor stored and shown. The Overview names the finding that sets the endpoint score.

**Why SOC analysts care.** Queues are long; the score decides what gets looked at first. An unexplained number is not trusted and cannot be tuned. When every point has a reason ("+10: the logon had SeDebugPrivilege"), an analyst can disagree with a specific factor instead of ignoring the score.

**How it works.** `assess_risk()` reads only the finding's own evidence, so it is deterministic and testable. Severity says how bad it would be; confidence says how sure we are; context factors move priority without pretending to change either.

**Pitfalls.** Risk is not likelihood: a remediated EICAR test is still "HIGH" severity by Defender's label but lower priority (−15). Keep modifiers few and documented, or the score becomes impossible to reason about.

**Interview question.** "How do you stop a risk score from becoming a black box?"

**Strong answer.** "Make it additive and small: a base from severity, a handful of named modifiers taken from the evidence, each stored with its reason, and a clear statement that it's for prioritization, not probability. Then anyone can see why a finding is 85 instead of 70 and challenge a specific factor."

---

## Phase 24: Search and pivots across every source

**What was built.** Database-side filters for every field MoeSOC normalizes (provider, SID, ports, logon session, parent process, file and registry paths, DNS names, Defender threat names), escaped `LIKE` matching, paging by `LIMIT/OFFSET`, an Events "More filters" row, CLI flags, and Timeline pivots generated from whatever the selected event recorded.

**Why SOC analysts care.** Investigation is pivoting: from an alert to the user, from the user to the session, from the session to the processes, from a process to the domain it resolved. Each pivot should be one click and should not load the whole database into memory.

**How it works.** One `_where()` builder turns an `EventFilter` into parameterized SQL (no string-built values, wildcards escaped). Defender threat names live in the normalized JSON details and are matched with `json_extract`, limited to Defender rows. Indexes from schema v6 cover paths, destinations and DNS names.

**Interview question.** "An analyst finds a suspicious domain in one DNS event. What pivots do you want next?"

**Strong answer.** "Which processes looked it up (Sysmon 22 by name), what those processes connected to (by ProcessGuid or destination IP), who ran them (logon session back to the 4624), and whether other hosts resolved it. Every pivot should be a filter on recorded fields, so the answer is reproducible."

---

## Phase 25: Data retention

**What was built.** A retention period (7/30/90 days, default 30, stored in the database's new `settings` table, schema v7), a preview that counts what would be deleted, and a confirmed, single-transaction deletion of MoeSOC's own old events, closed findings (with notes, history and evidence links) and unused scan records. Open findings and all their evidence are always kept. Windows logs are never touched — the module does not even import event-log code, and a test checks that.

**Why SOC analysts care.** Telemetry grows without bound, and keeping personal activity data longer than needed is a privacy risk. But deleting evidence of an open case is worse. Good retention is predictable: you can see what will go before it goes.

**How it works.** Constant SQL with bound parameters. Order matters: closed findings first (cascading their links), then events not protected by a remaining finding, then scans no remaining finding references, keeping the newest scan.

**Interview question.** "Your EDR database is full. How would you design retention without hurting investigations?"

**Strong answer.** "Age-based deletion of raw telemetry, but never evidence attached to open cases; closed cases can expire with their evidence after the period. Make it previewable and auditable, run it in one transaction, and never confuse your own copy with the source logs — retention in my tool must not delete Windows logs."

---

## Phase 26: Rule tuning and auditable suppressions

**What was built.** A Tuning page and CLI to disable rules, change their numeric thresholds within bounds, and suppress future findings by exact value (account, source IP, host, process, file, Defender threat) with scope and expiry. Every change requires a reason and lands in an audit log; nothing is hard-deleted, and existing findings are never touched.

**Why SOC analysts care.** Untuned detections drown analysts in noise; uncontrolled suppressions hide attacks. The professional answer is narrow, explained, expiring exceptions with an audit trail — so in six months someone can see who silenced what, why, and how often it fired since.

**How it works.** Overrides are stored in SQLite and merged into the rule metadata at scan time (only parameters that already exist as integers). After the rules and the risk model run, each finding is checked against the active suppressions; matches increment a hit counter instead of creating a finding.

**Pitfalls.** Broad suppressions (wildcards, whole hosts forever) are blind spots — hence exact values, required reasons, optional expiry and hit counts. Tuned thresholds change what a finding means, so the finding records the values it used.

**Interview question.** "A vulnerability scanner triggers your password-spray rule every night. What do you do?"

**Strong answer.** "Confirm it is the scanner (source address, schedule, owner), then add a narrow suppression for that source address on that rule only, with a reason and an expiry, and review its hit count. I would not disable the rule or raise the threshold globally, because that would blind me to a real spray from anywhere else."

---

## Phase 27: HTML reports

**What was built.** Finding reports (built from the investigation story, plus confidence and risk factors and triage history) and an endpoint summary, exported as single HTML files with inline CSS only, from the Reports page or `report` CLI. An optional redaction pass replaces computer names, accounts, domains, SIDs and IP addresses with stable placeholders.

**Why SOC analysts care.** Findings have to leave the console: escalations, tickets, management updates, peer review. The report must be readable without the tool, must not leak secrets (command lines, scripts), must be honest about data gaps, and should be safe to share — hence redaction.

**How it works.** Plain string building with `html.escape` on every value; no templates that could execute code, no JavaScript, no external links. Redaction maps each distinct value to `HOST-n`/`USER-n`/`DOMAIN-n`/`SID-n`/`IP-n` so the narrative still makes sense ("USER-1 failed 6 times from IP-1"). Well-known SIDs and loopback addresses are kept because they identify no one.

**Pitfalls.** HTML injection through telemetry (a user name like `<script>`) — tests feed hostile values. Redaction by regex can miss values that never appeared in evidence; the report says what was redacted rather than promising anonymity.

**Interview question.** "What belongs in an incident report for a suspected account compromise?"

**Strong answer.** "A one-line summary with severity and confidence, the timeline of what the logs show with the identifiers that link the events, why the tool scored it that way, what we could not see, what was done (triage, notes) and what should happen next. No secrets from command lines, and redacted identities if it leaves the team."

---

## Phase 28: Benchmarks

**What was built.** A reproducible benchmark (`scripts/benchmark.py`, `benchmark.bat`) that times parse, store, detect, search, story and report at 1k/10k/50k/100k synthetic events in a throwaway database, saving JSON with the machine description (no host name). Results from the Windows PC and the Linux sandbox are in `docs/benchmarks.md`.

**Why SOC analysts care.** A tool that freezes during a busy day gets switched off. Knowing that a 50,000-event scan takes seconds, and where time goes, tells you which limits are safe and what to optimize.

**How it works.** `time.perf_counter()` around each stage; the same generator for every size so results are comparable; synthetic data clearly labelled, timings real.

**What it showed.** Parse and detect scale linearly; storage gets slower than linear at 100k (index maintenance), which is the first thing to optimize if scans grow. Raw XML dominates disk use.

**Interview question.** "How would you prove your detection pipeline scales?"

**Strong answer.** "Measure, don't estimate: a fixed synthetic workload at several sizes, each stage timed separately, on the real target hardware, with results versioned. Then look at the growth curve — linear is fine, super-linear tells you where to dig — and state what the benchmark does not cover, like event-log read time."

---

## Phase 29: Application icon

**What was built.** An original icon (shield + detection pulse) generated from geometry by a script, exported as a multi-size Windows `.ico`, used for the window, taskbar (with an explicit AppUserModelID) and Desktop shortcut.

**Why it matters.** A security tool is judged on trust at first glance; a generic Python icon on the taskbar looks unfinished. Generating the icon from code keeps it reviewable and free of licensing questions.

**How it works.** Each size is drawn separately at 8× and downsampled with Lanczos; small sizes use a simplified, heavier design because a 16-pixel icon is not a scaled-down 256-pixel one.

**Interview question.** "Why does a Python desktop app often show the Python icon in the Windows taskbar, and how do you fix it?"

**Strong answer.** "Windows groups taskbar buttons by AppUserModelID, which defaults to the host executable — python.exe. Setting an explicit ID with SetCurrentProcessExplicitAppUserModelID before creating windows, plus a window icon, makes the app show and group under its own icon. A packaged executable also embeds the .ico."

---

## Phase 31: Packaging

**What was built.** A PyInstaller one-folder build (`MoeSOC.exe`, windowed, icon and version resource, rules bundled), start-up logic for the executable (single instance, one standard UAC prompt, limited mode if declined), a `--self-test` mode verified on Windows, and an Inno Setup script for `MoeSOC-Setup-x64.exe` that keeps user data on uninstall.

**Why it matters.** Analysts and reviewers will not set up a Python environment. A tool that installs like any Windows program, asks for elevation the standard way, and explains what it will and will not do gets used and trusted.

**How it works.** PyInstaller freezes the interpreter, PySide6, pywin32 and the code; data files are found through `sys._MEIPASS`. The executable runs "as invoker" and requests elevation itself, so it can still run its self-test unattended. One-folder (not one-file) starts faster and avoids unpacking to a temp folder on every start, which antivirus tools dislike.

**Pitfalls.** UPX compression and one-file self-extraction trigger antivirus heuristics; unsigned executables trigger SmartScreen; hidden imports (pywin32 modules) must be declared; a `*.spec` ignore rule can silently drop the build recipe from git (fixed here).

**Interview question.** "Why should a security tool request elevation at runtime instead of embedding requireAdministrator in its manifest?"

**Strong answer.** "Both use the standard UAC prompt, but runtime elevation lets the same binary do unprivileged things — a self-test, showing a clear 'not elevated' state if the user declines, focusing an already-running instance without a second prompt. It also makes the privilege boundary explicit and testable in code."

---

## Phases 32–33: Release preparation and Windows CI

**What was built.** Version 1.0.0 across the package, executable resource and installer (a test keeps them in sync), a changelog, draft release notes and an owner checklist; a GitHub Actions workflow on Windows that lints, tests, runs the CLI and the GUI smoke test offscreen, builds the executable and self-tests it; and `ci_local.bat` to run the same steps on a PC.

**Why it matters.** A release is a promise that the artifact matches the code and the tests. CI on the target OS catches what a Linux-only pipeline cannot (pywin32, Qt platform plugins, the event-log API, elevation).

**How it works.** The CI test job mirrors the PC's verification script; the build job proves the frozen executable starts and finds its data by running its self-test, then publishes checksums. Publishing itself stays a human step that needs credentials and a privacy review of the history.

**Interview question.** "Why run a Windows security tool's CI on Windows runners, and what can't CI tell you?"

**Strong answer.** "Because the risky parts are Windows-specific: event-log APIs, privileges, packaging. Runners are elevated, which tests admin paths but can hide permission bugs, so I also test non-elevated behaviour locally. CI can't tell me how real attacks look on real endpoints or how analysts use the tool — that needs real-machine validation, which I track separately."

---

## Phases 34–35: Final README and portfolio demo

**What was built.** A README that describes what the tool does today (and what it does not), a testing guide covering every module, refreshed screenshots from the final code, and an explicit demo mode: a synthetic attack story in a separate, marked database, imported through the normal pipeline, with the window labelled DEMO and collection disabled.

**Why it matters.** A portfolio demo must be honest: an interviewer should never wonder whether the findings are real. Labelling synthetic data everywhere, and making it impossible to mix with real telemetry, is the same discipline a SOC applies to test data in production systems.

**What the final review found.** Reviewing the demo's redacted report showed one person getting two placeholders (keyed by `DOMAIN\user`); reviewing the demo Overview showed the real computer's Health next to synthetic findings. Both were fixed with tests. Reading your own output as a user would is part of verification.

**Interview question.** "Walk me through a detection you built, end to end."

**Strong answer.** "COR-003: six failed logons, then a success — COR-001 flags that. COR-003 then follows the new session's logon ID into Sysmon and Security events: PowerShell started from Word with an encoded command, a hidden admin account created by that same session. Each link is exact and labelled; a Defender detection for the same user is linked more weakly and labelled as such. The finding explains its confidence and risk, the story lists what the data can't tell, and I can export a redacted report. It's a lead, not proof — the next step is confirming with the user and the source address."

---

## Correctness session after the audit (A-1 to A-11)

**What was fixed.**

- **A-1:** a finding's identity was "first record of the visible burst". The live window slides, so one campaign became 22 findings. A finding is now a *campaign*: the rule, host, identity or source, and mode. The campaign continues while the gaps between events stay within the rule window.
- **A-2:** the domain in Event 4625 is whatever the client typed. It is now kept as a *claim* and resolved separately from the identity authority.
- **A-3:** evidence is re-parsed with the parser of its own channel.
- **A-4:** the subscription drains once on open instead of waiting for a signal that may never come for records that already exist.

**Why it matters.** Duplicate findings waste analyst time and split triage history. A field the attacker controls must never decide who the victim is. A false "mismatch" teaches analysts to ignore the integrity check. A live monitor that misses events is worse than none, because it looks healthy.

**Lesson about validation.** The first real live-delivery run reported FAILED. In fact the trigger event was never written: process auditing was off. A test has to prove that its stimulus happened before it judges the system. The script now says INCONCLUSIVE in that case.

**Interview question.** "An attacker sends failed logons with a different domain each time. What happens in your tool?"

**Strong answer.** "The typed domain is treated as a claim, not an identity. Without a SID, an empty, '.', or own-computer domain is the local account. A domain I have seen proven by a SID or a successful logon stays separate. On a computer I can prove has only local accounts, invented domains resolve to the local account, so the brute-force rule still fires. The claimed domains stay visible in the evidence, which is itself a useful signal. I never merge two proven domains on the user name alone."

---

## Always-on sensor (service, tray, console)

**What was built.** The monitoring half of MoeSOC is now a Windows service: `MoeSOCSensor`, running as a virtual account in *Event Log Readers*. It catches up, subscribes to the Security, PowerShell, Defender and (when present) Sysmon logs, and sleeps on Windows' signals until records arrive. A small pywin32 tray in the user's session shows status and toasts. Clicking a toast opens the exact finding in the existing console.

**Why it matters.** A detection tool that only works while its window is open misses everything that happens while it is closed. The split also enforces least privilege:

- the privileged part has no GUI and a tiny IPC surface;
- the user-facing parts run without administrator rights.

**What was hard.**

- *Session 0.* A service cannot show anything, so notifications must cross a process boundary to the tray.
- *Privileged writers.* A SYSTEM process writing into `%LOCALAPPDATA%` can be redirected with junctions. The sensor therefore owns a protected `%ProgramData%` folder instead.
- *Pipe squatting.* `FILE_FLAG_FIRST_PIPE_INSTANCE` stops a user process from taking the name first, users get no right to create pipe instances, and the client verifies the server's account.
- *A real race.* With no saved position, subscribing "from new events" after the catch-up lost a record written in between. The Windows test run found it, and the fix is to remember the newest record before catching up.

**Interview question.** "Why not just run your GUI at startup with admin rights?"

**Strong answer.** "Because then the most exposed process — the one parsing rich UI input — holds the highest privilege, and monitoring stops whenever someone closes a window. I put collection and detection in a service with no UI and least privilege: a virtual account in Event Log Readers, SeChangeNotifyPrivilege only, and code under Program Files. The tray and console talk to it over a local named pipe with a strict allow-list, and nothing in that protocol can run commands or touch files. Notifications are per finding with persisted dedup, so one brute-force campaign is one toast, not fifty."
