# Detections

Every rule has a YAML file under `rules/` (version, metadata, MITRE mapping, thresholds, false positives, investigation steps) and a Python function (the logic). **A detection is an investigation lead, not proof of compromise.**

| ID | Version | Name | Severity | Confidence | MITRE |
|---|---|---|---|---|---|
| DET-001 | 1.1 | Multiple Failed Logins | MEDIUM | MEDIUM | T1110 |
| DET-002 | 1.0 | Password Spray Behavior | MEDIUM | MEDIUM | T1110.003 |
| DET-003 | 1.0 | Windows Security Log Cleared | HIGH | HIGH (that it happened) | T1070.001 |
| COR-001 | 2.0 | Possible Account Compromise | HIGH | derived per finding: LOW / MEDIUM / HIGH | T1110, T1078 |

## Background: the events

| Event | Meaning | It is *not* |
|---|---|---|
| 4624 | A logon session was created | Malicious by itself: thousands occur daily (services, SYSTEM, network shares) |
| 4625 | An account failed to log on | An attack by itself: people mistype passwords |
| 1102 | The Security audit log was cleared | Proof of an attacker: administrators clear logs too |

The 4625 `SubStatus` tells the analyst why a logon failed:

| SubStatus | Meaning | What it suggests |
|---|---|---|
| `0xC000006A` | Wrong password | The account exists: guessing or a typo |
| `0xC0000064` | Account does not exist | Username enumeration or spraying |
| `0xC0000234` | Account locked out | Guessing continued past the lockout threshold |
| `0xC0000072` | Account disabled | Someone is trying an old account |

The logon types that matter most here: 2 (interactive), 3 (network, e.g. SMB), 5 (service), 7 (unlock), 10 (RDP).

## Account identity (applies to every authentication rule)

Two events belong to the same account only if their **identity keys** match (`moesoc/core/identity.py`). In order of preference:

1. **SID.** Unique per account, and survives renames. The NULL SID `S-1-0-0` is ignored.
2. **DOMAIN\user**, case-insensitive. `CORP\admin` and `PC01\admin` are different accounts. A domain of `.` means "this computer".
3. **HOST\user** when no domain was recorded, so a local account is scoped to the computer that logged it.
4. **user** alone, only as a last resort.

**Why a resolver is needed.** A failed logon (4625) usually records the NULL SID, because the account might not exist. The matching 4624 records the real SID. `IdentityResolver` links a name-only event to a SID when exactly one SID was seen for the same DOMAIN\user in the analyzed events. Ambiguous names (one name with several SIDs, e.g. an account deleted and re-created) are never merged. Every finding stores its identity basis and SID in its evidence.

**Domain spellings (`moesoc/core/domains.py`).** Windows writes the same domain as `CORP` (NetBIOS) in most Security events and as `corp.local` (DNS) in others. MoeSOC treats them as one domain **only with evidence**, never from the spelling, because a NetBIOS name is configured independently of the DNS name:

| Evidence | Strength | Example |
| --- | --- | --- |
| Accounts under both names share an **authority SID** (`S-1-5-21-A-B-C`, the account SID without its RID) | Strong: the SID identifies the issuing domain | `CORP\svc` = `S-1-5-21-1-2-3-1201`, `corp.local\web` = `S-1-5-21-1-2-3-1202` |
| **This computer's configuration** (NetBIOS ↔ DNS domain, short ↔ fully qualified computer name), read-only from Windows | Strong for this computer's own domain | Joined to `CORP` / `corp.local` |

Safety rules: only `S-1-5-21-…` SIDs count (SYSTEM appears as `NT AUTHORITY` *and* as `WORKGROUP`, which proves nothing); a name seen with two different authority SIDs is ambiguous and never aliased; no prefix or first-label guessing. The result is built once per scan (`DetectionContext`) and shared by every rule. A finding whose events used several spellings lists them in `account_spellings`, and its identity lists the alias and its reason in `domain_aliases`.

## DET-001: Multiple Failed Logins

- **Logic:** 5 or more Event 4625 records for the same **identity** within a rolling 5-minute window.
- **Algorithm:** a sliding window over each identity's failures, ordered by event time; the record ID breaks ties, and input order is irrelevant. Windows that overlap merge into one *burst*, so a 40-attempt attack is one finding with `failure_count: 40`. The window boundary is inclusive.
- **Evidence:** identity (basis, SID), count, first and last failure, source addresses, workstations, logon types, authentication packages, failure reasons, EventRecordIDs.
- **False positives:** forgotten password; stale saved credentials; a service or task with an old password; admin activity; authorized testing.

## DET-002: Password Spray Behavior

- **Logic:** one **source** fails against 5 or more **distinct identities** within a rolling 30-minute window.
- **Source:** the IP address (IPv4-mapped IPv6 is normalized), or the workstation name when no IP was recorded. Failures with neither are skipped.
- **Why it is separate from DET-001:** brute force is many guesses against one account. Spraying is a few guesses against many accounts, which stays under per-account lockout limits and never triggers DET-001. Both can fire on the same activity when an attacker does both; they describe different behaviors.
- **Defaults:** 5 accounts / 30 minutes. Both are tunable in YAML. Case variants of one name count once; the same name in two domains counts twice.
- **Evidence:** source, distinct account count, accounts tried (up to 50), failures on non-existent accounts (an enumeration hint), failure reasons, logon types, EventRecordIDs.
- **False positives:** shared or kiosk computers; services running as several accounts; scanners or authorized tests; jump hosts and proxies.

## DET-003: Windows Security Log Cleared

- **Logic:** every Security Event 1102.
- **Parsing:** 1102 is logged by `Microsoft-Windows-Eventlog`, and its payload is in `<UserData><LogFileCleared>…`, not in `<EventData>`. The generic parser reads both formats by element name (`parsers/windows_event.py`). Deeper nested structures are ignored rather than guessed.
- **Confidence HIGH** means Windows itself recorded the clearing. It says nothing about intent.
- **Evidence:** actor (DOMAIN\user, SID, logon ID), time, computer, EventRecordID.
- **False positives:** authorized maintenance; lab work; troubleshooting.

## DET-004: Low-and-Slow Authentication Guessing

- **Logic (identity mode):** 10 or more Event 4625 records for one identity within a rolling **60-minute** window.
- **Logic (source mode):** 15 or more failures from one source over **2 or more** identities within 60 minutes. A single-account source is left to identity mode, so one slow attack is one finding.
- **No double reporting:** failures already inside a DET-001 burst are not counted (identity mode); source mode also skips failures inside a DET-002 spray window. The exclusion uses the loaded DET-001/DET-002 parameters, and the finding states how many were excluded. If DET-001 is not loaded, nothing is excluded.
- **Why these defaults:** Windows 11 locks an account after 10 invalid attempts in 10 minutes by default. A careful attacker stays below that and below DET-001 (5 in 5 min), for example one guess every 5–6 minutes, which is 10+ in an hour. A person mistyping rarely reaches 10 failures in an hour for one account.
- **Machine accounts** (`HOST$`) are ignored by default (`ignore_machine_accounts`): their slow failures are almost always a broken secure channel.
- **Evidence:** mode, identity or source, accounts, count, first and last failure, sources, logon types, failure reasons, EventRecordIDs, and the **cadence**: median, shortest and longest gap, and `regular_interval` (every gap within 10% of the median), which points at a device or script retrying an old password.
- **Severity / confidence:** MEDIUM / **LOW**, because stale saved credentials (phones, mapped drives, services) produce exactly this pattern. MITRE T1110, T1110.001.
- **Each Windows record counts once**, even if the input repeats it, and input order does not matter.

## COR-001: Possible Account Compromise

- **Logic:** a 4624 for an identity that was preceded by 5 or more 4625s for the same identity in the 10 minutes before it (inclusive). Several successes after the same burst are reported once.
- **Why correlation is stronger:** one failed logon is noise, and one successful logon is normal. The *sequence* is what a successful password guess looks like. It is also what a user who finally types the password correctly looks like, so the confidence is derived from the evidence, not fixed.

### Confidence scoring (explainable)

Each factor adds or removes points. The panel and `moesoc-cli show` list every factor that applied.

| Factor | Points |
|---|---|
| Success was a network logon (type 3, 8 or 10) | +2 |
| Success was a local interactive logon (type 2, 7 or 11) | −1 |
| Success came from a remote address (not loopback or missing) | +1 |
| …and that same remote address also produced failures | +1 |
| Failures came from 3 or more different addresses | +1 |
| 10 or more failures (twice the threshold) | +1 |
| Same workstation and logon type as the failures, with no remote address | −1 |

Total ≤ 0 → **LOW** · 1–2 → **MEDIUM** · ≥ 3 → **HIGH**. Severity stays HIGH regardless; severity is impact, confidence is evidence strength.

**Examples:** five wrong passwords at the console, then the right one: −2 → LOW. Five failures and then an RDP success, all from 198.51.100.7: +4 → HIGH.

- **Evidence:** identity; the failure record IDs and the success record ID; failure source IPs and the success IP; workstations; logon types; authentication packages; failure reasons; first and last failure and the success time; whether the success IP, logon type and workstation matched the failures; total attempts; distinct source count; the success logon ID; the confidence breakdown.
- **Privileged session context (4672, v2.2):** if Windows wrote Event 4672 ("special privileges assigned to new logon") for the successful logon — same computer, `SubjectLogonId` equal to the 4624's `TargetLogonId`, within 60 seconds — the finding shows the privileges (sensitive ones such as SeDebugPrivilege first), links the 4672 record as evidence, and its **risk** rises by 10 with the reason listed in `risk_factors`. Confidence does not change: privileges say how bad a compromise would be, not whether it happened.

## Event 4672: context only

- Every administrator and service logon produces a 4672, so it is never a finding on its own.
- 4672 for SYSTEM, LOCAL SERVICE and NETWORK SERVICE (S-1-5-18/19/20) are counted and not stored (`filtered` in the collection result); they carry no investigative value and would double the stored volume.
- Logon IDs are unique only until restart, so a match also requires the same computer and a timestamp within 60 seconds.
- **UAC split tokens:** an administrator's interactive logon creates a filtered and an elevated session, each with its own 4624 naming the other in `TargetLinkedLogonId`. 4672 belongs to the elevated one, so MoeSOC checks both the logon ID and the linked logon ID.

## Event 4688: process creation (telemetry, not a rule)

- **Requires** the audit policy "Audit Process Creation" (Success). Command lines appear only when "Include command line in process creation events" is also enabled. MoeSOC never changes either setting; when the command line is missing it shows **Unavailable**.
- **Normalized:** new process path/name and PID, creator PID and (Windows 10+) parent path, the creator's account and logon ID (`SubjectLogonId`, so a process can be tied to the logon that started it), token elevation (Default / Full / Limited), integrity level (from the `S-1-16-*` label), and `target_logon_id` when the process runs in another session (e.g. `runas`).
- **Volume:** 4688 is read with its **own query and budget**, so a busy machine's process events can never push authentication, account or log-clearing events out of a scan.
- **Privacy:** command lines can contain secrets. They are stored locally like all telemetry, shown in the Events page and raw XML, but never repeated in timeline summaries or diagnostics.
- No rule fires on 4688 alone; it is context for investigation and for later process-tree and cross-source correlation.

## DET-005: New User Account Created

- **Logic:** every Event 4720. Account creation is routine, so the default is **LOW** severity with **HIGH** confidence that it happened.
- **Context that raises severity to MEDIUM:** the new name ends with `$`. Such user accounts are hidden from `net user` and imitate computer accounts (which Windows creates with Event 4741, not 4720).
- **Evidence:** new account (DOMAIN\name) and SID (from `TargetSid`), local or domain scope, who created it, the creator's SID and **logon ID** (to pivot into the session that did it), SAM name, UPN, raw UserAccountControl codes, record ID.
- **MITRE:** T1136.001 Create Account: Local Account (T1136.002 when the account is created on a domain controller).

## DET-006: Account Added to Privileged Local Group

- **Logic:** Event 4732 whose group is a built-in privileged group, recognised by its **well-known SID**. Names are localized (`Administratoren`, `VORDEFINIERT` on German Windows), so a name never decides on its own; a custom group *named* "Administrators" with a normal SID is not the built-in group.
- **Tiers:** HIGH for administrator-equivalent groups (Administrators S-1-5-32-544, Account Operators -548, Server Operators -549, Backup Operators -551); MEDIUM for remote access or elevated capability (Print Operators -550, Remote Desktop Users -555, Distributed COM Users -562, Hyper-V Administrators -578, Remote Management Users -580). Other groups are stored as context only.
- **Fallback:** if Windows recorded no group SID, the English name `Administrators` still matches, with confidence **LOW** and `group_matched_by: name`.
- **Evidence:** member SID, the member's name (looked up from another event that recorded that SID, with its source), group name, domain, SID and meaning, who made the change and their logon ID, record ID.
- **MITRE:** T1098.007 Account Manipulation: Additional Local or Domain Groups.

## COR-002: New Account Added to Administrators

- **Logic:** Event 4720 creates account SID *X*, then Event 4732 adds *X* to an **administrator-equivalent** (HIGH tier) group, on the same computer, within **30 minutes**. Creation must come first.
- **Matching:** by SID only. Names are not used: 4732 usually records no member name for local accounts.
- **One finding per new account,** even if it is added to several groups; the evidence names the first addition.
- **Confidence:** HIGH; MEDIUM when the group was recognised only by name. Severity HIGH.
- **Evidence:** account and SID, created at/by (with logon ID), added at/by (with logon ID), whether the same person did both, group and meaning, seconds between the two events, both record IDs.
- **Why 30 minutes:** `net user x /add` followed by `net localgroup administrators x /add` normally happens within seconds or minutes, by hand or by script.
- **MITRE:** T1136.001 and T1098.007 (both verified on attack.mitre.org).
- DET-005 and DET-006 still fire for the same two events: they describe each change; COR-002 describes the sequence.

## Event 4104: PowerShell script blocks (telemetry)

- **Source:** `Microsoft-Windows-PowerShell/Operational`, Event 4104. Windows PowerShell 5.1 logs **every** script block only when the policy *Turn on PowerShell Script Block Logging* is enabled; without it, it still logs blocks it considers suspicious itself, at **Warning** level. Health shows the policy state (read-only); MoeSOC never changes it.
- **Normalized:** user SID (4104 records no user name), PowerShell host PID, script-block ID, part *n* of *m*, script length, SHA-256 of the text, and whether PowerShell itself flagged it (`windows_flagged`).
- **Privacy:** the script text is **not** copied into normalized fields, summaries or findings. It stays only in the locally stored raw XML, which the analyst can open on purpose. Findings keep short excerpts (≤ 80 characters, long base64 runs shortened) and the hash.
- Large scripts are split over several 4104 events with the same ScriptBlockId; DET-007 reassembles them per computer in `MessageNumber` order and ignores duplicates.

## DET-007: Suspicious PowerShell Behavior

- **Logic:** score each (reassembled) script block from explainable indicators; a finding needs **≥ 3 points**, severity and confidence become HIGH at **≥ 6**. PowerShell use alone is never a finding.
- **Indicators and points:**

| Indicator | Points | Related technique |
|---|---|---|
| Download **and** execute (download cradle, e.g. `IEX (New-Object Net.WebClient).DownloadString(…)`) | 3 | T1105 |
| Download only | 1 | T1105 |
| AMSI internals (`AmsiUtils`, `amsiInitFailed`, …) | 3 | T1562.001 |
| Defender tampering (`Set-MpPreference -Disable…`, exclusions) | 3 | T1562.001 |
| Credential-dumping keywords (`sekurlsa`, `Invoke-Mimikatz`, `MiniDumpWriteDump`) | 3 | T1003.001 |
| Base64 decode that is executed or loaded | 2 (alone: 1) | T1027 |
| Assembly loaded from memory (`[Reflection.Assembly]::Load`) | 2 | T1620 |
| Native injection APIs **with** `Add-Type`/`DllImport` | 2 | T1055 |
| Obfuscation (≥ 15 backticks, ≥ 3 format-string fragments, strings from `[char]` codes) | 2 | T1027 |
| PowerShell itself flagged the block (Warning level) | 2 | — |
| Hidden window (`-w hidden`) | 1 | T1564.003 |
| **Process context:** PowerShell started by an unusual parent (Office, mshta, wscript, rundll32, …) | 2 | — |
| **Process context:** encoded command line (`-enc`, `-EncodedCommand`) | 2 | T1027 |

- **Process context** comes from Sysmon Event 1 or Security 4688 for the same computer and PID: the most recent process start **before** the script block (PID reuse aware). Without either source the score uses the script alone.
- **Evidence:** user (name from the process event, else SID), computer, PowerShell PID, parent process, script-block ID, parts seen, script length and SHA-256, every indicator with points, reason, technique and excerpt, and the record IDs of the 4104 parts and the process event.
- **MITRE:** T1059.001 Command and Scripting Interpreter: PowerShell (the indicators list related techniques in the evidence).
- **False positives:** deployment scripts that download and run installers; security and inventory tools that read AMSI or Defender settings; penetration tests; developer tooling that loads assemblies. Each indicator is shown so the analyst can judge.
- **Not detected:** scripts run where Script Block Logging is off and PowerShell did not flag them; PowerShell 7 (`PowerShellCore/Operational` is not collected yet); obfuscation outside the listed patterns.

## DET-008: Microsoft Defender Detection (Events 1116 → 1117/1118/1119)

- **What it reports:** Microsoft Defender's own detections. The wording is always "Microsoft Defender detected …": MoeSOC does not analyse the file and never claims to have identified malware itself.
- **Events:** 1116 (Defender detected malware or potentially unwanted software), 1117 (Defender took an action), 1118 (an action failed, non-critical), 1119 (critical failure). All four are collected from `Microsoft-Windows-Windows Defender/Operational` in their own incremental group (`defender_detection`).
- **Correlation (Phase 20):** one finding per **Defender Detection ID** per computer. The detection (1116) is joined with the latest action event for the same Detection ID. Because Defender may record the action minutes or hours later, and an incremental scan may only contain one of the two, the scanner also loads earlier Defender events with the same Detection ID from up to **7 days** before the scan range. The dedup key is the Detection ID, so a later 1117 updates the same finding instead of creating a new one.
- **Remediation state:** `remediated` (latest action is Quarantine, Remove, Clean or Block with error code 0x00000000), `action failed` (1118/1119, or a 1117 with a non-zero error code), `allowed` (a user or policy allowed the threat), `action recorded` (another action, e.g. "No action"), `no action recorded` (1116 only so far). If Defender retried after a failure, the latest action decides.
- **Severity:** from Defender's severity (Severe/High → HIGH, Moderate → MEDIUM, Low → LOW, unknown → MEDIUM), raised to **HIGH** when the action failed or the threat was allowed, because it may still be present. The reasons are listed in the finding ("Why this severity").
- **Confidence:** HIGH, meaning *Defender recorded this detection*. Whether the file is really malicious is Defender's verdict (it can be a false positive, e.g. the EICAR test file).
- **Evidence:** threat name and ID, Defender severity and category, Detection ID, detection time and source (Real-Time Protection, scan, …), origin, user, process, file and every resource Defender named (`file:`, `containerfile:`, `webfile:`, `process:` …), remediation state with action, time, error code and seconds after detection, number of 1116 events, and the security-intelligence version.
- **MITRE:** none mapped. A Defender threat name (e.g. `Trojan:Win32/…`) is a malware classification, not a technique; mapping it would be guesswork.
- **Parsing notes:** field names contain spaces (`Threat Name`, `Detection User`); `Path` holds several resources separated by `; `, each `type:_value`; archive members appear as `archive->member`; `Process Name` can be `Unknown`.
- **Not covered:** Defender configuration changes (5001, 5007), tamper protection and exclusion changes; other antivirus products; Defender for Endpoint cloud alerts.

## Cross-source correlation engine (`engine/activity.py`)

The activity graph indexes one detection run's events and answers "which events belong together?" across logs. Every link is reported with its kind and strength:

| Link | Joins | Strength |
|---|---|---|
| `logon_id` | 4624 TargetLogonId (and its UAC linked ID) = 4688 / 4720 / 4732 SubjectLogonId = Sysmon `LogonId`, same computer, after the logon and inside the follow-up window (logon IDs repeat after a restart) | exact |
| `process_guid` | Sysmon ProcessGuid of a process and of its network, file, registry and DNS events | exact |
| `file_path` | Defender's file = Sysmon 11 `TargetFilename` = a later process image, same computer, case-insensitive | exact |
| `detection_id` | Defender 1116 and its 1117/1118/1119 | exact |
| `pid` | PowerShell 4104 host PID → most recent process start with that PID before it | weaker (PID reuse) |
| `user_time` | Defender detection for the logon's user, within the window | weak |

SYSTEM, LOCAL SERVICE and NETWORK SERVICE logon IDs (0x3e7, 0x3e5, 0x3e4) are never treated as sessions. Sysmon file and network events are not part of every rule run (too voluminous); for COR-004 the scanner loads them **by key** (the file path Defender named, then the writer's ProcessGuid), bounded by computer and time (schema v6 adds the indexes).

## COR-003: Suspicious Activity After Failed Logons

- **Logic:** ≥ 5 failed logons for one identity within 10 minutes, then a successful logon (the same matching as COR-001, including domain aliases), then **within 60 minutes in that logon session**: a user account created (4720), a local group change (4732), PowerShell with suspicious indicators (DET-007 scoring, its process linked to the session), or a Microsoft Defender detection for that user.
- **Not enough on its own:** ordinary processes in the session. They are listed as context (`processes_in_session`).
- **Confidence:** HIGH when at least one follow-up shares the logon session; MEDIUM when the only follow-up is a Defender detection matched by user and time.
- **Evidence:** a **chain** of steps (time, log, event ID, record ID, what happened, link kind and strength), the failure count, the logon (type, source, logon ID), the DET-007 indicators of linked PowerShell, and the processes started in the session. No command lines or script text are copied.
- **Relationship to COR-001:** COR-001 reports the logon; COR-003 reports what the session did afterwards. Both can exist for the same incident.
- **MITRE:** T1110 Brute Force, T1078 Valid Accounts.

## COR-004: Defender Detection Traced to Its Source

- **Logic:** a Defender 1116 that names a file; the latest Sysmon 11 that wrote **the same path** on the same computer within 60 minutes before the detection; the writing process (Sysmon 1 by ProcessGuid), its DNS lookups (22) and connections (3) before the write; and any process started from that file.
- **Severity:** from Defender's severity; HIGH if the file was started or Defender's remediation did not succeed. **Confidence:** HIGH when the writer's process start was collected, MEDIUM when only the file event names it.
- **Evidence:** summary ("Microsoft Defender detected … in a file written by …"), file path, write time and seconds to detection, writer path, GUID, parent and user, DNS names and connections, execution count, remediation state, the chain, and related techniques per finding: **T1105** Ingress Tool Transfer when network activity preceded the write, **T1204.002** User Execution: Malicious File when the file was started.
- **Requires Sysmon** with file-create (11) logging for the folder; without it, DET-008 still reports the detection.

## Risk score (all findings, `engine/risk.py`)

The risk score orders the analyst's queue. It is **not** a probability of compromise. The scanner applies one model to every finding after the rules have run, and stores each applied factor with its reason (`risk_factors`, shown as "Why this risk score").

| Factor | Points |
|---|---|
| Base: severity LOW / MEDIUM / HIGH / CRITICAL | 20 / 40 / 70 / 90 |
| Confidence LOW (the evidence also fits benign activity) | −10 |
| The logon received special privileges (Event 4672) | +10 |
| Microsoft Defender reports the threat remediated | −15 |
| Defender's remediation failed, or the threat was allowed | +10 |
| The detected file was started as a process | +10 |
| Corroborated by two or more different logs (cross-source chain) | +5 |

The result is clamped to 0–100; if the cap applies, that is listed too. The endpoint score on the Overview is the highest **open** finding's score, and the card names that finding. Because the score depends only on stored evidence, a rescan refreshes it for findings of the same rule version; findings of older rule versions keep the score they were stored with.

## Tuning and suppressions (`storage/tuning.py`, schema v8)

- **Rule tuning:** a rule can be disabled, or one of its existing integer parameters (thresholds, windows) changed within bounds: windows (`*_minutes`) 1–1,440, `*_days` 1–30, counts 1–10,000. Event IDs are identifiers and are never tunable, and a test guarantees every tunable parameter is actually read by the code. The YAML file is not edited; the override is stored in the database and applied when a scan loads the rules. Findings produced with tuned values carry `tuning` evidence (value and YAML default). Setting a parameter back to its default removes the override.
- **Suppressions:** hide future findings whose evidence matches a value exactly (case-insensitive): `account` (full or short name), `source_ip`, `host`, `process` (name or path), `file_path`, `threat` (Defender threat name). Optional rule scope and expiry (1–365 days). Wildcards are refused. Matching findings are not stored; the scan reports how many were suppressed and each suppression counts its hits.
- **Audit:** every add, removal, enable/disable and parameter change needs a reason (≥ 5 characters) and is written to `audit_log`. Removing a suppression records who-when-why; the row stays.
- **Never changed:** existing findings, their triage state and notes.

## Rule versions

Each finding stores the `rule_version` that produced it. A rescan by the same version refreshes the evidence of an existing finding. A finding produced by an **older** version is left exactly as it was, so changed logic never silently reinterprets earlier findings. Version history: DET-001 1.1 (identity matching), 1.2 (domain aliases); DET-002 1.1 (domain aliases); COR-001 2.0 (identity + derived confidence), 2.1 (domain aliases).

## Known limitations

- Guessing slower than 10 per hour per account (or 15 per hour per source) evades DET-004 as well; very slow attacks need longer baselines than one scan window.
- Machine accounts (`HOST$`) are not filtered out. Their failures can indicate a broken secure channel.
- Text search is case-insensitive for ASCII only (a SQLite LIKE limitation); identity matching itself handles Unicode correctly.
