# MoeSOC Endpoint: Gap Analysis and Improvement Roadmap

**Reviewer roles:** senior SOC engineer, detection engineer, Windows security engineer, technical reviewer.
**Audited:** v1.0.0, commit `62ca492`, 2026-10-08. No product code was modified.
Measurements and probe details are in [MoeSOC_Final_Validation_Report.md](MoeSOC_Final_Validation_Report.md).

**Labels:**

- **REAL WINDOWS TESTED:** seen on genuine telemetry of the test PC.
- **SYNTHETIC / FIXTURE TESTED:** only test fixtures or the labelled demo database.
- **NOT TESTED**
- **BLOCKED:** environment or user interaction.

A unit test passing is *not* counted as "working on Windows".

---

## 1. What was run

| Item | Result | Label |
|---|---|---|
| git status / version | clean tree, `master` @ `62ca492`, tag `v1.0.0` (local), version 1.0.0 everywhere, no remote | — |
| Ruff | clean, 0 errors / 0 warnings (Linux 144 files, Windows 143) | — |
| Full pytest | 452 collected; Windows elevated 452 passed; Windows standard user 451 + 1 skip; Linux 450 + 2 skips ×3 | — |
| Windows integration tests | 2/2 passed elevated (Application log, real Security log read); standard user: correct access-denied skip | REAL WINDOWS TESTED |
| GUI smoke | 76/76 (real window), 76/76 (offscreen), 76/76 (elevated) | SYNTHETIC data in a real window |
| MoeSOC.exe self-test | PASSED (12 rules, schema v8, icon, pywin32, 9 pages) | REAL WINDOWS TESTED |
| Real Security log scan | 1,269 records, 515 new, 0 parse failures, 0.36 s; rescan 0/0, no duplicates | REAL WINDOWS TESTED |
| Current databases | app DB v8: 1,331 real events, 4 real findings; validation DB: 998 events, 3 findings; integrity ok | REAL |
| Rules and correlations | all 12 read in code and YAML; positives exercised on the demo DB | see section 3 |
| Timeline / stories | ordered, every link labelled; over-inclusive "same account" relations | SYNTHETIC |
| Risk engine | bases and modifiers verified; double counting found | REAL (base, LOW confidence) + SYNTHETIC |
| Search / pivots | 19 filters, combinations and paging all correct SQL-side | SYNTHETIC |
| Reports | XSS-safe; redaction complete for host, user, SID, IP and profile path; DNS names not redacted | SYNTHETIC |
| Launcher | UAC approve, decline and single instance seen in the real launcher log | REAL WINDOWS TESTED (historical log) |
| Packaging | exe builds and self-tests; **no installer** (Inno Setup absent) | BLOCKED |
| CI configuration | valid YAML, sensible jobs; local mirror passes; **never run on GitHub** | BLOCKED (no remote) |

## 2. Telemetry sources

### Windows Security

- **Implemented:**
  - 1102, 4624, 4625, 4672 (context, service-account noise dropped), 4688 (separate budget), 4720, 4732.
  - Incremental record-ID watermarks with gap, rollover and reset recovery.
  - Live subscription.
- **REAL WINDOWS TESTED:**
  - Collection: 1,269 real records, 0 parse failures; incremental rescans; 0 duplicates.
  - DET-001 ×2, DET-005 and COR-001 fired on real events.
  - Evidence re-verified 24/24.
  - Live monitor start, stop and restart.
- **SYNTHETIC ONLY:** 1102 (log clear), privileged 4732, password spray, low-and-slow, and real-time live delivery (not demonstrated: 0 events in 36 s).
- **Missing:**
  - 4648 explicit credentials (runas / pass-the-hash context).
  - 4728/4756 (global/universal group adds), 4733/4729 (removals), 4726 (deleted), 4724/4738 (password reset / changed).
  - 4697 and System 7045 (service install), 4698 (scheduled task).
  - 4740 (lockout), 4776 (NTLM validation), 4768/4771 (Kerberos, on DCs).

### Sysmon

- **Implemented:** detection of the service and variant; collection and parsing of 1, 3, 11, 13, 22; process tree by ProcessGuid; COR-004 and COR-003 links.
- **REAL WINDOWS TESTED:** nothing. Sysmon is not installed (MoeSOC correctly never installs it). Health reports this correctly (REAL).
- **SYNTHETIC ONLY:** all parsing, process trees with GUIDs, COR-004.
- **Missing:** no detection uses Sysmon 3, 13 or 22 directly (e.g. Run-key persistence, suspicious parent-child pairs from Sysmon 1, LOLBin network connections). Events 7, 8, 10, 12, 23 and 25 are not collected. There is no documented reference config tested with MoeSOC.

### PowerShell (4104)

- **Implemented:** collection, multi-part script reassembly, Windows "warning" flag, indicator scoring (DET-007), process context, local-only script storage.
- **REAL WINDOWS TESTED:** 41 real 4104 records collected and parsed with 0 failures and **0 findings** (a real false-positive check, but a small one).
- **SYNTHETIC ONLY:** every positive DET-007 case.
- **Missing:** a real positive (Script Block Logging is disabled; enabling it is the owner's decision). There is no 4103 (module logging) and no AMSI telemetry. `--text` search cannot search script content.

### Microsoft Defender

- **Implemented:** 1116–1119, Detection-ID join to the remediation result (7-day look-back), DET-008, COR-004 source tracing.
- **REAL WINDOWS TESTED:** the channel is readable; **0** real detection events exist.
- **SYNTHETIC ONLY:** DET-008 and COR-004 entirely.
- **Missing:** a real EICAR validation (pending approval). Defender configuration-change events (5001 real-time protection disabled, 5007 config change, 5013 tamper protection) are not collected, although they are among the most valuable Defender events for a SOC.

## 3. Detections and correlations

| Rule | Purpose | Data source | MITRE | FP risk | Real validation | Strong enough for a SOC portfolio? |
|---|---|---|---|---|---|---|
| DET-001 | Burst of failed logons for one account | Security 4625 | T1110 | High (typos, stale creds), mitigated by explicit FP list | **REAL ✅** | Yes, once A-1 (duplicate floods) and A-2 (domain-field split) are fixed |
| DET-002 | One source, many accounts | 4625 | T1110.003 | Medium (shared hosts, scanners); **misfires on one account with varied domain strings** | SYNTHETIC | Logic sound; needs the identity fix and a real test |
| DET-003 | Security log cleared | 1102 | T1070.001 | Low | SYNTHETIC | Yes: trivial but expected |
| DET-004 | Slow guessing below DET-001 | 4625 | T1110 / .001 | High (retrying devices); LOW confidence is the right choice | SYNTHETIC; **duplicates in live mode** | Good idea and good write-up; broken by A-1 in live mode |
| DET-005 | New local account (`$` names raised) | 4720 | T1136.001 | High (admin work); LOW severity is appropriate | **REAL ✅** | Yes, as an awareness rule |
| DET-006 | Member added to privileged local group (by well-known SID, localized-safe) | 4732 | T1098.007 | Medium | partial (real record parsed, no positive) | Yes; the SID-based design is a strong interview point. Missing 4728/4756 for domain groups |
| DET-007 | Suspicious PowerShell scoring | 4104 + process context | T1059.001 | Medium–high (admin scripts) | partial (0 FP on 41 real blocks); positive synthetic | Promising; needs a real positive and a larger benign corpus |
| DET-008 | Defender detection + remediation state | Defender 1116–1119 | none (Defender classifies) | Low | SYNTHETIC | Yes for the triage value; must be validated with EICAR |
| COR-001 | Failures then success, same identity | 4625 → 4624 (+4672) | T1110, T1078 | Medium; confidence factors handle typo cases (real case scored LOW, correctly) | **REAL ✅** | Yes: the best-validated logic in the project |
| COR-002 | New account → admin group | 4720 → 4732 (SID) | T1136.001, T1098.007 | Low–medium | SYNTHETIC | Yes; needs a real test (create test account, add, remove) |
| COR-003 | Failed logons → success → suspicious activity in the **same logon session** | Security + Sysmon/4688 + 4104 + Defender | T1110, T1078 | Medium; weak user-and-time Defender links | SYNTHETIC | Strongest *idea* in the project; unproven on real data |
| COR-004 | Defender detection → file writer → DNS/network → execution | Defender + Sysmon 11/1/22/3 | T1105, T1204.002 per finding | Low | SYNTHETIC (impossible without Sysmon) | Impressive on paper; unproven |

## 4. Scores (0–10, junior SOC portfolio scale)

| # | Area | Score | Why |
|---|---|---|---|
| 1 | Architecture | **8** | Clean collector → parser → normalized event → storage → engine → UI layers; shared backend for CLI and GUI; SQL only in `storage/`. Weak spots: window-based finding identity (A-1), hard-coded rule wiring |
| 2 | Windows telemetry | **6** | Excellent Security-log handling (watermarks, noise, localization, SIDs) but three of four sources unproven, live path Security-only, important event IDs missing |
| 3 | Detection engineering | **6** | Explainable and well documented, but auth-heavy; no persistence, lateral-movement or defense-evasion-beyond-log-clear detections; evasion via domain field |
| 4 | Correlation | **6** | Right keys (logon ID, ProcessGuid, file path, Detection ID) with labelled link strength; real-data proof only for COR-001 |
| 5 | Investigation workflow | **8** | Triage states + verdicts + notes + history, timeline, pivots, story, process tree, evidence re-check |
| 6 | False-positive handling | **6** | FP lists, confidence factors, LOW-confidence rules, tuning with bounds, suppressions with reasons and audit. But suppressions can be global and permanent, suppressed hits are not stored, and there is no allow-listing by context |
| 7 | Risk scoring | **6** | Transparent and bounded, "not a probability" stated; double counting, no recency, endpoint score is just the max |
| 8 | GUI/UX | **6** | Responsive, honest states, demo badge; cramped detail pane, text wrapping in chains, horizontal scroll at 1440 px |
| 9 | Testing | **7** | 452 deterministic tests, migrations, XSS, 76 GUI checks. Only 2 real-log tests; A-1, A-2 and A-3 slipped through |
| 10 | Security/privacy | **7** | Observe-only, no network, parameterized SQL, escaped reports, redaction. **Real computer name in git history** |
| 11 | Performance | **7** | 100k events in about 18.5 s end-to-end on the PC, 1.8 KB/event, incremental scans 0.23 s. Memory not measured; detection re-runs the whole window per live batch |
| 12 | Packaging | **5** | Self-testing exe; no installer, signing or checksums; UAC-decline behaviour differs between launcher and exe |
| 13 | Documentation | **8** | Thorough, mostly accurate, real vs synthetic separated; headline overstates, LICENSE missing |
| 14 | Real-world validation | **3** | 3/12 rules with real positives, all from the owner's own lock-screen typos; Sysmon and Defender 0% real; live delivery unproven |
| 15 | Junior SOC portfolio value | **7** | Clearly above the average student project in reasoning and honesty. Becomes 8–9 with real validation and the three MEDIUM fixes |

## 5. Weaknesses

### W1. Real-telemetry validation covers 3 of 12 rules

- **Problem:** Only DET-001, DET-005 and COR-001 have fired on real events. Sysmon, Defender and DET-007 positives are synthetic only.
- **Why it matters:** A detection engineer is judged on whether rules work against real logs (field quirks, localization, volume). Fixtures are written by the same person as the parser.
- **How serious:** **High** for credibility (not for safety).
- **How to improve:** In a VM or on the test PC:
  1. Install Sysmon with a public config (e.g. SwiftOnSecurity or Olaf Hartong's modular).
  2. Enable Script Block Logging.
  3. Run EICAR.
  4. Add and remove a test admin account.
  5. Do failed RDP or SMB logons from a second machine.

  Record sanitized results in `docs/validation.md` with record counts and screenshots.
- **Effort:** MEDIUM.
- **Portfolio impact:** HIGH.

### W2. Duplicate findings for long campaigns in live mode (A-1)

- **Problem:** Finding identity = rule + host + first record of the visible burst. Live batches reload about 70 minutes, so a 3-hour slow campaign produced **22 DET-004 findings**.
- **Why it matters:** Alert fatigue is the number-one SOC complaint. An interviewer who knows detection engineering will ask "what happens with a slow brute force over hours?"
- **How serious:** **Medium–High.**
- **How to improve:** Keep an "open incident" key per (rule, identity or source). If a new burst overlaps or is within N minutes of an open finding's `last_seen`, extend that finding instead of creating one. Add a regression test that replays the probe batch by batch.
- **Effort:** MEDIUM.
- **Portfolio impact:** HIGH.

### W3. Identity split on the attacker-controlled 4625 domain (A-2)

- **Problem:** `TargetDomainName` in 4625 is what the client sent. Varying it (or empty vs host name) splits one account. DET-001 is evaded and DET-002 reports a spray.
- **Why it matters:** Identity normalization is the core of authentication detection, and this is a known evasion pattern.
- **How serious:** **Medium.**
- **How to improve:**
  - For workgroup or local targets, scope identity to `host\user` regardless of the claimed domain when the domain is not a known authority.
  - Add a username-only secondary grouping for DET-001.
  - Show "claimed domains" in the evidence.
- **Effort:** LOW–MEDIUM.
- **Portfolio impact:** HIGH.

### W4. Evidence verification false alarms for non-Security sources (A-3)

- **Problem:** `verify-evidence` parses all evidence with the Security parser. Genuine Sysmon, PowerShell and Defender evidence shows **"mismatch"**.
- **Why it matters:** Evidence integrity is one of the project's selling points; a false tamper signal undermines trust.
- **How serious:** **Medium.**
- **How to improve:** Use `parse_any_xml` (the dispatch already exists) and compare per-source key fields. Add four tests.
- **Effort:** LOW.
- **Portfolio impact:** MEDIUM.

### W5. Live monitoring not proven to deliver events; Security only (A-4)

- **Problem:**
  - 0 events in a 36 s real session.
  - The subscription signal is auto-reset and initially non-signalled (Microsoft's sample uses initially signalled manual-reset).
  - Sysmon, PowerShell and Defender are not live.
- **Why it matters:** "Real-time monitoring" is a headline claim.
- **How serious:** **Medium** (catch-up scans prevent data loss).
- **How to improve:** Drain once after `EvtSubscribe` (or create the signal initially set); add a real integration test that subscribes to the Application log from a bookmark and checks backlog delivery; extend to the other three channels with per-channel bookmarks.
- **Effort:** MEDIUM.
- **Portfolio impact:** MEDIUM–HIGH.

### W6. No persistence or lateral-movement detections

- **Problem:** No rules for service installs (7045/4697), scheduled tasks (4698), Run keys (Sysmon 13, already collected), explicit credentials (4648), or RDP sessions. Defender tampering events (5001/5007) are not collected either.
- **Why it matters:** These are the bread-and-butter alerts a junior SOC analyst triages daily.
- **How serious:** **Medium.**
- **How to improve:** Add 3–4 focused rules: new service, new scheduled task, Run-key write by an unusual process, Defender real-time protection disabled. Reuse the existing explainability pattern.
- **Effort:** MEDIUM.
- **Portfolio impact:** HIGH.

### W7. Git history contains the real computer name

- **Problem:** Screenshots before `815f8cc` show the real computer name.
- **Why it matters:** It is a privacy leak on publication. It also tells reviewers the privacy process came late.
- **How serious:** **High** (blocking for public release).
- **How to improve:** Publish from a fresh repository (squash) or use `git filter-repo` to drop those blobs; re-check with `git rev-list --all --objects`.
- **Effort:** LOW.
- **Portfolio impact:** HIGH (avoids a bad first impression).

### W8. Suppression safety

- **Problem:** Suppressions can be global (all rules) and permanent. Suppressed findings are not stored at all.
- **Why it matters:** A suppression for an IP silently hides a later COR-003 chain from it, with no trace to review.
- **How serious:** **Medium.**
- **How to improve:**
  - Require a rule ID or a maximum expiry for global suppressions.
  - Never suppress correlations by default.
  - Store suppressed matches as status `SUPPRESSED` (hidden by default, reviewable).
- **Effort:** LOW–MEDIUM.
- **Portfolio impact:** MEDIUM.

### W9. Risk-model double counting and no aggregation

- **Problem:** Severity and modifiers derive from the same condition (DET-008, COR-004). Weak links earn the corroboration bonus. The endpoint score is the max only, with no time decay.
- **Why it matters:** A reviewer will test the claim "explainable and additive".
- **How serious:** **Low–Medium.**
- **How to improve:** Make severity the rule's base only and apply conditions once. Count only exact links for corroboration. Optionally add recency decay.
- **Effort:** LOW.
- **Portfolio impact:** MEDIUM.

### W10. Release hygiene

- **Problem:** No LICENSE file (pyproject says MIT), no installer, no checksums, CI never run, unsigned exe, local-only tag, headline "verified on Windows 11" overstated.
- **Why it matters:** These are the first things a reviewer clicks on GitHub.
- **How serious:** **Medium.**
- **How to improve:**
  1. Add LICENSE.
  2. Push and let CI run.
  3. Publish the portable zip + SHA256 from the CI artifact.
  4. Reword the headline.
  5. The installer is optional.
- **Effort:** LOW.
- **Portfolio impact:** MEDIUM.

### W11. Thin real-log test coverage

- **Problem:** 2 of 452 tests touch a real event log. No test reads a real Sysmon, PowerShell or Defender channel, or a live subscription.
- **Why it matters:** The A-3 and A-4 defects live exactly at that boundary.
- **How serious:** **Medium.**
- **How to improve:** Windows-only integration tests:
  - read the newest PowerShell 4104 if present (skip otherwise);
  - subscribe to the Application log from a bookmark and assert backlog delivery;
  - round-trip evidence verification on each channel present.
- **Effort:** LOW–MEDIUM.
- **Portfolio impact:** MEDIUM.

### W12. GUI density

- **Problem:** Narrow detail pane; chain text wraps mid-word; horizontal scrolling at 1440 px.
- **Why it matters:** Screenshots are the portfolio's first impression.
- **How serious:** **Low.**
- **How to improve:** Make the splitter resizable with a remembered position; render the chain as a compact table with eliding.
- **Effort:** LOW.
- **Portfolio impact:** LOW–MEDIUM.

### W13. Small correctness and polish items

- **Problem:** CLI `BrokenPipeError` tracebacks; empty MITRE line for COR-004; stale risk on old-rule-version findings; launcher vs exe UAC-decline difference; `ß`/`ss` merge.
- **Why it matters:** Polish.
- **How serious:** **Low.**
- **How to improve:** Small targeted fixes, each with a test.
- **Effort:** LOW.
- **Portfolio impact:** LOW.

---

# TOP 10 NEXT IMPROVEMENTS

Ranked by security-engineering value and credibility for SOC roles:

1. **Real-telemetry validation campaign** in a lab VM:
   - Sysmon with a public config.
   - Script Block Logging.
   - EICAR.
   - Test admin account add and remove.
   - Failed RDP or SMB from a second host.

   Publish sanitized evidence per rule (W1).
2. **Fix duplicate finding floods**: stable incident identity across windows, plus a regression test (W2 / A-1).
3. **Fix the 4625 identity split**: client-supplied domain and empty vs host name (W3 / A-2).
4. **Prove and harden live monitoring**: initial drain or signal, a real integration test; then Sysmon, PowerShell and Defender live channels (W5 / A-4).
5. **Add persistence and defense-evasion detections**: new service (7045/4697), scheduled task (4698), Run key (Sysmon 13), Defender protection disabled (5001/5007) (W6).
6. **Fix evidence verification for all sources** (W4 / A-3).
7. **Make suppressions safe and reviewable**: scoped or expiring, stored as SUPPRESSED (W8).
8. **Clean up the risk model**: no double counting, exact links only for corroboration (W9).
9. **Add Windows integration tests** for every channel and the subscription (W11).
10. **Release hygiene**: clean history, LICENSE, CI run, checksummed portable zip, honest headline (W7 + W10). This is listed last only because it is quick; it is also the first item of *Must do before GitHub* below.

## What NOT to build (scope creep)

- **ML/"AI" anomaly scoring.** Unexplainable, needs data that does not exist, and it dilutes the project's main strength (explainability).
- **Automatic response** (blocking IPs, killing processes, quarantine). This contradicts the observe-only safety model and adds risk with no portfolio gain.
- **Multi-host agent, server or fleet console, cloud upload.** That is a different product; it brings an authentication and transport-security burden.
- **Kernel drivers or ETW-TI.** Out of scope and unsafe for a portfolio.
- **Sigma rule engine / full Sigma compatibility.** Interesting, but a large parser project. Instead, *map* a few rules to equivalent Sigma rules in the docs.
- **Dashboards with charts and themes, more GUI pages.** Cosmetic. Fix density first.
- **Threat-intel feeds or VirusTotal lookups.** These need network access and keys and break the "no network" promise.
- **Replacing SQLite** with a server database. Unnecessary at single-host scale.

## MUST DO BEFORE GITHUB

1. Remove identifying screenshots from history (fresh repository or `git filter-repo`) and verify with `git rev-list --all --objects`.
2. Add a `LICENSE` file matching `pyproject.toml` (MIT).
3. Reword the README headline. Real positives: DET-001, DET-005, COR-001. Everything else is fixture or demo validated. Add a "Known issues" section listing A-1 … A-4.
4. Push, let GitHub Actions run, and fix whatever the clean runner finds. Only then call CI "passing".

## BEST NEXT DEVELOPMENT

1. Fix A-1 (duplicate floods) and A-2 (identity split), with regression tests reproducing the audit probes.
2. Lab validation campaign (Sysmon + Script Block Logging + EICAR + admin-group test + second-host failures); update `docs/validation.md` with sanitized real evidence.
3. Live monitoring: initial drain fix, real integration test, extend to the other three channels.
4. Four persistence and defense-evasion detections (7045/4697, 4698, Sysmon 13 Run keys, Defender 5001/5007).
5. Fix evidence verification for all sources (A-3) and make suppressions safe (W8).

## OPTIONAL LATER

- Risk model cleanup (no double counting, recency decay, endpoint aggregation).
- Installer via Inno Setup, code signing, published release with checksums.
- GUI density improvements (resizable detail pane, compact chain table).
- 4648 / 4728 / 4756 / 4740 / 4776 collection and a "privileged logon from new source" rule.
- Sigma mapping table in the docs; ATT&CK Navigator layer export of covered techniques.
- Measured memory profile in the benchmarks.

---

## Final answers

**Is MoeSOC ready for GitHub?**
Not today. It will be after the history is cleaned and a LICENSE is added (a few hours). The current tree itself contains no personal identifiers.

**Is it ready to put on my CV?**
Yes, if described accurately. For example: "Windows endpoint detection console (Python/PySide6/SQLite): incremental Security-log collection validated on real Windows 11 events, 12 explainable detections and correlations across Security, Sysmon, PowerShell and Defender (Sysmon/Defender paths validated on synthetic data), triage, timelines, process trees, 452 automated tests." Do not claim real-world Sysmon or Defender coverage yet.

**Is it ready to call v1.0?**
As **software**, mostly yes: stable, tested, documented. As a **detection product**, no:

- Three MEDIUM defects sit in core detection paths.
- Live monitoring has not been shown to receive an event.
- 9 of 12 rules have no real positive.

A more defensible label today would be "v1.0 (lab-validated for Security-log authentication; other sources fixture-validated)", or ship the fixes and validation as 1.1.

**What is currently the weakest part?**
Real-world validation (3/10). Close behind is the brute-force core, because of duplicate floods and identity splitting: the exact area where the project is otherwise strongest.

**What single improvement would make the biggest difference?**
A documented lab validation campaign that makes every rule fire on genuine telemetry, with the A-1/A-2 fixes it will force. It turns "well-engineered" into "proven", and it gives you concrete stories for interviews.

**What would a SOC hiring manager likely ask?**

1. "Which of these rules have you seen fire on real data, and what false positives did you hit?"
2. "How do you stop a slow brute force over hours from creating dozens of alerts?" (A-1)
3. "Event 4625's domain field: who controls it, and how does your identity matching handle it?" (A-2)
4. "Why Sysmon, and which config would you deploy? What does Event 4688 give you without it?"
5. "Walk me through COR-003. Why is the logon ID a strong link and user-plus-time a weak one?"
6. "How would you detect persistence on this endpoint?" (W6)
7. "Your risk score says 75: what does that number mean, and what does it not mean?"
8. "How do you make sure a suppression doesn't hide a real attack?" (W8)
9. "What happens to your evidence when the Security log rolls over?" (20 MB, about 25,000 records here)
10. "Why no automatic response?" A good answer: observe-only by design, analyst decides, avoids self-inflicted outages.
