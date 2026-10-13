# Public Release Audit (v1.1.0)

Date: 2026-10-11. Scope: the source tree that becomes the **new** public repository (`release/public-source/`), exported from the private repository's committed tree. Not in scope: the private Git history, which is never published.

## 1. Release freeze

| Item | Value |
|---|---|
| Private branch | `master` |
| Validated code commit | `5e282f0` (final code of the Always-On validation) |
| Release commit | the commit that adds this file. It changes only version strings and documentation on top of `5e282f0`. |
| Working tree | clean at export (`git status` empty) |
| Version | **1.1.0** (`moesoc/__init__.py`, `pyproject.toml`, `packaging/version_info.txt`, `packaging/MoeSOC.iss`; kept in sync by `tests/test_static_imports.py`) |
| Database schema | v9 |
| Local tags | `v1.0.0` (private, untouched); no `v1.1.0` tag created |
| Final tests (code `5e282f0`) | Windows elevated 672 passed / 1 skipped; Windows non-elevated 671 / 2; Linux 670 / 3; GUI smoke 76/76; Ruff clean |
| Final Windows validation | **PASS** ([MoeSOC_AlwaysOn_Final_Report.md](MoeSOC_AlwaysOn_Final_Report.md)) |

## 2. How the public tree is built

1. `git archive HEAD` of the private repository. This takes **tracked files only**, so nothing that `.gitignore` excludes can enter: real-machine screenshots, databases, logs, validation output, the history bundle, `audit/`, `.venv`, `dist/`, `build/`.
2. These committed paths are then removed:
   - `docs/screenshots/audit/` (duplicate demo screenshots);
   - `docs/MoeSOC_Final_Validation_Report.pdf` (duplicate of the `.md`);
   - `docs/release/checklist.md` (a private-repository procedure, superseded by [PUBLIC_RELEASE_CHECKLIST.md](PUBLIC_RELEASE_CHECKLIST.md));
   - every `__pycache__`.
3. **No `.git` directory** is copied. The tree is meant to start a new history.

The audit below does **not rely on `.gitignore`**: every file in the exported tree was scanned.

## 3. Checks

| # | Check | Method | Result |
|---|---|---|---|
| 1 | Real computer name | Text search of all 274 files for the validation PC's name and any `DESKTOP-…` name; OCR of every screenshot | ✅ none. One text match, "desktop-control tool", is not a host name. Screenshots show `WORKSTATION`. |
| 2 | Usernames | Search for personal user folders (`C:\Users\<name>`) and the owner's name | ✅ none. Only the fictional `alice`, `LAB\Administrator`, and the documented lab test account name `moesoc-test`. |
| 3 | E-mail addresses | Regex | ✅ only `user@contoso.com` (a test identity) |
| 4 | SIDs | Regex for `S-1-5-21-…` excluding the documented synthetic authorities | ✅ only synthetic SIDs (`1111111111-…`, `7777777777-…`, `4444444444-…`, `1-2-3`, `111-222-333`). Well-known SIDs (`S-1-5-18`, `S-1-5-32-544`) are not personal. |
| 5 | IP addresses | Regex for IPv4 outside the RFC 5737 documentation ranges and loopback | ✅ only RFC 5737, loopback and `10.0.0.5` in one parser test |
| 6 | Passwords, API keys, tokens, private keys | Regex (assignments, `-----BEGIN … PRIVATE KEY`, cloud and GitHub token formats) | ✅ none. Docs prompt for passwords interactively (`net user … *`) and never contain one. |
| 7 | Absolute personal paths | Regex for user folders, home and sandbox paths | ✅ none; paths use `%LOCALAPPDATA%`, `%ProgramData%`, `<USER>` |
| 8 | Databases | File types `.db`, `.sqlite`, `-wal`, `-shm` | ✅ none |
| 9 | Logs | `.log` files; validation output files | ✅ none (`*.log`, `*_output.txt` are untracked) |
| 10 | EVTX files | `.evtx` | ✅ none. Test events are hand-written XML fixtures with host `WS-LAB01.lab.example`. |
| 11 | Crash dumps | `.dmp`, `.mdmp` | ✅ none |
| 12 | Private test output | `audit/`, `verify_output.txt`, `live_delivery_output.txt`, `.verify-data/`, `ci-data/` | ✅ none |
| 13 | Screenshots with identifiers | OCR + visual check of all PNGs; PNG metadata (only DPI) | ✅ 19 public screenshots (12 GUI, 5 demo, 2 icon sheets), all synthetic. `real-*.png` never included. See [SCREENSHOT_PLAN.md](SCREENSHOT_PLAN.md). |
| 14 | Benchmark files | `docs/benchmarks/*.json` | ✅ OS build, CPU model and timings only; "host name intentionally not recorded" |
| 15 | AI-session or tooling links | Search for session URLs and trailers | ✅ none in the tree. They exist only in private commit messages, which are not published. |
| 16 | Build scripts and config | `scripts/`, `packaging/`, `launcher/`, `.github/` | ✅ relative paths and environment variables only; no credentials; CI is read-only (`permissions: contents: read`) |
| 17 | Reports and docs | All `docs/*.md`, release notes, changelog | ✅ hosts written as `<HOST>` / `<USER>` placeholders; validation numbers only |
| 18 | Private history | — | ✅ not published: new repository from this tree only |

Areas inspected: source (`moesoc/`, `app.py`, `sensor.py`, `tray.py`), `tests/` and `tests/fixtures/`, `docs/` (reports, screenshots, benchmarks), demo and example scripts, build scripts (`scripts/`, `packaging/`, `launcher/`), configuration (`pyproject.toml`, `requirements*.txt`, `rules/*.yaml`, `.github/workflows/ci.yml`, `.gitignore`).

## 4. Findings that need the owner

| Item | Action |
|---|---|
| `LICENSE` copyright holder | Resolved: "Mohamed Sawaed", the owner's chosen public name. The commit author uses the owner's GitHub no-reply address, not a personal e-mail. |
| Private Git history contains screenshots showing the real computer name | Never push the private repository or its tags; create the new repository from `release/public-source/` |
| `docs/screenshots/real-*.png` exist in the private working folder | Keep them private (they are git-ignored and excluded) |
| The tray-notification screenshot does not exist yet | MANUAL CAPTURE REQUIRED, then re-audit it |

## 5. Result

**PASS.** No personal identifiers, secrets, databases, logs, dumps or private test output in the public tree. The automated scan's remaining matches were reviewed and are false positives: the phrase "desktop-control tool" (also quoted in this file) and a synthetic SID.

## 6. Verification of the public tree (Linux)

- Imports and version: `moesoc.__version__ == "1.1.0"`; CLI banner "MoeSOC Endpoint 1.1.0".
- `pytest`: 670 passed, 0 failed, 3 skipped (2 Windows-only, 1 needs a non-root user).
- Ruff check and format: clean.
- Markdown links: every relative link in `README.md`, the release notes and `docs/*.md` resolves inside the tree.

## 7. Verification of the public tree and release build (Windows)

`audit\release_build.bat` (release tooling, not part of the product) unpacks the public tree on the validation PC and builds the release package **from that tree**. Full log: `release/v1.1.0/BUILD_REPORT.txt`, which is not part of the source tree.

| Step | Result |
|---|---|
| Files / version | 274 / `1.1.0` |
| Ruff | clean |
| pytest (Windows, not elevated) | 671 passed, 0 failed, 2 skipped |
| PyInstaller build | exit 0; `MoeSOC.exe`, `MoeSOCSensor.exe`, `MoeSOCTray.exe` |
| Packaged self-test | PASSED (`MoeSOC 1.1.0`, 12 rules, schema v9, icon, Windows API, GUI) |
| Code signing | **NotSigned**: no certificate; the binaries are not code-signed |
| Embedded paths | the bundled Python modules carry relative paths only (`moesoc\…`); no user folder or computer name found in the package |
| SHA-256 | `SHA256SUMS.txt` written and verified on Windows; the zip's hash re-computed independently on Linux matches |
