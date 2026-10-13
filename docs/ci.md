# Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request, on `windows-latest`:

| Job | Steps |
|---|---|
| **test** | Python 3.13 · install `requirements-dev.txt` · Ruff check and format · full pytest suite · CLI `health`, `scan`, `detections` against the runner's real logs (read-only) · GUI smoke test with `QT_QPA_PLATFORM=offscreen` · screenshots uploaded as an artifact |
| **build** (after test) | PyInstaller `MoeSOC.exe` · `MoeSOC.exe --self-test` must exit 0 · installer if Inno Setup is present on the runner · zip + `SHA256SUMS.txt` uploaded as an artifact |

GitHub's Windows runners run elevated, so CI also exercises paths that need administrator rights on a desktop: the real Security-log scan and the live `EvtSubscribe` subscription in the GUI smoke test. CI is read-only: it never changes the runner's audit policy, installs Sysmon or writes to an event log.

## Run the same thing locally

`scripts\ci_local.bat` runs the test job's commands (and the executable self-test if `dist\MoeSOC` exists) on a Windows PC, including the offscreen GUI mode. Output: `ci_local_output.txt`.

## Status

| Item | Status |
|---|---|
| Workflow commands on Windows (local mirror, October 8, 2026) | TESTED: Ruff clean, 448 passed / 1 skipped, offscreen GUI smoke PASSED, executable self-test PASSED |
| Workflow on GitHub Actions | NOT TESTED: the project has no GitHub repository yet (see `docs/PUBLIC_RELEASE_CHECKLIST.md`) |
