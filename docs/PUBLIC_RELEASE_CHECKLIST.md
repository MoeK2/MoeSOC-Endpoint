# Public Release Checklist (v1.1.0)

Nothing here has been pushed or published. The public repository is created **only** from `release/public-source/`, as a **new** Git history. The private history (old screenshots with the real computer name) is never pushed.

## Preparation (done in this session)

- [x] **Privacy audit**: see [PUBLIC_RELEASE_AUDIT.md](PUBLIC_RELEASE_AUDIT.md)
- [x] **README**: rewritten for v1.1.0; links checked
- [x] **LICENSE**: MIT, present, referenced by the README
- [x] **Screenshots**: existing ones audited ([SCREENSHOT_PLAN.md](SCREENSHOT_PLAN.md)); `real-*.png` and `audit/` duplicates excluded
- [ ] **Screenshots, manual**: tray notification (MANUAL CAPTURE REQUIRED), then re-audit
- [x] **Tests**: on `release/public-source/` itself: Linux 670 passed, Windows (non-elevated) 671 passed; Windows elevated 672 passed on the validated code
- [x] **Version**: 1.1.0 in `moesoc/__init__.py`, `pyproject.toml`, `packaging/version_info.txt`, `packaging/MoeSOC.iss` (a test keeps them in sync)
- [x] **Release notes**: `RELEASE_NOTES_v1.1.0.md`; **CHANGELOG**: 1.1.0 entry
- [x] **Release build**: built on Windows by PyInstaller from `release/public-source/` (not from the private tree)
- [x] **Self-test**: `MoeSOC.exe --self-test` PASSED for the release build (reports `MoeSOC 1.1.0`)
- [x] **Hashes**: `release/v1.1.0/SHA256SUMS.txt`, verified on Windows and independently on Linux; re-verify after any rebuild

## Publishing (after your approval)

- [ ] **New clean Git repository** from `release/public-source/` (no `.git` copied from the private repo)
- [ ] Check `git status` / `git ls-files` in the new repo: no `.db`, `.log`, `real-*.png`, `audit/`, `release/`, `.bundle`
- [ ] **First GitHub push** (repository name, public or private: your choice)
- [ ] **CI green**: "Windows CI" workflow (lint, tests, CLI, GUI smoke, build, self-test, checksums)
- [ ] Tag `v1.1.0` **in the new repository** (the private `v1.0.0` tag stays private and untouched)
- [ ] **GitHub release** `v1.1.0`: `MoeSOC-Endpoint-v1.1.0-win-x64.zip` + `SHA256SUMS.txt`, notes from `RELEASE_NOTES_v1.1.0.md`; state "not code-signed"
- [ ] Repository description and topics from `docs/GITHUB_DESCRIPTION.txt` and `docs/GITHUB_TOPICS.txt`
- [ ] **CV update** ([PORTFOLIO_COPY.md](PORTFOLIO_COPY.md) §B)
- [ ] **LinkedIn update** (§C Projects, §D post)
