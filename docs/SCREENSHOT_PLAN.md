# Screenshot Plan (v1.1.0 public release)

Rules for every public screenshot:

- **No real hostname.** The console header shows the computer name. GUI-smoke and demo screenshots replace it with `WORKSTATION`. A manual capture on the real PC shows the real name and must be redacted before publishing.
- **No real username, no SID, no private path.** Only fictional accounts (`LAB\alice`, `LAB\Administrator`) and obviously synthetic SIDs (`S-1-5-21-1111111111-…`, `-7777777777-…`).
- **No private IP.** Only RFC 5737 documentation addresses (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) or loopback.
- **Never fabricated.** Every image comes from the real application. Synthetic data is labelled as such in the README.

## Recommended set (README)

| # | Screenshot | File | Source | Status |
|---|---|---|---|---|
| 1 | Overview | `docs/screenshots/demo/demo-1-overview.png` | `scripts/demo.py` (synthetic, labelled DEMO) | ✅ exists, audited |
| 2 | COR-001 detection detail (confidence and risk explained) | `docs/screenshots/03-detections.png` | `scripts/gui_smoke.py` (synthetic) | ✅ exists, audited |
| 3 | Evidence / timeline | `docs/screenshots/04-timeline.png` (and `05-evidence-events.png`) | `scripts/gui_smoke.py` | ✅ exists, audited |
| 4 | Investigation story | `docs/screenshots/09-story.png` | `scripts/gui_smoke.py` | ✅ exists, audited |
| 5 | Tray notification ("Possible Account Compromise") | `docs/screenshots/tray-notification.png` (to add) | real tray on the PC | **MANUAL CAPTURE REQUIRED** |
| 6 | Process tree / tuning | `docs/screenshots/08-process-tree.png`, `11-tuning.png` | `scripts/gui_smoke.py` | ✅ exist, audited |

### Manual capture instructions: tray notification (#5)

1. Trigger a HIGH finding the authorized way (the lock-screen test in `docs/validation.md`, or a demo database), or reuse a notification as it appears.
2. Capture **only the notification** (Win+Shift+S, rectangle). Do not capture the taskbar clock area, other notifications or other apps.
3. Check the image before committing: no account name, no computer name, no folder path. The notification body names the rule, severity and risk; it should not contain any of these. If it does, crop or blur them.
4. Save as `docs/screenshots/tray-notification.png` and add it to the README screenshot table.

Optional: a **sensor-mode Overview** showing "MoeSOC Sensor: Available". It has to be captured from the real console, so its header shows the real computer name. Redact the header (or capture on a PC whose name is generic) before publishing. Status: **MANUAL CAPTURE REQUIRED** (optional).

## Audit of every existing screenshot

Method:
- OCR (Tesseract, 2× upscale) of every tracked PNG, searched for host names (`DESKTOP-…`, the validation PC's name), user folders (`C:\Users\…`), SIDs (`S-1-5-21-…`), e-mail addresses and IP addresses.
- Visual inspection of the README images.

| File | Hostname | Username | SID | Private path | IP | Verdict |
|---|---|---|---|---|---|---|
| `01-overview-empty.png` | `WORKSTATION` | none | none | none | none | ✅ public |
| `02-overview-findings.png` | `WORKSTATION` | `LAB\Administrator` (fictional) | none | none | none | ✅ public |
| `03-detections.png` | `WORKSTATION` | `LAB\alice` (fictional) | none | none | `192.0.2.45`, `203.0.113.50` (RFC 5737) | ✅ public |
| `04-timeline.png` | `WORKSTATION` | fictional | none | none | RFC 5737 | ✅ public |
| `05-evidence-events.png` | `WORKSTATION` | fictional | none | none | RFC 5737; `WS-LAB01.lab.example` | ✅ public |
| `06-events-filtered.png` | `WORKSTATION` | fictional | none | none | RFC 5737 | ✅ public |
| `07-after-live-scan.png` | `WORKSTATION` | none | none | none | none | ✅ public (shows the limited, non-elevated state) |
| `08-process-tree.png` | `WORKSTATION` | fictional | none | none | none | ✅ public |
| `09-story.png` | `WORKSTATION` | fictional | none | none | RFC 5737 | ✅ public |
| `10-settings-retention.png` | `WORKSTATION` | none | none | none | none | ✅ public |
| `11-tuning.png` | `WORKSTATION` | fictional | none | none | none | ✅ public |
| `12-reports.png` | `WORKSTATION` | none | none | none | none | ✅ public |
| `demo/demo-1…5-*.png` | `WORKSTATION · demo`, DEMO badge | fictional | synthetic only, `S-1-5-21-7777777777-…` (demo-3) | fictional `C:\Users\alice\…` (demo-3, demo-4) | RFC 5737 | ✅ public |
| `audit/demo-*.png` | same as `demo/` (duplicates from the audit run) | | | | | ⛔ **excluded** from the public tree (duplicates) |
| `icon-sizes-dark.png`, `icon-sizes-light.png` | n/a | n/a | n/a | n/a | n/a | ✅ public |
| `real-cor001-*.png`, `real-det001-*.png` | **real host name, real account** | | | | | ⛔ **never public**: untracked (git-ignored) and excluded |

Note: `scripts/gui_smoke.py` rewrites `docs/screenshots/*.png` on every Windows verification run. The public tree takes the committed copies audited above. Re-audit before replacing them with newer captures.
