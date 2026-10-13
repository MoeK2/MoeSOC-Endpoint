"""Real Windows check that live monitoring DELIVERS new Security events (audit item A-4).

Run elevated through ``scripts\\validate_live_delivery.bat`` (standard UAC prompt).

Read-only for Windows: it never changes audit policy, logs or accounts. It uses a fresh,
separate database folder (``live-validation-data``), never your real MoeSOC data.

How a harmless Security event is produced: when "Audit Process Creation" is already
enabled on this PC (MoeSOC checks for existing Event 4688 records and changes nothing),
starting ``whoami.exe`` writes one Event 4688. The script reads the live log itself to
confirm Windows wrote that record; if it did not, the result is INCONCLUSIVE (nothing to
deliver), never PASSED or FAILED. The check:

  1. start live monitoring (catch-up scan, then subscription) and wait for ON
  2. run whoami.exe once; the 4688 must arrive through the subscription, without a scan
  3. the database must contain that record exactly once
  4. stop; restart; run where.exe once; it must arrive once; nothing is duplicated

If process-creation auditing is off, it stops and prints the manual alternative (two
wrong passwords at the lock screen) instead of changing any policy.
Output: live_delivery_output.txt (counts and record numbers only, no names).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from moesoc.collectors.eventlog import WindowsEventLogReader  # noqa: E402
from moesoc.collectors.subscription import WindowsSubscriptionSource  # noqa: E402
from moesoc.core.config import AppConfig  # noqa: E402
from moesoc.engine.live import LiveMonitor  # noqa: E402
from moesoc.engine.rules import load_rules  # noqa: E402
from moesoc.engine.scanner import ScanService  # noqa: E402
from moesoc.storage.database import Database  # noqa: E402
from moesoc.utils.privileges import is_admin  # noqa: E402

DATA = ROOT / "live-validation-data"
OUT = ROOT / "live_delivery_output.txt"
LINES: list[str] = []
WAIT_FOR_DELIVERY = 30.0


def out(text: str = "") -> None:
    LINES.append(text)
    print(text, flush=True)


def count_process(db: Database, exe: str) -> list[int]:
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT record_id FROM events WHERE event_id = 4688 AND lower(process_path) LIKE ?",
            (f"%\\{exe.lower()}",),
        ).fetchall()
    return sorted(r[0] for r in rows)


RECORD_ID = re.compile(r"<EventRecordID>(\\d+)</EventRecordID>")


def newest_security_record(reader: WindowsEventLogReader) -> int:
    """EventRecordID of the newest Security record, read from Windows, not MoeSOC."""
    for xml in reader.query("Security", "*", newest_first=True):
        match = RECORD_ID.search(xml)
        return int(match.group(1)) if match else 0
    return 0


def written_by_windows(reader: WindowsEventLogReader, after: int, exe: str) -> list[int]:
    """4688 records for ``exe`` that Windows itself wrote after record ``after``."""
    xpath = f"*[System[(EventID=4688) and (EventRecordID>{int(after)})]]"
    found = []
    for xml in reader.query("Security", xpath):
        if f"\\{exe.lower()}<" in xml.lower():
            match = RECORD_ID.search(xml)
            if match:
                found.append(int(match.group(1)))
    return sorted(found)


def run_once(
    label: str,
    service: ScanService,
    db: Database,
    reader: WindowsEventLogReader,
    exe: list[str],
) -> dict:
    states: list[tuple[float, str, str]] = []
    batches = []
    stop = threading.Event()
    t0 = time.monotonic()
    monitor = LiveMonitor(
        service,
        WindowsSubscriptionSource,
        lambda s, m: states.append((round(time.monotonic() - t0, 2), s.value, m)),
        batches.append,
    )
    thread = threading.Thread(target=monitor.run, args=(stop,), daemon=True)
    thread.start()
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and not any(s[1] in ("ON", "ERROR") for s in states):
        time.sleep(0.2)
    if not any(s[1] == "ON" for s in states):
        stop.set()
        thread.join(30)
        out(f"[{label}] monitor did not reach ON: {states}")
        return {"verdict": "FAILED"}
    name = Path(exe[0]).name
    before = count_process(db, name)
    log_mark = newest_security_record(reader)
    started = time.monotonic()
    # Fixed System32 paths from this script, never event data; no shell.
    subprocess.run(exe, capture_output=True, check=False, timeout=30)  # noqa: S603
    arrived_at = None
    while time.monotonic() - started < WAIT_FOR_DELIVERY:
        if len(count_process(db, name)) > len(before):
            arrived_at = round(time.monotonic() - started, 2)
            break
        time.sleep(0.25)
    time.sleep(3)  # let any duplicate show up before counting
    after = count_process(db, name)
    stop.set()
    thread.join(30)
    new = [r for r in after if r not in before]
    in_log = written_by_windows(reader, log_mark, name)
    delivered = sum(b.events_new for b in batches)
    if not in_log:
        verdict = "INCONCLUSIVE"  # Windows wrote no trigger record: nothing to deliver
    elif arrived_at is not None and new == in_log:
        verdict = "PASSED"
    else:
        verdict = "FAILED"  # Windows wrote it, MoeSOC did not store it exactly once
    result = {
        "verdict": verdict,
        "written_by_windows": in_log,
        "arrived_after_s": arrived_at,
        "new_records": new,
        "batches": len(batches),
        "events_new_in_batches": delivered,
        "states": [(t, s) for t, s, _ in states],
        "stopped": not thread.is_alive(),
    }
    out(f"[{label}] {name}: {result}")
    return result


def main() -> int:
    out(f"MoeSOC live delivery validation - {time.strftime('%Y-%m-%d %H:%M:%S')}")
    if not is_admin():
        out("Not elevated: run scripts\\validate_live_delivery.bat and approve the UAC prompt.")
        return 2
    reader = WindowsEventLogReader()
    has_4688 = any(True for _ in reader.query("Security", "*[System[(EventID=4688)]]"))
    if not has_4688:
        out("Process-creation auditing appears to be OFF (no Event 4688 in the Security log).")
        out("MoeSOC does not change audit policy. MANUAL alternative:")
        out("  1. Start MoeSOC elevated, switch Live on, note the event count.")
        out("  2. Lock the screen (Win+L), type a wrong password twice, then log in.")
        out("  3. Within ~10 s the two Event 4625 records must appear without pressing Scan.")
        return 3
    if DATA.exists():
        shutil.rmtree(DATA)
    config = AppConfig(data_dir=DATA, rules_dir=ROOT / "rules")
    db = Database(config.database_path)
    db.initialize()
    service = ScanService(config, db, load_rules(config.rules_dir))
    system32 = Path(r"C:\Windows\System32")
    first = run_once(
        "run 1 (start, deliver, stop)", service, db, reader, [str(system32 / "whoami.exe")]
    )
    second = run_once(
        "run 2 (restart, deliver, stop)", service, db, reader, [str(system32 / "where.exe"), "/?"]
    )
    with db.connect() as conn:
        dups = conn.execute(
            "SELECT COUNT(*) FROM (SELECT channel, record_id, COUNT(*) n FROM events "
            "GROUP BY 1, 2 HAVING n > 1)"
        ).fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    out(f"events stored: {total}; duplicate rows: {dups}")
    verdicts = {first.get("verdict", "FAILED"), second.get("verdict", "FAILED")}
    if dups or "FAILED" in verdicts:
        out("LIVE DELIVERY: FAILED")
        return 1
    if "INCONCLUSIVE" in verdicts:
        out("LIVE DELIVERY: INCONCLUSIVE - Windows wrote no Event 4688 for the test process,")
        out("so there was nothing to deliver (process-creation auditing is probably off now).")
        out("MoeSOC does not change audit policy. Use the manual check instead:")
        out("  1. Start MoeSOC elevated, switch Live on, note the event count.")
        out("  2. Lock the screen (Win+L), type a wrong password twice, then log in.")
        out("  3. Within ~10 s the two Event 4625 records must appear without pressing Scan.")
        return 3
    out("LIVE DELIVERY: PASSED")
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception as exc:  # report, never hide
        out(f"ERROR {type(exc).__name__}: {exc}")
        code = 1
    OUT.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    sys.exit(code)
