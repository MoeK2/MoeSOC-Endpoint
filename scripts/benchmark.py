"""Benchmark the MoeSOC pipeline on synthetic events (real timings, synthetic data).

    python scripts/benchmark.py                 # 1k, 10k, 50k, 100k events
    python scripts/benchmark.py --sizes 1000 5000 --json docs/benchmarks/my-run.json

Every number printed is measured on this machine in this run. The *events* are
synthetic (documentation IP ranges, test accounts), generated in memory; the
database is a throwaway file in a temporary folder. Your real MoeSOC database and
the Windows event logs are never touched.

Stages (each timed separately, wall clock):
  parse   — XML → normalized events (parse_any_xml)
  store   — insert into SQLite in one transaction
  detect  — load the detection window and run every rule + risk model
  search  — three filtered, paginated searches (user, IP prefix, text)
  story   — build the investigation story of the largest finding
  report  — render that finding's HTML report
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from moesoc import __version__  # noqa: E402
from moesoc.engine.rules import load_rules  # noqa: E402
from moesoc.engine.scanner import load_rule_input, run_detections  # noqa: E402
from moesoc.parsers.dispatch import parse_any_xml  # noqa: E402
from moesoc.storage.database import Database  # noqa: E402
from moesoc.storage.event_search import EventFilter, search_events  # noqa: E402
from moesoc.storage.report import finding_report  # noqa: E402
from moesoc.storage.repository import DetectionRepository, EventRepository  # noqa: E402
from moesoc.storage.story import build_story  # noqa: E402

TEMPLATE = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>{event_id}</EventID>
    <Version>2</Version>
    <TimeCreated SystemTime="{time}" />
    <EventRecordID>{record}</EventRecordID>
    <Channel>Security</Channel>
    <Computer>BENCH-HOST.lab.example</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserSid">{sid}</Data>
    <Data Name="TargetUserName">{user}</Data>
    <Data Name="TargetDomainName">LAB</Data>
    <Data Name="TargetLogonId">0x{logon:x}</Data>
    <Data Name="LogonType">{logon_type}</Data>
    <Data Name="Status">{status}</Data>
    <Data Name="SubStatus">{sub_status}</Data>
    <Data Name="WorkstationName">WS-{ws}</Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
    <Data Name="IpAddress">{ip}</Data>
    <Data Name="IpPort">{port}</Data>
  </EventData>
</Event>"""


def generate(count: int, end: datetime) -> list[str]:
    """Background logons spread over 24 h, with a brute-force burst every 2,000 events."""
    records: list[str] = []
    span = timedelta(hours=24)
    for i in range(count):
        burst = (i % 2000) < 7  # 6 failures then a success -> DET-001 / COR-001
        if burst:  # an attack is fast: 5 s apart, starting at the burst's slot
            start = end - span + span * ((i - i % 2000) / max(count, 1))
            at = start + timedelta(seconds=5 * (i % 2000))
        else:
            at = end - span + span * (i / max(count, 1))
        if burst:
            user, ip = f"target{i // 2000}", "203.0.113.66"
            event_id = 4624 if (i % 2000) == 6 else 4625
        else:
            user, ip = f"user{i % 250}", f"192.0.2.{i % 200 + 1}"
            event_id = 4625 if i % 11 == 0 else 4624
        failure = event_id == 4625
        records.append(
            TEMPLATE.format(
                event_id=event_id,
                time=at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z",
                record=1_000_000 + i,
                sid="S-1-0-0" if failure else f"S-1-5-21-1-2-3-{1000 + i % 250}",
                user=user,
                logon=0x10000 + i,
                logon_type=3,
                status="0xC000006D" if failure else "0x0",
                sub_status="0xC000006A" if failure else "0x0",
                ws=i % 40,
                ip=ip,
                port=50000 + i % 10000,
            )
        )
    return records


def timed(fn):
    start = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start


def run(size: int, rules: dict) -> dict:
    end = datetime.now(UTC).replace(microsecond=0)
    xml = generate(size, end)
    with tempfile.TemporaryDirectory(prefix="moesoc-bench-") as folder:
        db = Database(Path(folder) / "bench.db")
        db.initialize()
        events, parse_s = timed(lambda: [parse_any_xml(x) for x in xml])

        def store():
            with db.connect() as conn:
                return EventRepository(conn).insert_many(events)

        stored, store_s = timed(store)

        def detect():
            with db.connect() as conn:
                window = load_rule_input(conn, end - timedelta(hours=25), end)
                found = run_detections(window, rules, ())
                repo = DetectionRepository(conn)
                for d in found:
                    repo.upsert(d, None)
                return found

        found, detect_s = timed(detect)

        def search():
            with db.connect() as conn:
                return [
                    search_events(conn, EventFilter(username="user1", limit=200)).total,
                    search_events(conn, EventFilter(ip="192.0.2.", limit=200)).total,
                    search_events(conn, EventFilter(text="target", limit=200)).total,
                ]

        totals, search_s = timed(search)
        with db.connect() as conn:
            biggest = max(DetectionRepository(conn).list_all(), key=lambda d: d.occurrence_count)
        story, story_s = timed(lambda: _with(db, lambda c: build_story(c, biggest.id, rules)))
        report, report_s = timed(lambda: _with(db, lambda c: finding_report(c, biggest.id, rules)))
        db_bytes = (Path(folder) / "bench.db").stat().st_size + _wal_size(Path(folder))
    return {
        "events": size,
        "stored": stored,
        "findings": len(found),
        "search_totals": totals,
        "story_steps": len(story.steps),
        "report_bytes": len(report.encode("utf-8")),
        "db_mb": round(db_bytes / 1_048_576, 1),
        "seconds": {
            "parse": round(parse_s, 3),
            "store": round(store_s, 3),
            "detect": round(detect_s, 3),
            "search": round(search_s, 3),
            "story": round(story_s, 3),
            "report": round(report_s, 3),
        },
        "events_per_second": {
            "parse": round(size / parse_s) if parse_s else None,
            "store": round(size / store_s) if store_s else None,
            "detect": round(size / detect_s) if detect_s else None,
        },
    }


def _with(db: Database, fn):
    with db.connect() as conn:
        return fn(conn)


def _wal_size(folder: Path) -> int:
    wal = folder / "bench.db-wal"
    return wal.stat().st_size if wal.exists() else 0


def machine() -> dict:
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "moesoc": __version__,
        "measured_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "note": "Real timings on synthetic events; host name intentionally not recorded.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 10_000, 50_000, 100_000])
    parser.add_argument("--json", type=Path, help="also write results to this file")
    args = parser.parse_args()
    rules = load_rules(ROOT / "rules")
    info = machine()
    print(f"MoeSOC {info['moesoc']} benchmark · {info['platform']} · Python {info['python']}")
    print(f"CPU: {info['processor']} ({info['cpu_count']} logical) · synthetic events\n")
    header = (
        f"{'events':>8} {'parse s':>8} {'store s':>8} {'detect s':>9} {'search s':>9} "
        f"{'story s':>8} {'report s':>9} {'findings':>9} {'DB MB':>6}"
    )
    print(header)
    print("-" * len(header))
    results = []
    for size in args.sizes:
        r = run(size, rules)
        results.append(r)
        s = r["seconds"]
        print(
            f"{size:>8,} {s['parse']:>8.2f} {s['store']:>8.2f} {s['detect']:>9.2f} "
            f"{s['search']:>9.3f} {s['story']:>8.3f} {s['report']:>9.3f} "
            f"{r['findings']:>9,} {r['db_mb']:>6.1f}",
            flush=True,
        )
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({"machine": info, "results": results}, indent=2) + "\n")
        print(f"\nSaved {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
