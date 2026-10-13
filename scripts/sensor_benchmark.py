"""Background-sensor resource measurements (always-on milestone).

    python scripts/sensor_benchmark.py burst [--events 1000]
        SYNTHETIC: 1,000 records through the sensor's real pipeline (ingest_live in
        batches of at most 500, as LiveMonitor delivers them, then the notification
        decision) in a throwaway database. Reports processing time, CPU time, peak
        memory and the latency from the last batch to the notification.

    python scripts/sensor_benchmark.py watch --service MoeSOCSensor --minutes 10
    python scripts/sensor_benchmark.py watch --name MoeSOCTray.exe --minutes 2
        REAL (Windows, run elevated to read a service process): samples a running process
        every 5 s: average and peak CPU %, working set, private bytes, write operations.

Results are printed as JSON and appended to sensor_benchmark_output.txt.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
OUT = ROOT / "sensor_benchmark_output.txt"


def _peak_memory_mb() -> float:
    if sys.platform == "win32":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        ctypes.windll.psapi.GetProcessMemoryInfo(
            wintypes.HANDLE(-1), ctypes.byref(counters), counters.cb
        )
        return counters.PeakWorkingSetSize / 2**20
    import resource

    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def burst(events: int) -> dict[str, object]:
    import demo

    from moesoc.core.config import AppConfig
    from moesoc.engine.rules import load_rules
    from moesoc.engine.scanner import ScanService
    from moesoc.sensor.notifications import NotificationEngine
    from moesoc.storage.database import Database
    from moesoc.utils.time import utc_now

    data = Path(tempfile.mkdtemp(prefix="moesoc-sensor-bench-"))
    config = AppConfig(data_dir=data, rules_dir=ROOT / "rules")
    db = Database(config.database_path)
    db.initialize()
    rules = load_rules(config.rules_dir)
    service = ScanService(config, db, rules, host_aliases=list, standalone_hosts=list)
    engine = NotificationEngine(rules)
    with db.connect() as conn:
        engine.evaluate(conn)  # baseline, as on the sensor's first start
    start = utc_now() - timedelta(minutes=30)
    records = []
    for i in range(events - 1):  # many users, a few failures each: realistic noise
        user = f"user{i % 200}"
        records.append(
            demo.auth(
                4625, user, start + timedelta(milliseconds=i * 50), 10 + i, f"198.51.100.{i % 250}"
            )
        )
    records.append(
        demo.auth(4624, "user7", start + timedelta(seconds=60), 10 + events, "198.51.100.7")
    )
    cpu0, wall0 = time.process_time(), time.perf_counter()
    batches = [records[i : i + 500] for i in range(0, len(records), 500)]
    stored = 0
    last_batch_at = wall0
    for batch in batches:
        last_batch_at = time.perf_counter()
        stored += service.ingest_live(batch).events_new
    with db.connect() as conn:
        notes = engine.evaluate(conn)
    done = time.perf_counter()
    return {
        "mode": "burst (SYNTHETIC records, real pipeline)",
        "records": len(records),
        "batches": len(batches),
        "events_stored": stored,
        "seconds": round(done - wall0, 3),
        "cpu_seconds": round(time.process_time() - cpu0, 3),
        "records_per_second": round(len(records) / (done - wall0)),
        "peak_memory_mb": round(_peak_memory_mb(), 1),
        "notifications": [f"{n.rule_id} {n.severity} {n.reason}" for n in notes],
        "notification_latency_after_last_batch_s": round(done - last_batch_at, 3),
    }


def _service_pid(name: str) -> int:
    import win32service

    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        handle = win32service.OpenService(scm, name, win32service.SERVICE_QUERY_STATUS)
        try:
            return int(win32service.QueryServiceStatusEx(handle)["ProcessId"])
        finally:
            win32service.CloseServiceHandle(handle)
    finally:
        win32service.CloseServiceHandle(scm)


def _pid_by_name(name: str) -> int:
    import win32api
    import win32con
    import win32process

    for pid in win32process.EnumProcesses():
        try:
            handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        except Exception:  # noqa: S112 - processes we may not open (protected, gone)
            continue
        try:
            path = win32process.GetModuleFileNameEx(handle, 0)
        except Exception:
            path = ""
        finally:
            win32api.CloseHandle(handle)
        if Path(path).name.lower() == name.lower():
            return pid
    raise SystemExit(f"No running process named {name}")


def watch(pid: int, minutes: float, interval: float = 5.0) -> dict[str, object]:
    import win32api
    import win32con
    import win32process

    access = win32con.PROCESS_QUERY_LIMITED_INFORMATION  # enough for times, memory, I/O
    handle = win32api.OpenProcess(access, False, pid)
    cpus = max(1, int(win32api.GetSystemInfo()[5]))

    def cpu_seconds() -> float:
        times = win32process.GetProcessTimes(handle)
        return (times["KernelTime"] + times["UserTime"]) / 1e7

    samples_cpu, samples_ws, samples_private = [], [], []
    io_start = win32process.GetProcessIoCounters(handle)
    start_cpu, start = cpu_seconds(), time.perf_counter()
    previous_cpu, previous = start_cpu, start
    end = start + minutes * 60
    while time.perf_counter() < end:
        time.sleep(interval)
        now, used = time.perf_counter(), cpu_seconds()
        samples_cpu.append(100 * (used - previous_cpu) / ((now - previous) * cpus))
        previous_cpu, previous = used, now
        memory = win32process.GetProcessMemoryInfo(handle)
        samples_ws.append(memory["WorkingSetSize"] / 2**20)
        samples_private.append(memory["PagefileUsage"] / 2**20)
    io_end = win32process.GetProcessIoCounters(handle)
    elapsed = time.perf_counter() - start
    return {
        "mode": "watch (REAL process)",
        "pid": pid,
        "minutes": round(elapsed / 60, 2),
        "logical_cpus": cpus,
        "cpu_percent_avg": round(100 * (cpu_seconds() - start_cpu) / (elapsed * cpus), 3),
        "cpu_percent_peak_5s": round(max(samples_cpu, default=0), 2),
        "working_set_mb_first_last_peak": [
            round(samples_ws[0], 1),
            round(samples_ws[-1], 1),
            round(max(samples_ws), 1),
        ],
        "private_mb_first_last_peak": [
            round(samples_private[0], 1),
            round(samples_private[-1], 1),
            round(max(samples_private), 1),
        ],
        "write_operations": io_end["WriteOperationCount"] - io_start["WriteOperationCount"],
        "write_mb": round(
            (io_end["WriteTransferCount"] - io_start["WriteTransferCount"]) / 2**20, 3
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    b = sub.add_parser("burst")
    b.add_argument("--events", type=int, default=1000)
    w = sub.add_parser("watch")
    w.add_argument("--service")
    w.add_argument("--name")
    w.add_argument("--pid", type=int)
    w.add_argument("--minutes", type=float, default=10)
    args = parser.parse_args()
    if args.mode == "burst":
        result = burst(args.events)
    else:
        pid = args.pid or (_service_pid(args.service) if args.service else _pid_by_name(args.name))
        result = {"target": args.service or args.name or pid, **watch(pid, args.minutes)}
    text = json.dumps(result, indent=2)
    print(text)
    with OUT.open("a", encoding="utf-8") as handle:
        handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n{text}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
