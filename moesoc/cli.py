"""Command-line verification interface.

    python -m moesoc.cli health
    python -m moesoc.cli scan
    python -m moesoc.cli import-xml exported.xml
    python -m moesoc.cli events --user alice --event-id 4625
    python -m moesoc.cli detections [--all]
    python -m moesoc.cli show 3
    python -m moesoc.cli triage 3 INVESTIGATING --note "checking with the user"
    python -m moesoc.cli timeline 3 --minutes 30
    python -m moesoc.cli verify-evidence 3

Output is a *safe summary*: no raw XML, no command lines, no credentials.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import timedelta
from pathlib import Path

from moesoc import APP_NAME, __version__
from moesoc.collectors.eventlog import WindowsEventLogReader
from moesoc.core.config import AppConfig
from moesoc.core.detection import related_techniques
from moesoc.core.enums import TriageStatus
from moesoc.core.exceptions import MoeSOCError
from moesoc.engine.risk import stored_risk_note
from moesoc.engine.rules import load_rules
from moesoc.engine.scanner import ScanService, ScanSummary
from moesoc.engine.validation import EvidenceStatus, verify_detection_evidence
from moesoc.health import run_health_checks
from moesoc.storage.database import Database
from moesoc.storage.event_search import EventFilter, detection_timeline, search_events
from moesoc.storage.overview import load_overview
from moesoc.storage.process_tree import build_process_tree, render_tree_lines
from moesoc.storage.report import finding_report, summary_report
from moesoc.storage.repository import DetectionRepository
from moesoc.storage.retention import (
    ALLOWED_DAYS,
    apply_retention,
    get_retention_days,
    plan_retention,
    set_retention_days,
)
from moesoc.storage.story import build_story, render_story_lines
from moesoc.storage.tuning import (
    SUPPRESSION_TYPES,
    TuningError,
    TuningRepository,
    tunable_parameters,
)
from moesoc.utils.logging import configure_logging
from moesoc.utils.privileges import hostname
from moesoc.utils.time import format_local, utc_now

log = logging.getLogger("moesoc.cli")


def _print_summary(summary: ScanSummary) -> None:
    print(f"Scan #{summary.scan_id} ({summary.origin}) finished in {summary.duration_seconds}s")
    print(f"  Records read        : {summary.records_read:,}")
    print(f"  Events normalized   : {summary.events_normalized:,}")
    print(f"  New events stored   : {summary.events_new:,}")
    print(f"  Parse failures      : {summary.parse_failures:,}")
    print(f"  Detections (window) : {summary.detections_found:,} ({summary.detections_new:,} new)")
    if summary.detections_suppressed:
        print(f"  Suppressed          : {summary.detections_suppressed:,} (matched a suppression)")
    if summary.collection_mode:
        print(f"  Collection          : {summary.collection_mode}")
    if summary.truncated:
        print("  NOTE: collection reached the per-scan limit; older events were not read.")
    for note in summary.notes:
        print(f"  NOTE: {note}")


def _progress(message: str) -> None:
    print(message, flush=True)


def _cmd_health(config: AppConfig, db: Database, _args: argparse.Namespace) -> int:
    for check in run_health_checks(db):
        print(f"{check.name:<26} {check.state.value:<12} {check.message}")
    return 0


def _cmd_scan(config: AppConfig, db: Database, _args: argparse.Namespace) -> int:
    service = ScanService(config, db, load_rules(config.rules_dir))
    _print_summary(service.run_live_scan(progress=_progress))
    return 0


def _cmd_import(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    service = ScanService(config, db, load_rules(config.rules_dir))
    _print_summary(service.import_xml_file(Path(args.file), progress=_progress))
    return 0


def _cmd_events(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    f = EventFilter(
        start=utc_now() - timedelta(hours=args.since_hours) if args.since_hours else None,
        event_ids=tuple(args.event_id or ()),
        username=args.user,
        domain=args.domain,
        ip=args.ip,
        logon_type=args.logon_type,
        process=args.process,
        sources=tuple(args.source or ()),
        text=args.text,
        provider=args.provider,
        sid=args.sid,
        port=args.port,
        parent_process=args.parent,
        file_path=args.file,
        registry_path=args.registry,
        dns_query=args.dns,
        threat=args.threat,
        hostname=args.host,
        logon_id=args.logon_id,
        limit=args.limit,
        offset=args.offset,
    )
    with db.connect() as conn:
        page = search_events(conn, f)
    if not page.events:
        print("No matching events. Run a scan first, or change the filters.")
        return 0
    print(f"{page.total:,} matching events ({f.describe()}); showing {len(page.events)}:\n")
    header = (
        f"{'Time (local)':<20} {'ID':<5} {'Account':<32} {'Logon type':<18} {'Source':<16} "
        f"{'Record':<10} Event #"
    )
    print(header)
    print("-" * len(header))
    for item in page.events:
        e = item.event
        account = e.target_account_display or e.subject_username or "—"
        print(
            f"{format_local(e.timestamp):<20} {e.event_id:<5} {account[:32]:<32} "
            f"{(e.logon_type_name or '—'):<18} {(e.source_ip or '—'):<16} "
            f"{e.record_id:<10} #{item.pk}"
        )
    return 0


def _cmd_process_tree(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    with db.connect() as conn:
        tree = build_process_tree(conn, args.event)
    print("Process tree (evidence, not a verdict). Links: guid = Sysmon ProcessGuid, ")
    print("[pid] = Security 4688 PID match (weaker), [recorded only] = parent not collected.\n")
    for line in render_tree_lines(tree):
        print(line)
    return 0


def _cmd_story(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    rules = load_rules(config.rules_dir)
    with db.connect() as conn:
        story = build_story(conn, args.id, rules)
    for line in render_story_lines(story):
        print(line)
    return 0


def _cmd_retention(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    with db.connect() as conn:
        days = args.days or get_retention_days(conn)
        if args.save:
            set_retention_days(conn, days)
            print(f"Retention period saved: {days} days.")
        plan = plan_retention(conn, days)
    print(plan.describe())
    if not args.apply:
        print("Nothing was deleted. Use --apply --yes to delete (MoeSOC data only).")
        return 0
    if not args.yes:
        print("Refusing to delete without --yes.", file=sys.stderr)
        return 1
    with db.connect() as conn:
        done = apply_retention(conn, days, confirmed=True)
    print(
        f"Deleted {done.events:,} events, {done.findings:,} closed findings and "
        f"{done.scans:,} scan records from the MoeSOC database."
    )
    return 0


def _cmd_suppress(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    rules = load_rules(config.rules_dir)
    with db.connect() as conn:
        repo = TuningRepository(conn)
        if args.action == "add":
            s = repo.add_suppression(
                args.type, args.value, args.reason, rule_id=args.rule, days=args.days,
                known_rules=rules,
            )  # fmt: skip
            expiry = format_local(s.expires_at) if s.expires_at else "until removed"
            print(f"Added suppression #{s.id}: {s.describe()}, {expiry}.")
            print("Existing findings are unchanged; future matches are not stored.")
        elif args.action == "remove":
            s = repo.remove_suppression(args.id, args.reason)
            print(f"Removed suppression #{s.id} ({s.describe()}); kept in the audit history.")
        else:
            items = repo.suppressions(include_inactive=args.all)
            if not items:
                print("No suppressions." if args.all else "No active suppressions (use --all).")
            for s in items:
                state = "removed" if s.removed_at else (
                    "expired" if not s.is_active(utc_now()) else "active"
                )  # fmt: skip
                expiry = format_local(s.expires_at) if s.expires_at else "never"
                print(
                    f"#{s.id:<4} {state:<8} {s.describe()} · expires {expiry} · "
                    f"{s.hit_count} hits · reason: {s.reason}"
                )
    return 0


def _cmd_rules(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    rules = load_rules(config.rules_dir)
    with db.connect() as conn:
        repo = TuningRepository(conn)
        if args.action in ("enable", "disable", "set"):
            rule = rules.get(args.id)
            if rule is None:
                raise TuningError(f"Unknown rule {args.id}.")
            if args.action == "set":
                repo.set_rule_parameter(rule, args.parameter, args.value, args.reason)
                print(
                    f"{rule.rule_id}: {args.parameter} = {args.value} (recorded in the audit log)."
                )
            else:
                repo.set_rule_enabled(rule, args.action == "enable", args.reason)
                print(f"{rule.rule_id} {args.action}d (recorded in the audit log).")
            return 0
        overrides = repo.overrides()
    for rule_id, rule in sorted(rules.items()):
        enabled, params = overrides.get(rule_id, (True, {}))
        values = ", ".join(
            f"{name}={params.get(name, rule.parameters[name])}" + ("*" if name in params else "")
            for name in tunable_parameters(rule)
        )
        state = "enabled " if enabled else "DISABLED"
        print(f"{rule_id:<8} v{rule.version:<4} {state} {rule.title}")
        if values:
            print(f"         {values}")
    print("\n* = tuned value (YAML default overridden)")
    return 0


def _cmd_audit(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    with db.connect() as conn:
        entries = TuningRepository(conn).audit_log(args.limit)
    if not entries:
        print("The audit log is empty.")
    for e in entries:
        print(
            f"{format_local(e.at)}  {e.action:<20} {e.target:<18} {e.details}  reason: {e.reason}"
        )
    return 0


def _cmd_report(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists() and not args.overwrite:
        raise MoeSOCError(f"{out} already exists. Use --overwrite to replace it.")
    if args.finding is not None:
        rules = load_rules(config.rules_dir)
        with db.connect() as conn:
            text = finding_report(conn, args.finding, rules, redact=args.redact)
    else:
        snapshot = load_overview(db)
        with db.connect() as conn:
            text = summary_report(conn, snapshot, redact=args.redact)
    try:
        out.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise MoeSOCError(f"Could not write {out}: {exc.strerror or exc}") from exc
    kind = "redacted " if args.redact else ""
    print(f"Wrote {kind}report: {out} ({len(text.encode('utf-8')):,} bytes)")
    return 0


def _cmd_detections(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    with db.connect() as conn:
        detections = DetectionRepository(conn).list_all()
    if not args.all:
        detections = [d for d in detections if not d.status.is_closed]
    if not detections:
        print("No detections found." if args.all else "No open detections (use --all).")
        return 0
    for d in detections:
        subject = d.account or d.evidence.get("source") or "—"
        print(
            f"#{d.id:<4} [{d.severity}/{d.confidence}] {d.rule_id} v{d.rule_version} {d.title}"
            f" — risk {d.risk_score}/100 — {d.status.label}"
        )
        print(
            f"      {subject} · {format_local(d.first_seen)} → {format_local(d.last_seen)}"
            f" · {d.occurrence_count} evidence events"
        )
    return 0


def _cmd_show(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    rules = load_rules(config.rules_dir)
    with db.connect() as conn:
        repo = DetectionRepository(conn)
        d = repo.get(args.id)
        if d is None:
            raise MoeSOCError(f"Detection #{args.id} does not exist.")
        notes, history = repo.notes(d.id), repo.history(d.id)
    rule = rules.get(d.rule_id)
    print(f"#{d.id} {d.rule_id} v{d.rule_version} — {d.title}")
    print(
        f"Severity {d.severity} · Confidence {d.confidence} · Risk {d.risk_score}/100 "
        f"· Status {d.status.label}" + (f" · Verdict {d.verdict}" if d.verdict else "")
    )
    if rule:
        mapped = ", ".join(f"{m.technique_id} {m.name}" for m in rule.mitre)
        extra = related_techniques(d.evidence)
        if extra:
            mapped = ", ".join(
                filter(None, [mapped, f"related to this finding: {', '.join(extra)}"])
            )
        print(f"MITRE: {mapped or 'none mapped (the classification comes from another source)'}")
    note = stored_risk_note(d.severity, d.confidence, d.evidence, d.risk_score)
    if note:
        print(note)
    confidence = d.evidence.get("confidence")
    if isinstance(confidence, dict):
        print(f"\nWhy confidence is {confidence.get('value')} ({confidence.get('points')} points):")
        for factor in confidence.get("factors", []):
            print(f"  {factor['points']:+d}  {factor['reason']}")
    print("\nEvidence:")
    for key, value in d.evidence.items():
        if key not in ("confidence",):
            print(f"  {key}: {value}")
    print("\nStatus history:")
    for h in history:
        print(f"  {format_local(h.changed_at)}  {h.from_status or '—'} → {h.to_status}")
    if notes:
        print("\nAnalyst notes:")
        for n in notes:
            print(f"  {format_local(n.created_at)}  {n.body}")
    return 0


def _cmd_triage(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    with db.connect() as conn:
        repo = DetectionRepository(conn)
        updated = repo.set_status(args.id, TriageStatus(args.status))
        if args.note:
            repo.add_note(args.id, args.note)
    print(f"Finding #{args.id} is now {updated.status.label}.")
    return 0


def _cmd_note(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    with db.connect() as conn:
        DetectionRepository(conn).add_note(args.id, args.text)
    print(f"Note added to finding #{args.id}.")
    return 0


def _cmd_timeline(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    with db.connect() as conn:
        timeline = detection_timeline(conn, args.id, timedelta(minutes=args.minutes))
    print(
        f"{timeline.title}: {format_local(timeline.window_start)} → "
        f"{format_local(timeline.window_end)}"
    )
    print(
        f"{len(timeline.items)} of {timeline.total_in_window} events · "
        f"{timeline.evidence_count} evidence (marked *)\n"
    )
    for item in timeline.items:
        mark = "*" if item.is_evidence else " "
        print(
            f"{mark} {format_local(item.event.timestamp)}  {item.event.event_id}  "
            f"#{item.event.record_id:<8} {item.explanation}"
        )
    for note in timeline.notes:
        print(f"\nNote: {note}")
    return 0


def _cmd_verify(config: AppConfig, db: Database, args: argparse.Namespace) -> int:
    with db.connect() as conn:
        detection_id = args.id
        if detection_id is None:
            latest = [d for d in DetectionRepository(conn).list_all() if d.rule_id == args.rule]
            if not latest:
                print(f"No {args.rule} finding stored yet.")
                return 1
            detection_id = latest[0].id  # list is newest first
        reader = WindowsEventLogReader()
        checks = verify_detection_evidence(conn, reader, detection_id, hostname())
    print(f"Finding #{detection_id}:")
    if not checks:
        print(f"Finding #{detection_id} has no linked evidence events.")
        return 1
    for c in checks:
        print(f"{c.status.value:<10} record {c.record_id:<10} event {c.event_id}  {c.detail}")
    verified = sum(c.status is EvidenceStatus.VERIFIED for c in checks)
    print(f"\n{verified} of {len(checks)} evidence events verified against the live log.")
    return 0 if verified == len(checks) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="moesoc-cli", description=f"{APP_NAME} {__version__}")
    parser.add_argument("--data-dir", type=Path, help="Use a different data directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Echo diagnostics to console")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health", help="Check privileges and telemetry availability").set_defaults(
        func=_cmd_health
    )
    sub.add_parser("scan", help="Scan the Windows Security log").set_defaults(func=_cmd_scan)
    imp = sub.add_parser("import-xml", help="Analyze an exported Security log XML file")
    imp.add_argument("file")
    imp.set_defaults(func=_cmd_import)

    ev = sub.add_parser("events", help="Search stored events (filters combine)")
    ev.add_argument("--limit", type=int, default=20)
    ev.add_argument("--user", help="account name contains")
    ev.add_argument("--domain", help="exact domain")
    ev.add_argument("--ip", help="exact address or prefix")
    ev.add_argument("--event-id", type=int, action="append", help="repeatable")
    ev.add_argument("--logon-type", type=int)
    ev.add_argument("--text", help="search normalized fields")
    ev.add_argument("--process", help="process name or path contains")
    ev.add_argument(
        "--source",
        action="append",
        choices=["security", "sysmon", "powershell", "defender"],
        help="repeatable",
    )
    ev.add_argument("--provider", help="provider contains")
    ev.add_argument("--sid", help="exact SID (target or subject)")
    ev.add_argument("--port", type=int, help="source or destination port")
    ev.add_argument("--parent", help="parent process contains")
    ev.add_argument("--file", help="file path contains")
    ev.add_argument("--registry", help="registry path contains")
    ev.add_argument("--dns", help="DNS query contains")
    ev.add_argument("--threat", help="Microsoft Defender threat name contains")
    ev.add_argument("--host", help="exact computer name")
    ev.add_argument("--logon-id", help="exact logon ID (combine with --host)")
    ev.add_argument("--offset", type=int, default=0, help="skip this many (paging)")
    ev.add_argument("--since-hours", type=float)
    ev.set_defaults(func=_cmd_events)

    det = sub.add_parser("detections", help="List findings (open only by default)")
    det.add_argument("--all", action="store_true", help="include closed findings")
    det.set_defaults(func=_cmd_detections)
    show = sub.add_parser("show", help="Full detail of one finding")
    show.add_argument("id", type=int)
    show.set_defaults(func=_cmd_show)
    tri = sub.add_parser("triage", help="Set a finding's status")
    tri.add_argument("id", type=int)
    tri.add_argument("status", choices=[s.value for s in TriageStatus])
    tri.add_argument("--note")
    tri.set_defaults(func=_cmd_triage)
    note = sub.add_parser("note", help="Add an analyst note")
    note.add_argument("id", type=int)
    note.add_argument("text")
    note.set_defaults(func=_cmd_note)
    tl = sub.add_parser("timeline", help="Events around a finding")
    tl.add_argument("id", type=int)
    tl.add_argument("--minutes", type=int, default=15)
    tl.set_defaults(func=_cmd_timeline)
    tree = sub.add_parser("process-tree", help="Ancestors and children of a process event")
    tree.add_argument("event", type=int, help="Event # from 'events' (Sysmon 1 or 4688)")
    tree.set_defaults(func=_cmd_process_tree)

    ret = sub.add_parser(
        "retention", help="Preview or apply deletion of old MoeSOC data (never Windows logs)"
    )
    ret.add_argument("--days", type=int, choices=ALLOWED_DAYS, help="default: saved setting")
    ret.add_argument("--save", action="store_true", help="save --days as the retention period")
    ret.add_argument("--apply", action="store_true", help="delete (requires --yes)")
    ret.add_argument("--yes", action="store_true", help="confirm deletion")
    ret.set_defaults(func=_cmd_retention)

    sup = sub.add_parser("suppress", help="Add, list or remove auditable suppressions")
    sup_sub = sup.add_subparsers(dest="action", required=True)
    sup_add = sup_sub.add_parser("add", help="Hide future findings that match a value")
    sup_add.add_argument("--type", required=True, choices=SUPPRESSION_TYPES)
    sup_add.add_argument("--value", required=True)
    sup_add.add_argument("--reason", required=True)
    sup_add.add_argument("--rule", help="only this rule (default: all rules)")
    sup_add.add_argument("--days", type=int, help="expire after N days (default: never)")
    sup_rm = sup_sub.add_parser("remove", help="Remove (kept in history)")
    sup_rm.add_argument("id", type=int)
    sup_rm.add_argument("--reason", required=True)
    sup_ls = sup_sub.add_parser("list")
    sup_ls.add_argument("--all", action="store_true", help="include removed and expired")
    sup.set_defaults(func=_cmd_suppress)

    rl = sub.add_parser("rules", help="List rules, enable/disable them, tune parameters")
    rl_sub = rl.add_subparsers(dest="action")
    for name in ("enable", "disable"):
        p = rl_sub.add_parser(name)
        p.add_argument("id")
        p.add_argument("--reason", required=True)
    rl_set = rl_sub.add_parser("set", help="change an integer parameter")
    rl_set.add_argument("id")
    rl_set.add_argument("parameter")
    rl_set.add_argument("value", type=int)
    rl_set.add_argument("--reason", required=True)
    rl.set_defaults(func=_cmd_rules)

    aud = sub.add_parser("audit", help="Show the tuning audit log")
    aud.add_argument("--limit", type=int, default=50)
    aud.set_defaults(func=_cmd_audit)

    rep = sub.add_parser("report", help="Write a self-contained HTML report")
    what = rep.add_mutually_exclusive_group(required=True)
    what.add_argument("--finding", type=int, help="report on one finding (its story)")
    what.add_argument("--summary", action="store_true", help="endpoint summary")
    rep.add_argument("--out", required=True, help="output .html file")
    rep.add_argument("--redact", action="store_true", help="replace hosts, users, SIDs, IPs")
    rep.add_argument("--overwrite", action="store_true")
    rep.set_defaults(func=_cmd_report)

    story = sub.add_parser("story", help="Investigation story of a finding and related findings")
    story.add_argument("id", type=int)
    story.set_defaults(func=_cmd_story)

    ver = sub.add_parser("verify-evidence", help="Re-check a finding's evidence in the live log")
    target = ver.add_mutually_exclusive_group(required=True)
    target.add_argument("id", type=int, nargs="?")
    target.add_argument("--rule", help="verify the most recent finding of this rule, e.g. COR-001")
    ver.set_defaults(func=_cmd_verify)
    return parser


def _safe_console() -> None:
    # A redirected stdout on Windows uses the ANSI code page (e.g. cp1252), which cannot
    # encode characters such as "→". Never let console encoding crash a command.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")


def main(argv: list[str] | None = None) -> int:
    _safe_console()
    args = build_parser().parse_args(argv)
    from moesoc.sensor.paths import console_data_dir

    config = AppConfig.default(args.data_dir or console_data_dir())
    # Diagnostic logs stay in the user's folder, also when reading the sensor's database.
    log_dir = config.log_dir if args.data_dir else AppConfig.default().log_dir
    configure_logging(
        log_dir, level=logging.DEBUG if args.verbose else logging.INFO, console=args.verbose
    )
    db = Database(config.database_path)
    try:
        db.initialize()
        return int(args.func(config, db, args))
    except MoeSOCError as exc:
        print(f"Error: {exc.user_message}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        # The reader closed early (e.g. "| head" or "| more" quit): not an error.
        _silence_stdout()
        return 0


def _silence_stdout() -> None:
    """Point stdout at the null device so the interpreter's final flush cannot fail again."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass


if __name__ == "__main__":
    sys.exit(main())
