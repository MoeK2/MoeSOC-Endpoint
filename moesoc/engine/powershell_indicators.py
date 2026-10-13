"""Explainable indicators in PowerShell script-block text (Event 4104).

PowerShell itself is not malicious: administrators download modules, decode
base64 and hide windows for legitimate reasons. Each indicator therefore adds
points with a written reason, and DET-007 only fires when several (or one strong)
indicators add up. Only short excerpts around a match are kept; the full script
stays in the locally stored raw event and is never copied into findings or logs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

EXCERPT_RADIUS = 30
MAX_EXCERPT = 80
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=]{41,}")  # long base64-like runs are shortened


@dataclass(frozen=True, slots=True)
class Indicator:
    id: str
    points: int
    reason: str
    technique: str | None  # MITRE ATT&CK technique this behaviour relates to
    excerpt: str | None = None

    def as_evidence(self) -> dict[str, object]:
        return {
            "id": self.id,
            "points": self.points,
            "reason": self.reason,
            "technique": self.technique,
            "excerpt": self.excerpt,
        }


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


DOWNLOAD = _re(
    r"Net\.WebClient|DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|"
    r"Invoke-RestMethod|\birm\b|Start-BitsTransfer|Net\.Http\.HttpClient"
)
EXECUTE = _re(r"\bIEX\b|Invoke-Expression|\|\s*iex\b|\.Invoke\(\)|ScriptBlock\]::Create")
BASE64 = _re(r"FromBase64String")
AMSI = _re(r"AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsiContext")
DEFENDER = _re(
    r"Set-MpPreference\b[^\n]*-Disable\w*|Add-MpPreference\b[^\n]*-Exclusion\w*|"
    r"Set-MpPreference\b[^\n]*-ExclusionPath"
)
CREDENTIALS = _re(r"sekurlsa|Invoke-Mimikatz|MiniDumpWriteDump|comsvcs(\.dll)?[^\n]*MiniDump")
INJECTION = _re(r"VirtualAlloc(Ex)?|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx")
NATIVE_IMPORT = _re(r"DllImport|Add-Type")
REFLECTION = _re(r"Reflection\.Assembly\]::Load|\[Reflection\.Assembly\]::Load|Assembly\]::Load\(")
HIDDEN = _re(r"-w(indowstyle)?\s+(hidden|1)\b")
FORMAT_OBFUSCATION = re.compile(r"\"\{\d\}\{\d\}[^\"]*\"\s*-f\b", re.IGNORECASE)
CHAR_JOIN = _re(r"\[char\]\s*\d+\s*\+|-join\s*\(?\s*\[char")


def excerpt(text: str, match: re.Match[str] | None) -> str | None:
    """A short, single-line window around the match; long base64 runs are shortened."""
    if match is None:
        return None
    start = max(0, match.start() - EXCERPT_RADIUS)
    end = min(len(text), match.end() + EXCERPT_RADIUS)
    window = " ".join(text[start:end].split())
    window = _LONG_TOKEN.sub(lambda m: m.group(0)[:12] + "…", window)
    if len(window) > MAX_EXCERPT:
        window = window[: MAX_EXCERPT - 1] + "…"
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) and not window.endswith("…") else ""
    return f"{prefix}{window}{suffix}"


def analyze_script(text: str | None, *, windows_flagged: bool = False) -> list[Indicator]:
    """Indicators found in one script block (or one fragment of it)."""
    found: list[Indicator] = []
    if windows_flagged:
        found.append(
            Indicator(
                "windows_flagged",
                2,
                "PowerShell itself logged this script block as suspicious (Warning level)",
                None,
            )
        )
    if not text:
        return found

    download = DOWNLOAD.search(text)
    execute = EXECUTE.search(text)
    if download and execute:
        found.append(
            Indicator(
                "download_execute",
                3,
                "Downloads content and executes it (download cradle)",
                "T1105",
                excerpt(text, download),
            )
        )
    elif download:
        found.append(
            Indicator(
                "download",
                1,
                "Downloads content from the network",
                "T1105",
                excerpt(text, download),
            )
        )

    base64 = BASE64.search(text)
    if base64 and (execute or REFLECTION.search(text) or download):
        found.append(
            Indicator(
                "encoded_payload",
                2,
                "Decodes base64 and executes or loads the result",
                "T1027",
                excerpt(text, base64),
            )
        )
    elif base64:
        found.append(
            Indicator("base64_decode", 1, "Decodes base64 data", "T1027", excerpt(text, base64))
        )

    checks = (
        (AMSI, "amsi_bypass", 3, "References AMSI internals (typical AMSI bypass)", "T1562.001"),
        (
            DEFENDER,
            "defender_tamper",
            3,
            "Disables Defender features or adds exclusions",
            "T1562.001",
        ),
        (
            CREDENTIALS,
            "credential_theft",
            3,
            "Credential-dumping keywords (LSASS / Mimikatz)",
            "T1003.001",
        ),
        (REFLECTION, "reflective_load", 2, "Loads a .NET assembly from memory", "T1620"),
        (HIDDEN, "hidden_window", 1, "Starts PowerShell with a hidden window", "T1564.003"),
    )
    for pattern, ident, points, reason, technique in checks:
        match = pattern.search(text)
        if match:
            found.append(Indicator(ident, points, reason, technique, excerpt(text, match)))

    injection = INJECTION.search(text)
    if injection and NATIVE_IMPORT.search(text):
        found.append(
            Indicator(
                "injection_api",
                2,
                "Imports native memory/thread APIs used for code injection",
                "T1055",
                excerpt(text, injection),
            )
        )

    backticks = text.count("`")
    formats = len(FORMAT_OBFUSCATION.findall(text))
    char_join = CHAR_JOIN.search(text)
    if backticks >= 15 or formats >= 3 or char_join:
        reasons = []
        if backticks >= 15:
            reasons.append(f"{backticks} backtick escapes")
        if formats >= 3:
            reasons.append(f"{formats} format-string fragments")
        if char_join:
            reasons.append("strings built from character codes")
        found.append(
            Indicator(
                "obfuscation",
                2,
                "Obfuscated text: " + ", ".join(reasons),
                "T1027",
                excerpt(text, char_join) if char_join else None,
            )
        )
    return found


def merge(indicators: list[Indicator]) -> list[Indicator]:
    """One entry per indicator id (a script split over several events counts once)."""
    best: dict[str, Indicator] = {}
    for indicator in indicators:
        current = best.get(indicator.id)
        if current is None or (current.excerpt is None and indicator.excerpt is not None):
            best[indicator.id] = indicator
    return sorted(best.values(), key=lambda i: (-i.points, i.id))
