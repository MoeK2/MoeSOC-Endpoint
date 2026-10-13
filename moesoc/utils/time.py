"""Timestamp helpers. Everything internal is timezone-aware UTC."""

from __future__ import annotations

import re
from datetime import UTC, datetime

# Windows SystemTime uses up to 7 fractional digits (100 ns); Python supports 6.
_FRACTION = re.compile(r"\.(\d+)")


def parse_windows_timestamp(value: str) -> datetime:
    """Parse ``TimeCreated/@SystemTime`` (e.g. ``2026-10-06T08:15:22.1234567Z``).

    Raises ValueError for unparseable input.
    """
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_local(ts: datetime | None) -> str:
    """Analyst-facing local time string."""
    if ts is None:
        return "—"
    return ts.astimezone().strftime("%Y-%m-%d %H:%M:%S")
