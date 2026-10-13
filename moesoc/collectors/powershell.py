"""PowerShell Operational collector (script block events), incremental like the others."""

from __future__ import annotations

from moesoc.collectors.eventlog import EventLogReader
from moesoc.collectors.security import ChannelCollector
from moesoc.core.enums import PowerShellEventId
from moesoc.parsers.powershell import POWERSHELL_CHANNEL, parse_powershell_xml

POWERSHELL_GROUPS: dict[str, frozenset[int]] = {
    "powershell_scriptblock": frozenset({int(PowerShellEventId.SCRIPT_BLOCK)}),
}


class PowerShellCollector(ChannelCollector):
    def __init__(self, reader: EventLogReader) -> None:
        super().__init__(reader, POWERSHELL_CHANNEL, POWERSHELL_GROUPS, parse_powershell_xml)
