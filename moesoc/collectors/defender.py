"""Microsoft Defender Operational collector (detections and remediation results)."""

from __future__ import annotations

from moesoc.collectors.eventlog import EventLogReader
from moesoc.collectors.security import ChannelCollector
from moesoc.core.enums import DefenderEventId
from moesoc.parsers.defender import DEFENDER_CHANNEL, parse_defender_xml

DEFENDER_GROUPS: dict[str, frozenset[int]] = {
    "defender_detection": frozenset(int(e) for e in DefenderEventId),
}


class DefenderCollector(ChannelCollector):
    def __init__(self, reader: EventLogReader) -> None:
        super().__init__(reader, DEFENDER_CHANNEL, DEFENDER_GROUPS, parse_defender_xml)
