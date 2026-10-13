"""Sysmon collector: the same incremental logic, one budget per event family.

Network, file and registry events can be far more numerous than process events, so
each family is its own group with its own position and budget.
"""

from __future__ import annotations

from moesoc.collectors.eventlog import EventLogReader
from moesoc.collectors.security import ChannelCollector
from moesoc.core.enums import SysmonEventId
from moesoc.parsers.sysmon import SYSMON_CHANNEL, parse_sysmon_xml

SYSMON_GROUPS: dict[str, frozenset[int]] = {
    "sysmon_process": frozenset({int(SysmonEventId.PROCESS_CREATE)}),
    "sysmon_network": frozenset({int(SysmonEventId.NETWORK_CONNECT)}),
    "sysmon_file": frozenset({int(SysmonEventId.FILE_CREATE)}),
    "sysmon_registry": frozenset({int(SysmonEventId.REGISTRY_VALUE_SET)}),
    "sysmon_dns": frozenset({int(SysmonEventId.DNS_QUERY)}),
}


class SysmonCollector(ChannelCollector):
    def __init__(self, reader: EventLogReader) -> None:
        super().__init__(reader, SYSMON_CHANNEL, SYSMON_GROUPS, parse_sysmon_xml)
