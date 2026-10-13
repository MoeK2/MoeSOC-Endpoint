"""The normalized event model shared by every pipeline stage.

Every telemetry source is converted into a ``NormalizedEvent``. Fields that a
given event does not contain stay ``None`` — values are never invented.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from moesoc.core.enums import LOGON_TYPE_NAMES, TelemetrySource
from moesoc.core.identity import AccountIdentity, target_identity


@dataclass(frozen=True, slots=True)
class EventRef:
    """Stable identity of one stored Windows event (EventRecordID is per host + channel)."""

    hostname: str
    channel: str
    record_id: int


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    # --- identity (always present) -------------------------------------
    timestamp: datetime  # timezone-aware, UTC
    record_id: int
    source: TelemetrySource
    channel: str
    provider: str
    event_id: int
    hostname: str
    raw_xml: str

    # --- accounts -------------------------------------------------------
    subject_username: str | None = None
    subject_domain: str | None = None
    subject_user_sid: str | None = None
    target_username: str | None = None
    target_domain: str | None = None
    target_user_sid: str | None = None
    logon_type: int | None = None
    logon_id: str | None = None
    logon_guid: str | None = None
    logon_process: str | None = None
    authentication_package: str | None = None
    workstation_name: str | None = None

    # --- process --------------------------------------------------------
    process_name: str | None = None
    process_path: str | None = None
    parent_process: str | None = None
    command_line: str | None = None

    # --- network --------------------------------------------------------
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None

    # --- objects --------------------------------------------------------
    file_path: str | None = None
    registry_path: str | None = None

    # --- outcome --------------------------------------------------------
    status: str | None = None
    sub_status: str | None = None
    failure_reason: str | None = None

    # --- account management (4720, 4732) ---------------------------------
    member_name: str | None = None  # 4732: often a DN, or empty for local accounts
    member_sid: str | None = None
    group_name: str | None = None
    group_domain: str | None = None
    group_sid: str | None = None

    # --- privileges and processes (4672, 4688) ---------------------------
    privileges: str | None = None  # space-separated privilege names, as Windows lists them
    process_id: int | None = None
    parent_process_id: int | None = None
    token_elevation: str | None = None  # Full / Limited / Default (4688)
    integrity_level: str | None = None  # Low / Medium / High / System (4688 MandatoryLabel)

    # --- Sysmon ---------------------------------------------------------
    process_guid: str | None = None  # stable process identity (PIDs are reused)
    parent_process_guid: str | None = None
    hashes: str | None = None  # as configured in Sysmon, e.g. "SHA256=…,MD5=…"
    dns_query: str | None = None
    network_protocol: str | None = None

    # --- anything else worth keeping, as a JSON object string ------------
    details: str | None = None

    @property
    def identity(self) -> AccountIdentity | None:
        """Target account identity of this event alone (see core/identity.py)."""
        return target_identity(self)

    def detail(self, key: str) -> Any:
        """One value from ``details`` (None when absent or unreadable)."""
        if not self.details:
            return None
        try:
            data = json.loads(self.details)
        except ValueError:
            return None
        return data.get(key) if isinstance(data, dict) else None

    @property
    def privilege_list(self) -> list[str]:
        return self.privileges.split() if self.privileges else []

    @property
    def subject_account_display(self) -> str | None:
        if not self.subject_username:
            return None
        if self.subject_domain:
            return f"{self.subject_domain}\\{self.subject_username}"
        return self.subject_username

    @property
    def ref(self) -> EventRef:
        return EventRef(self.hostname, self.channel, self.record_id)

    @property
    def logon_type_name(self) -> str | None:
        if self.logon_type is None:
            return None
        return LOGON_TYPE_NAMES.get(self.logon_type, f"Type {self.logon_type}")

    @property
    def target_account_display(self) -> str | None:
        if not self.target_username:
            return None
        if self.target_domain:
            return f"{self.target_domain}\\{self.target_username}"
        return self.target_username
