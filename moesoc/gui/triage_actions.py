"""Triage and notes from the console, without Qt (testable anywhere).

B-7: a console without administrator rights can only read the sensor's database. Its
two analyst actions then go to the sensor over the local IPC pipe (``console_write``),
which validates them and saves them with the same repository code; the sensor stays the
only writer. An administrator console, or one without a sensor, writes directly as before.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from moesoc.core.enums import TriageStatus
from moesoc.sensor.ipc import console_write
from moesoc.storage.database import Database
from moesoc.storage.repository import DetectionRepository

Write = Callable[..., dict[str, Any]]


def set_triage(
    db: Database,
    detection_id: int,
    status: str,
    through_sensor: bool,
    write: Write = console_write,
) -> str:
    if through_sensor:
        reply = write("set_triage", finding=detection_id, status=TriageStatus(status).value)
        label = TriageStatus(reply["status"]).label
        return f"Finding #{detection_id} marked {label} (saved by the MoeSOC Sensor)."
    with db.connect() as conn:
        updated = DetectionRepository(conn).set_status(detection_id, TriageStatus(status))
    return f"Finding #{detection_id} marked {updated.status.label}."


def add_note(
    db: Database,
    detection_id: int,
    body: str,
    through_sensor: bool,
    write: Write = console_write,
) -> str:
    if through_sensor:
        write("add_note", finding=detection_id, body=body)
        return f"Note added to finding #{detection_id} (saved by the MoeSOC Sensor)."
    with db.connect() as conn:
        DetectionRepository(conn).add_note(detection_id, body)
    return f"Note added to finding #{detection_id}."
