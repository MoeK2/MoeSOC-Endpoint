"""Read-only check of the Windows Event Log API that pywin32 exposes on this machine.

Prints which Evt* functions and constants exist, then proves bookmarks and record-ID
queries work by reading a few events from the Application log (no admin needed).
Nothing is written to any log or setting.

    .venv\\Scripts\\python.exe scripts\\check_eventlog_api.py
"""

from __future__ import annotations

import sys


def main() -> int:
    if sys.platform != "win32":
        print("Windows only.")
        return 2
    import pywintypes
    import win32evtlog

    print("pywin32 build:", getattr(pywintypes, "__file__", "?"))
    names = sorted(n for n in dir(win32evtlog) if n.startswith("Evt"))
    wanted = [
        "EvtQuery",
        "EvtNext",
        "EvtRender",
        "EvtSeek",
        "EvtCreateBookmark",
        "EvtUpdateBookmark",
        "EvtSubscribe",
        "EvtRenderBookmark",
        "EvtSeekRelativeToBookmark",
        "EvtSubscribeStartAfterBookmark",
        "EvtSubscribeToFutureEvents",
        "EvtQueryForwardDirection",
        "EvtQueryReverseDirection",
    ]
    for name in wanted:
        print(f"{name:34} {'present' if name in names else 'MISSING'}")

    channel = "Application"
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    handle = win32evtlog.EvtQuery(channel, flags, "*")
    events = win32evtlog.EvtNext(handle, 3)
    print(f"Read {len(events)} newest {channel} events")
    if not events:
        return 0
    xml = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
    start = xml.find("<EventRecordID>") + len("<EventRecordID>")
    record_id = int(xml[start : xml.find("<", start)])
    print("Newest record ID:", record_id)

    # Bookmark round trip.
    bookmark = win32evtlog.EvtCreateBookmark(None)
    win32evtlog.EvtUpdateBookmark(bookmark, events[0])
    bookmark_xml = win32evtlog.EvtRender(bookmark, win32evtlog.EvtRenderBookmark)
    print("Bookmark XML:", " ".join(bookmark_xml.split()))
    restored = win32evtlog.EvtCreateBookmark(bookmark_xml)
    print("Bookmark restored from XML:", restored is not None)

    # Record-ID XPath filters (the approach MoeSOC's incremental collection uses).
    older = record_id - 1
    query = f"*[System[EventRecordID>{older}]]"
    found = win32evtlog.EvtNext(
        win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath, query), 10
    )
    print(f"XPath {query!r} returned {len(found)} event(s)")
    exact = win32evtlog.EvtNext(
        win32evtlog.EvtQuery(
            channel, win32evtlog.EvtQueryChannelPath, f"*[System[EventRecordID={record_id}]]"
        ),
        2,
    )
    print(f"XPath EventRecordID={record_id} returned {len(exact)} event(s)")
    import re

    found_stamp = re.search(r"SystemTime=['\"]([^'\"]+)['\"]", xml)
    stamp = found_stamp.group(1) if found_stamp else None
    print("Newest SystemTime:", stamp)
    if stamp:
        q = f"*[System[TimeCreated[@SystemTime>='{stamp}']]]"
        by_time = win32evtlog.EvtNext(
            win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath, q), 10
        )
        print(f"XPath SystemTime>= newest returned {len(by_time)} event(s)")
    print("DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
