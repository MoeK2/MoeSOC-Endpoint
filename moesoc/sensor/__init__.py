"""Always-on sensor: the background half of MoeSOC (Windows service, no GUI).

The sensor drives the same ScanService and LiveMonitor as the console; it only adds a
host (Windows service), local IPC and finding-based notifications. See
docs/ALWAYS_ON_ARCHITECTURE.md.
"""
