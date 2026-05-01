#!/usr/bin/env python3
"""
Push synthetic Windows Event Log entries via the Windows API for end-to-end benchmarking.

Writes events directly into a Windows Event Log channel using pywin32's
ReportEvent API.  Elastic Agent's winlog input picks them up from the real
Windows Event Log, pushing them through the genuine ingest pipeline so you
measure true end-to-end throughput (agent → ingest pipeline → Elasticsearch).

Requirements:
  Windows host, Python 3.8+, pywin32
    pip install pywin32

Channels:
  Application  – default; no special setup, runs unprivileged.
  System       – requires elevated privileges (run as Administrator).
  Custom log   – pass any registered channel name via --channel.

  For the ForwardedEvents channel (WEF), configure a local WEF subscription
  that subscribes to this machine's Application log, then point the agent at
  ForwardedEvents as normal.  The script itself always writes via ReportEvent,
  so it cannot write directly to ForwardedEvents.

Usage:
  # Minimal: 50 000 events → Application log (single thread)
  python push_windows_events.py --count 50000

  # High-throughput: 500 000 events, 8 writer threads
  python push_windows_events.py --count 500000 --workers 8

  # Continuous until Ctrl-C, targeting ~5 000 events/s
  python push_windows_events.py --continuous --rate 5000

  # Write to System log (as Administrator)
  python push_windows_events.py --count 100000 --channel System --workers 4

  # Reproducible run (fixed seed) with progress output
  python push_windows_events.py --count 200000 --seed 42 --verbose

The script registers a temporary event source "ElasticBenchmark" in the
target channel, writes the requested events, then removes the source on exit.
Each event carries realistic string-insert fields that exercise the ingest
pipeline's parsing and ECS mapping logic.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import queue
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional

# ---------------------------------------------------------------------------
# Guard: Windows only
# ---------------------------------------------------------------------------
if sys.platform != "win32":
    sys.exit("This script must run on Windows.  "
             "For cross-platform corpus generation use generate_windows_events.py instead.")

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import win32api
    import pywintypes
except ImportError:
    sys.exit(
        "pywin32 is required.\n"
        "  pip install pywin32\n"
        "  python -m pywin32_postinstall -install   # if needed after install"
    )

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

_COMPUTERS   = ["DC01", "DC02", "FS01", "WEB01", "WS-ALICE", "WS-BOB",
                 "WS-CHARLIE", "SRV-SQL01", "SRV-APP01"]
_USERS       = ["alice", "bob", "charlie", "david", "eve", "frank",
                "administrator", "svc_backup", "svc_monitor", "SYSTEM"]
_DOMAINS     = ["CORP", "EXAMPLE", "ACME", "WORKGROUP"]
_PROCESSES   = [
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\powershell.exe",
    r"C:\Windows\System32\wscript.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Program Files\Internet Explorer\iexplore.exe",
    r"C:\Windows\System32\net.exe",
    r"C:\Windows\System32\wevtutil.exe",
]
_LOGON_TYPES = ["2", "3", "4", "5", "7", "10"]
_AUTH_PKGS   = ["NTLM", "Kerberos", "Negotiate"]
_DNS_HOSTS   = ["www.microsoft.com", "update.windows.com", "dc01.corp.local",
                "github.com", "api.github.com", "malware-c2.example.org"]
_PORTS       = ["80", "443", "445", "8080", "3389", "22", "25"]
_IPS         = [f"10.{a}.{b}.{c}"
                for a in range(0, 4) for b in range(1, 20) for c in range(1, 50)]

def _r(seq):
    return random.choice(seq)

def _hex(n=8):
    return "".join(random.choices("0123456789abcdef", k=n))


# ---------------------------------------------------------------------------
# Event templates
#
# Each entry is (event_id, event_type, weight, string_inserts_factory).
# string_inserts_factory() → list[str]  (the StringInserts written by ReportEvent)
#
# The winlog input exposes these as winlog.event_data.Data[n] / message fields,
# which the forwarded ingest pipeline maps to ECS fields.
# ---------------------------------------------------------------------------

def _strings_logon_success():
    return [
        _r(_USERS), _r(_DOMAINS), f"0x{_hex(5)}",
        "S-1-0-0", "-", "-", "0x0",
        _r(_USERS), _r(_DOMAINS), f"0x{_hex(6)}",
        f"S-1-5-21-{_hex(9)}-{_hex(9)}-{_hex(9)}-1000",
        _r(_LOGON_TYPES), "0", "NtLmSsp", _r(_AUTH_PKGS),
        _r(["WS-ALICE", "WS-BOB", "WS-CHARLIE"]),
        f"{_r(_IPS)}", str(random.randint(1024, 65535)),
        "-", "-", "0",
    ]

def _strings_logon_failure():
    s = _strings_logon_success()
    s.extend(["%%2313", "0xc000006d", "0xc000006a"])
    return s

def _strings_logoff():
    return [
        f"S-1-5-21-{_hex(9)}-{_hex(9)}-{_hex(9)}-1000",
        _r(_USERS), _r(_DOMAINS), f"0x{_hex(6)}", _r(_LOGON_TYPES),
    ]

def _strings_process_create():
    return [
        f"S-1-5-21-{_hex(9)}-{_hex(9)}-{_hex(9)}-500",
        _r(_USERS), _r(_DOMAINS), f"0x{_hex(5)}",
        f"0x{_hex(4)}", _r(_PROCESSES), "%%1937", f"0x{_hex(4)}",
        _r(_PROCESSES), "-", "-", "0x0", "0x0",
        "S-1-16-12288",
    ]

def _strings_process_exit():
    return [
        f"S-1-5-21-{_hex(9)}-{_hex(9)}-{_hex(9)}-500",
        _r(_USERS), _r(_DOMAINS), f"0x{_hex(5)}",
        f"0x{_hex(4)}", _r(_PROCESSES), "0x0",
    ]

def _strings_network_share():
    return [
        f"S-1-5-21-{_hex(9)}-{_hex(9)}-{_hex(9)}-1000",
        _r(_USERS), _r(_DOMAINS), f"0x{_hex(5)}",
        _r(_COMPUTERS), _r(_IPS),
        r"\\*\IPC$", "%%4416",
    ]

def _strings_kerberos_tgs():
    user = _r(_USERS)
    return [
        f"{user}@{_r(_DOMAINS)}.LOCAL", _r(_DOMAINS),
        f"host/{_r(_COMPUTERS)}.corp.local",
        f"S-1-5-21-{_hex(9)}-{_hex(9)}-{_hex(9)}-502",
        "0x40810000", _r(["0x12", "0x11", "0x17"]),
        f"::{_r(_IPS)}", str(random.randint(1024, 65535)),
        "0x0", "-",
    ]

def _strings_powershell_block():
    cmds = [
        "Get-Process", "Get-Service", "Invoke-WebRequest -Uri http://example.com",
        "Set-ExecutionPolicy Bypass", "Import-Module ActiveDirectory",
        "Get-ADUser -Filter *", "New-Item -Path C:\\Temp\\file.txt",
    ]
    return [
        "1", "1", _r(cmds),
        f"{{{_hex(8)}-{_hex(4)}-{_hex(4)}-{_hex(4)}-{_hex(12)}}}",
        "",
    ]

def _strings_sysmon_process():
    proc = _r(_PROCESSES)
    return [
        "-",
        datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
        f"{{{_hex(8)}-{_hex(4)}-{_hex(4)}-{_hex(4)}-{_hex(12)}}}",
        str(random.randint(100, 65535)),
        proc, f"{random.randint(1,20)}.0.0.0", "Windows process",
        "Microsoft Corporation", proc.split("\\")[-1], proc,
        r"C:\Windows\system32\\",
        f"{_r(_DOMAINS)}\\{_r(_USERS)}", f"{{{_hex(8)}-{_hex(4)}-{_hex(4)}-{_hex(4)}-{_hex(12)}}}",
        f"0x{_hex(5)}", "1", "Medium",
        f"MD5={_hex(32).upper()},SHA256={_hex(64).upper()}",
        f"{{{_hex(8)}-{_hex(4)}-{_hex(4)}-{_hex(4)}-{_hex(12)}}}",
        str(random.randint(100, 65535)),
        _r(_PROCESSES), _r(_PROCESSES),
        f"{_r(_DOMAINS)}\\{_r(_USERS)}",
    ]

def _strings_sysmon_network():
    return [
        "-",
        datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
        f"{{{_hex(8)}-{_hex(4)}-{_hex(4)}-{_hex(4)}-{_hex(12)}}}",
        str(random.randint(100, 65535)),
        _r(_PROCESSES),
        f"{_r(_DOMAINS)}\\{_r(_USERS)}",
        _r(["tcp", "udp"]),
        _r(["true", "false"]),
        "false", _r(_IPS), _r(_COMPUTERS),
        str(random.randint(1024, 65535)), "-",
        "false", _r(_IPS), _r(_DNS_HOSTS),
        _r(_PORTS), _r(["https", "http", "ms-rdp", "-"]),
    ]

def _strings_sysmon_dns():
    return [
        "-",
        datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
        f"{{{_hex(8)}-{_hex(4)}-{_hex(4)}-{_hex(4)}-{_hex(12)}}}",
        str(random.randint(100, 65535)),
        _r(_DNS_HOSTS), "0",
        f"type: 5 {_r(_DNS_HOSTS)};{_r(_IPS)};",
        _r(_PROCESSES),
        f"{_r(_DOMAINS)}\\{_r(_USERS)}",
    ]

def _strings_sysmon_file():
    user = _r(_USERS)
    paths = [
        fr"C:\Users\{user}\AppData\Local\Temp\{_hex(8)}.exe",
        fr"C:\Windows\Temp\{_hex(8)}.dll",
        fr"C:\ProgramData\{_hex(8)}.bat",
    ]
    return [
        "-",
        datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
        f"{{{_hex(8)}-{_hex(4)}-{_hex(4)}-{_hex(4)}-{_hex(12)}}}",
        str(random.randint(100, 65535)),
        _r(_PROCESSES), _r(paths),
        datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:23],
        f"{_r(_DOMAINS)}\\{user}",
    ]


# (event_id, win32_type, weight, factory)
_SECURITY_EVENTS = [
    (4624, win32evtlog.EVENTLOG_AUDIT_SUCCESS, 35, _strings_logon_success),
    (4625, win32evtlog.EVENTLOG_AUDIT_FAILURE, 10, _strings_logon_failure),
    (4634, win32evtlog.EVENTLOG_AUDIT_SUCCESS, 20, _strings_logoff),
    (4688, win32evtlog.EVENTLOG_AUDIT_SUCCESS, 20, _strings_process_create),
    (4689, win32evtlog.EVENTLOG_AUDIT_SUCCESS, 10, _strings_process_exit),
    (5140, win32evtlog.EVENTLOG_AUDIT_SUCCESS,  5, _strings_network_share),
]

_SYSMON_EVENTS = [
    (1,  win32evtlog.EVENTLOG_INFORMATION_TYPE, 30, _strings_sysmon_process),
    (3,  win32evtlog.EVENTLOG_INFORMATION_TYPE, 20, _strings_sysmon_network),
    (5,  win32evtlog.EVENTLOG_INFORMATION_TYPE, 10, _strings_sysmon_process),
    (11, win32evtlog.EVENTLOG_INFORMATION_TYPE, 20, _strings_sysmon_file),
    (22, win32evtlog.EVENTLOG_INFORMATION_TYPE, 20, _strings_sysmon_dns),
]

_MIXED_EVENTS = _SECURITY_EVENTS + _SYSMON_EVENTS

_POWERSHELL_EVENTS = [
    (4104, win32evtlog.EVENTLOG_WARNING_TYPE, 100, _strings_powershell_block),
]

_EVENT_SETS = {
    "security":    _SECURITY_EVENTS,
    "sysmon":      _SYSMON_EVENTS,
    "powershell":  _POWERSHELL_EVENTS,
    "mixed":       _MIXED_EVENTS,
}


def _build_weighted(event_set):
    ids, types, weights, factories = zip(*[
        (eid, etype, w, f) for eid, etype, w, f in event_set
    ])
    return ids, types, weights, factories


# ---------------------------------------------------------------------------
# Event source management
# ---------------------------------------------------------------------------

SOURCE_NAME = "ElasticBenchmark"

def register_source(channel: str) -> None:
    """Register a minimal event source so ReportEvent doesn't error."""
    try:
        win32evtlogutil.AddSourceToRegistry(
            SOURCE_NAME,
            msgDLL=None,         # no message DLL — strings go in as-is
            eventLogType=channel,
            eventTypes=(win32evtlog.EVENTLOG_INFORMATION_TYPE |
                        win32evtlog.EVENTLOG_WARNING_TYPE |
                        win32evtlog.EVENTLOG_ERROR_TYPE |
                        win32evtlog.EVENTLOG_AUDIT_SUCCESS |
                        win32evtlog.EVENTLOG_AUDIT_FAILURE),
        )
    except pywintypes.error as e:
        # 5 = access denied (need admin for System); 87 = already registered
        if e.winerror == 5:
            sys.exit(
                f"Access denied registering event source in '{channel}'.\n"
                "  Run as Administrator, or use --channel Application."
            )
        if e.winerror != 87:  # 87 = key already exists, fine to ignore
            raise


def unregister_source() -> None:
    try:
        win32evtlogutil.RemoveSourceFromRegistry(SOURCE_NAME)
    except Exception:
        pass  # best-effort cleanup


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

@dataclass
class Stats:
    written: int = 0
    errors:  int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, n: int, err: int = 0) -> None:
        with self._lock:
            self.written += n
            self.errors  += err


def _writer_thread(
    work_queue: queue.Queue,
    channel: str,
    ids, types, weights, factories,
    stats: Stats,
    rate_limit: Optional[float],    # events/s per thread, None = unlimited
) -> None:
    handle = win32evtlog.OpenEventLog(None, channel)
    batch_size = 64

    while True:
        try:
            n = work_queue.get_nowait()
        except queue.Empty:
            break

        t0 = time.monotonic()
        ok = err = 0

        for _ in range(n):
            try:
                (eid,), (etype,), (factory,) = (
                    random.choices(ids,      weights=weights, k=1),
                    random.choices(types,    weights=weights, k=1),
                    random.choices(factories, weights=weights, k=1),
                )
                win32evtlogutil.ReportEvent(
                    SOURCE_NAME,
                    eid,
                    eventType=etype,
                    strings=factory(),
                )
                ok += 1
            except pywintypes.error:
                err += 1

            if rate_limit and ok % batch_size == 0:
                elapsed = time.monotonic() - t0
                expected = ok / rate_limit
                if expected > elapsed:
                    time.sleep(expected - elapsed)

        stats.add(ok, err)
        work_queue.task_done()

    win32evtlog.CloseEventLog(handle)


# ---------------------------------------------------------------------------
# Progress reporter
# ---------------------------------------------------------------------------

def _report_progress(stats: Stats, total: Optional[int], stop: threading.Event) -> None:
    t0 = time.monotonic()
    last_n = 0
    while not stop.is_set():
        time.sleep(2)
        n = stats.written
        elapsed = time.monotonic() - t0
        rate = (n - last_n) / 2
        last_n = n
        pct = f"{100*n/total:.1f}% " if total else ""
        print(f"  {pct}{n:,} events  |  {rate:,.0f} ev/s  |  {stats.errors} errors",
              flush=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--count", "-n", type=int, default=50_000,
                   help="Total events to write (default: 50000). Ignored if --continuous.")
    p.add_argument("--continuous", action="store_true",
                   help="Run until Ctrl-C (ignores --count).")
    p.add_argument("--type", "-t",
                   choices=["security", "sysmon", "powershell", "mixed"],
                   default="security",
                   help="Event mix to generate (default: security).")
    p.add_argument("--channel", default="Application",
                   help="Target event log channel (default: Application). "
                        "Use 'System' as Administrator for system events.")
    p.add_argument("--workers", "-w", type=int, default=1,
                   help="Parallel writer threads (default: 1). "
                        "Increase to saturate pipeline.")
    p.add_argument("--rate", type=float, default=None,
                   help="Target events/s (per worker). Default: unlimited.")
    p.add_argument("--seed", type=int, default=None,
                   help="Random seed for reproducible output.")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print progress every 2 seconds.")
    return p


def main():
    args = build_parser().parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    event_set = _EVENT_SETS[args.type]
    ids, types, weights, factories = _build_weighted(event_set)

    print(f"Registering event source '{SOURCE_NAME}' in channel '{args.channel}' ...",
          flush=True)
    register_source(args.channel)

    try:
        if args.continuous:
            _run_continuous(args, ids, types, weights, factories)
        else:
            _run_fixed(args, ids, types, weights, factories)
    finally:
        unregister_source()


def _run_fixed(args, ids, types, weights, factories):
    stats = Stats()
    wq = queue.Queue()

    # Distribute work evenly across workers
    chunk = max(1, args.count // args.workers)
    remainder = args.count - chunk * args.workers
    for i in range(args.workers):
        wq.put(chunk + (1 if i < remainder else 0))

    stop_evt = threading.Event()
    if args.verbose:
        reporter = threading.Thread(
            target=_report_progress, args=(stats, args.count, stop_evt), daemon=True
        )
        reporter.start()

    rate_per_worker = (args.rate / args.workers) if args.rate else None
    threads = [
        threading.Thread(
            target=_writer_thread,
            args=(wq, args.channel, ids, types, weights, factories, stats, rate_per_worker),
            daemon=True,
        )
        for _ in range(args.workers)
    ]

    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    elapsed = time.monotonic() - t0
    stop_evt.set()

    print(f"\nDone.")
    print(f"  Written : {stats.written:,}  events")
    print(f"  Errors  : {stats.errors:,}  events")
    print(f"  Elapsed : {elapsed:.1f} s")
    print(f"  Rate    : {stats.written / elapsed:,.0f} events/s")
    print(f"\nElastic Agent should now be indexing events from '{args.channel}'.")


def _run_continuous(args, ids, types, weights, factories):
    stats = Stats()
    stop_evt = threading.Event()
    rate_per_worker = (args.rate / args.workers) if args.rate else None

    def worker():
        while not stop_evt.is_set():
            try:
                (eid,), (etype,), (factory,) = (
                    random.choices(ids,       weights=weights, k=1),
                    random.choices(types,     weights=weights, k=1),
                    random.choices(factories, weights=weights, k=1),
                )
                win32evtlogutil.ReportEvent(
                    SOURCE_NAME,
                    eid,
                    eventType=etype,
                    strings=factory(),
                )
                stats.add(1)
            except pywintypes.error:
                stats.add(0, 1)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(args.workers)]

    print(f"Writing continuously to '{args.channel}' with {args.workers} worker(s). "
          "Press Ctrl-C to stop.", flush=True)
    t0 = time.monotonic()
    for t in threads:
        t.start()

    reporter = threading.Thread(
        target=_report_progress, args=(stats, None, stop_evt), daemon=True
    )
    reporter.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set()

    elapsed = max(0.001, time.monotonic() - t0)
    print(f"\nStopped.")
    print(f"  Written : {stats.written:,}  events")
    print(f"  Errors  : {stats.errors:,}  events")
    print(f"  Elapsed : {elapsed:.1f} s")
    print(f"  Rate    : {stats.written / elapsed:,.0f} events/s")


if __name__ == "__main__":
    main()
