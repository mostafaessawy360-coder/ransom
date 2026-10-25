"""Command line interface: scan | monitor | file | demo."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional

from . import __version__, report, samples
from .analyzer import HIGH_RISK, SUSPICIOUS, Analyzer
from .monitor import Event, Monitor
from .scanner import DEFAULT_EXCLUDES, scan


def _common() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--threshold", type=int, default=30, help="score for SUSPICIOUS (default 30)")
    p.add_argument("--high-threshold", type=int, default=70, help="score for HIGH_RISK (default 70)")
    p.add_argument("--ignore-ext", nargs="*", default=[], metavar="EXT",
                   help="skip content checks for these extensions, e.g. .dat .bin")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    return p


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(
        prog="ransomware-detector",
        description="Detects encrypted/ransomed files by analysing file CONTENT.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", parents=[common], help="scan a folder or file once")
    s.add_argument("path")
    s.add_argument("--json", metavar="FILE", help="write full results as JSON")
    s.add_argument("--csv", metavar="FILE", help="write results as CSV")
    s.add_argument("--all", action="store_true", help="list clean files too")
    s.add_argument("--workers", type=int, default=4)
    s.add_argument("--exclude", nargs="*", default=[], help="extra folder names to skip")

    m = sub.add_parser("monitor", parents=[common], help="watch a folder in real time")
    m.add_argument("path")
    m.add_argument("--interval", type=float, default=2.0, help="seconds between checks")
    m.add_argument("--window", type=float, default=60.0, help="burst window in seconds")
    m.add_argument("--alert-files", type=int, default=5, help="flagged files per window to alert")
    m.add_argument("--mass-files", type=int, default=50, help="changed files per window to alert")
    m.add_argument("--log", default="alerts.log", help="alert log file ('' to disable)")

    f = sub.add_parser("file", parents=[common], help="explain the verdict for one file")
    f.add_argument("path")

    d = sub.add_parser("demo", parents=[common], help="create safe sample files and scan them")
    d.add_argument("--dir", default="demo_samples")
    return parser


def _analyzer(args) -> Analyzer:
    return Analyzer(args.threshold, args.high_threshold, args.ignore_ext)


def _cmd_scan(args) -> int:
    color = report.enable_color(args.no_color)
    if not Path(args.path).exists():
        print(f"error: {args.path} does not exist", file=sys.stderr)
        return 3

    def progress(n: int, _path: str) -> None:
        if n % 200 == 0 and sys.stderr.isatty():
            print(f"\r  scanned {n} files...", end="", file=sys.stderr)

    summary = scan(args.path, _analyzer(args), workers=args.workers,
                   exclude_dirs=DEFAULT_EXCLUDES | set(args.exclude),
                   keep_all=args.all or bool(args.csv), progress=progress)
    if sys.stderr.isatty():
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)
    print(report.format_summary(summary, show_all=args.all, color=color))
    if args.json:
        report.write_json(summary, args.json)
        print(f"JSON written to {args.json}")
    if args.csv:
        report.write_csv(summary.reports, args.csv)
        print(f"CSV written to {args.csv}")
    if summary.counts[HIGH_RISK] or summary.alerts:
        return 2
    return 1 if summary.counts[SUSPICIOUS] else 0


def _cmd_file(args) -> int:
    color = report.enable_color(args.no_color)
    r = _analyzer(args).analyze(args.path)
    print(report.format_file_report(r, color))
    return 2 if r.verdict == HIGH_RISK else 1 if r.verdict == SUSPICIOUS else 0


def _cmd_monitor(args) -> int:
    color = report.enable_color(args.no_color)
    if not Path(args.path).is_dir():
        print(f"error: {args.path} is not a folder", file=sys.stderr)
        return 3

    def show(event: Event) -> None:
        stamp = time.strftime("%H:%M:%S")
        verdict = HIGH_RISK if event.level == "ALERT" or (
            event.report and event.report.verdict == HIGH_RISK) else SUSPICIOUS
        print(report.paint(f"[{stamp}] {event.level}: {event.message}", verdict, color), flush=True)

    mon = Monitor(args.path, _analyzer(args), interval=args.interval, window=args.window,
                  alert_files=args.alert_files, mass_files=args.mass_files,
                  on_event=show, log_path=args.log or None)
    n = mon.prime()
    print(f"Monitoring {args.path} ({n} existing files). Press Ctrl+C to stop.")
    try:
        mon.run()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def _cmd_demo(args) -> int:
    clean, infected = samples.generate_samples(args.dir)
    print(f"Sample files created in {Path(args.dir).resolve()}\n")
    color = report.enable_color(args.no_color)
    analyzer = _analyzer(args)
    for label, folder in (("CLEAN folder (expect no detections)", clean),
                          ("INFECTED folder (expect detections)", infected)):
        print(f"=== {label} ===")
        print(report.format_summary(scan(str(folder), analyzer, workers=1), color=color))
        print()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return {"scan": _cmd_scan, "file": _cmd_file,
            "monitor": _cmd_monitor, "demo": _cmd_demo}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
