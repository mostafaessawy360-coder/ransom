"""Console, JSON and CSV output."""

from __future__ import annotations

import csv
import json
import os
from typing import Iterable

from .analyzer import CLEAN, HIGH_RISK, SUSPICIOUS, FileReport
from .scanner import ScanSummary

_COLORS = {HIGH_RISK: "\033[91m", SUSPICIOUS: "\033[93m", CLEAN: "\033[92m"}
_RESET = "\033[0m"


def enable_color(force_off: bool = False) -> bool:
    """Colour only on a real terminal; also switches on ANSI support in old Windows consoles."""
    import sys
    if force_off or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")
    return True


def paint(text: str, verdict: str, color: bool) -> str:
    return f"{_COLORS[verdict]}{text}{_RESET}" if color else text


def format_file_report(r: FileReport, color: bool = False) -> str:
    lines = [f"{paint(r.verdict, r.verdict, color)}  score {r.score}/100  {r.path}",
             f"    size={r.size} bytes  type={r.detected_type or 'unknown'}  "
             f"entropy mean={r.entropy_mean} max={r.entropy_max}"]
    if r.error:
        lines.append(f"    error: {r.error}")
    for f in r.findings:
        lines.append(f"    +{f.points:<3} {f.rule}: {f.detail}")
    return "\n".join(lines)


def format_summary(summary: ScanSummary, show_all: bool = False, color: bool = False) -> str:
    out = []
    shown = summary.reports if show_all else summary.flagged
    for r in shown:
        rules = ", ".join(f.rule for f in r.findings) or "-"
        out.append(f"{paint(f'{r.verdict:<10}', r.verdict, color)} {r.score:>3}  {r.path}\n"
                   f"{'':15}{rules}")
    if summary.alerts:
        out.append("")
        for a in summary.alerts:
            out.append(paint(f"!! CAMPAIGN ALERT: {a}", HIGH_RISK, color))
    c = summary.counts
    out.append("")
    out.append(f"Scanned {summary.files_scanned} files in {summary.elapsed:.2f}s "
               f"({summary.files_errored} unreadable)")
    out.append(f"  {paint('HIGH_RISK', HIGH_RISK, color)}: {c[HIGH_RISK]}   "
               f"{paint('SUSPICIOUS', SUSPICIOUS, color)}: {c[SUSPICIOUS]}   "
               f"{paint('CLEAN', CLEAN, color)}: {c[CLEAN]}")
    return "\n".join(out)


def write_json(summary: ScanSummary, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary.to_dict(), f, indent=2, ensure_ascii=False)


def write_csv(reports: Iterable[FileReport], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["path", "verdict", "score", "size", "detected_type",
                    "entropy_mean", "entropy_max", "rules"])
        for r in reports:
            w.writerow([r.path, r.verdict, r.score, r.size, r.detected_type or "",
                        r.entropy_mean, r.entropy_max, ";".join(f.rule for f in r.findings)])
