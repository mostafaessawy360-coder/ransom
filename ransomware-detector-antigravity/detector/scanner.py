"""Directory scanner: runs the Analyzer over a tree and looks for campaign-level patterns."""

from __future__ import annotations

import os
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional

from .analyzer import CLEAN, HIGH_RISK, SUSPICIOUS, Analyzer, FileReport

DEFAULT_EXCLUDES = {".git", "node_modules", "__pycache__", ".venv", "venv",
                    "$RECYCLE.BIN", "System Volume Information"}


@dataclass
class ScanSummary:
    root: str
    files_scanned: int = 0
    files_errored: int = 0
    counts: Dict[str, int] = field(default_factory=lambda: {CLEAN: 0, SUSPICIOUS: 0, HIGH_RISK: 0})
    alerts: List[str] = field(default_factory=list)
    elapsed: float = 0.0
    reports: List[FileReport] = field(default_factory=list)   # flagged files (or all)

    @property
    def flagged(self) -> List[FileReport]:
        return [r for r in self.reports if r.verdict != CLEAN]

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_errored": self.files_errored,
            "counts": self.counts,
            "alerts": self.alerts,
            "elapsed_seconds": round(self.elapsed, 2),
            "reports": [r.to_dict() for r in self.reports],
        }


def iter_files(root: str, exclude_dirs: Iterable[str] = DEFAULT_EXCLUDES) -> Iterator[str]:
    exclude = set(exclude_dirs)
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in exclude]
        for name in filenames:
            yield os.path.join(dirpath, name)


def _batches(it: Iterator[str], size: int) -> Iterator[List[str]]:
    batch: List[str] = []
    for item in it:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def scan(root: str, analyzer: Optional[Analyzer] = None, workers: int = 4,
         exclude_dirs: Iterable[str] = DEFAULT_EXCLUDES, keep_all: bool = False,
         progress: Optional[Callable[[int, str], None]] = None) -> ScanSummary:
    analyzer = analyzer or Analyzer()
    summary = ScanSummary(root=str(root))
    started = time.time()
    pool = ThreadPoolExecutor(max_workers=workers) if workers > 1 else None

    try:
        for batch in _batches(iter_files(str(root), exclude_dirs), 500):
            results = pool.map(analyzer.analyze, batch) if pool else map(analyzer.analyze, batch)
            for report in results:
                summary.files_scanned += 1
                if report.error:
                    summary.files_errored += 1
                    continue
                summary.counts[report.verdict] += 1
                if keep_all or report.verdict != CLEAN:
                    summary.reports.append(report)
                if progress:
                    progress(summary.files_scanned, report.path)
    finally:
        if pool:
            pool.shutdown()

    summary.reports.sort(key=lambda r: r.score, reverse=True)
    summary.alerts = correlate(summary)
    summary.elapsed = time.time() - started
    return summary


def correlate(summary: ScanSummary) -> List[str]:
    """Campaign-level signals that one file alone cannot show."""
    alerts: List[str] = []
    flagged = summary.flagged
    if not flagged:
        return alerts

    content_rules = ("encrypted_text_file", "header_destroyed_high_entropy",
                     "high_entropy_unknown_type", "partially_encrypted")
    ext_counts = Counter(Path(r.path).suffix.lower() for r in flagged
                         if r.has_rule(*content_rules, "known_ransomware_extension"))
    for ext, n in ext_counts.most_common(3):
        if ext and n >= 5:
            alerts.append(f"{n} files with extension '{ext}' look encrypted "
                          f"(possible mass encryption)")

    note_dirs = {str(Path(r.path).parent) for r in flagged
                 if r.has_rule("ransom_note_filename", "ransom_note_content")}
    if len(note_dirs) >= 2:
        alerts.append(f"ransom-note-like files found in {len(note_dirs)} different folders")

    scanned = max(summary.files_scanned - summary.files_errored, 1)
    if len(flagged) >= 10 and len(flagged) / scanned >= 0.3:
        alerts.append(f"{len(flagged)} of {scanned} files "
                      f"({100 * len(flagged) // scanned}%) were flagged")
    return alerts
