"""Real-time monitor: polls a folder, analyses new/changed files, alerts on bursts.

Polling keeps the project dependency-free and identical on Windows, macOS and Linux.
"""

from __future__ import annotations

import os
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple

from .analyzer import CLEAN, Analyzer, FileReport
from .scanner import DEFAULT_EXCLUDES


@dataclass
class Event:
    level: str                       # "WARN" for one file, "ALERT" for a burst
    message: str
    report: Optional[FileReport] = None


class Monitor:
    def __init__(self, root: str, analyzer: Optional[Analyzer] = None, interval: float = 2.0,
                 window: float = 60.0, alert_files: int = 5, mass_files: int = 50,
                 exclude_dirs: Iterable[str] = DEFAULT_EXCLUDES,
                 on_event: Optional[Callable[[Event], None]] = None,
                 log_path: Optional[str] = None):
        self.root = root
        self.analyzer = analyzer or Analyzer()
        self.interval = interval
        self.window = window
        self.alert_files = alert_files      # flagged files inside the window -> ALERT
        self.mass_files = mass_files        # any changed files inside the window -> ALERT
        self.exclude_dirs = set(exclude_dirs)
        self.on_event = on_event
        self.log_path = log_path
        self._state: Dict[str, Tuple[int, int]] = {}
        self._flagged: Deque[float] = deque()
        self._changed: Deque[float] = deque()
        self._last_alert = 0.0
        self._last_mass = 0.0

    # --------------------------------------------------------------- internals
    def _snapshot(self) -> Dict[str, Tuple[int, int]]:
        snap: Dict[str, Tuple[int, int]] = {}
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in self.exclude_dirs]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                snap[path] = (st.st_mtime_ns, st.st_size)
        return snap

    def _emit(self, event: Event) -> None:
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.now().isoformat(timespec='seconds')} "
                            f"{event.level} {event.message}\n")
            except OSError:
                pass
        if self.on_event:
            self.on_event(event)

    @staticmethod
    def _prune(q: Deque[float], now: float, window: float) -> None:
        while q and now - q[0] > window:
            q.popleft()

    # ------------------------------------------------------------------ public
    def prime(self) -> int:
        """Record the current state as the baseline (existing files are not analysed)."""
        self._state = self._snapshot()
        return len(self._state)

    def poll_once(self, now: Optional[float] = None) -> List[Event]:
        now = time.time() if now is None else now
        current = self._snapshot()
        changed = [p for p, sig in current.items() if self._state.get(p) != sig]
        self._state = current

        events: List[Event] = []
        for path in changed:
            report = self.analyzer.analyze(path)
            if report.error:
                continue
            self._changed.append(now)
            if report.verdict != CLEAN:
                self._flagged.append(now)
                rules = ", ".join(f.rule for f in report.findings)
                events.append(Event("WARN", f"{report.verdict} score={report.score} "
                                            f"{path} [{rules}]", report))

        self._prune(self._flagged, now, self.window)
        self._prune(self._changed, now, self.window)

        if len(self._flagged) >= self.alert_files and now - self._last_alert > self.window:
            self._last_alert = now
            events.append(Event("ALERT", f"{len(self._flagged)} suspicious files in "
                                         f"{int(self.window)}s - possible ransomware activity "
                                         f"under {self.root}"))
        if len(self._changed) >= self.mass_files and now - self._last_mass > self.window:
            self._last_mass = now
            events.append(Event("ALERT", f"{len(self._changed)} files changed in "
                                         f"{int(self.window)}s - unusually high write activity"))
        for event in events:
            self._emit(event)
        return events

    def run(self, should_stop: Callable[[], bool] = lambda: False) -> None:
        self.prime()
        while not should_stop():
            time.sleep(self.interval)
            self.poll_once()
