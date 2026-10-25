"""Per-file analysis: combines content statistics, file type and name rules into a score."""

from __future__ import annotations

import stat
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

from . import entropy, magic, signatures

CHUNK = 16 * 1024            # bytes per sampled block (head / middle / tail)
MIN_ENTROPY_SIZE = 512       # blocks smaller than this are too short for entropy
ENTROPY_HIGH = 7.2           # bits/byte; text ~4-5.5, ciphertext ~7.9+
NOTE_SCAN_LIMIT = 256 * 1024
NOTE_MAX_FILE = 2 * 1024 * 1024

CLEAN, SUSPICIOUS, HIGH_RISK = "CLEAN", "SUSPICIOUS", "HIGH_RISK"


@dataclass
class Finding:
    rule: str
    points: int
    detail: str


@dataclass
class FileReport:
    path: str
    size: int = 0
    score: int = 0
    verdict: str = CLEAN
    detected_type: Optional[str] = None
    entropy_mean: float = 0.0
    entropy_max: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def has_rule(self, *rules: str) -> bool:
        return any(f.rule in rules for f in self.findings)


def _read_chunks(path: Path, size: int) -> List[bytes]:
    """Read up to three blocks: the whole file if small, else head/middle/tail."""
    with open(path, "rb") as f:
        if size <= 3 * CHUNK:
            data = f.read()
            return [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)]
        chunks = [f.read(CHUNK)]
        f.seek((size - CHUNK) // 2)
        chunks.append(f.read(CHUNK))
        f.seek(size - CHUNK)
        chunks.append(f.read(CHUNK))
        return chunks


def _read_text(path: Path, limit: int = NOTE_SCAN_LIMIT) -> str:
    with open(path, "rb") as f:
        raw = f.read(limit)
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


class Analyzer:
    """Scores a file from 0 to 100. Verdict thresholds are configurable."""

    def __init__(self, suspicious_threshold: int = 30, high_risk_threshold: int = 70,
                 ignore_exts: Iterable[str] = ()):
        self.suspicious_threshold = suspicious_threshold
        self.high_risk_threshold = high_risk_threshold
        self.ignore_exts = {
            (e.lower() if e.startswith(".") else "." + e.lower()) for e in ignore_exts
        }

    # ------------------------------------------------------------------ public
    def analyze(self, path) -> FileReport:
        p = Path(path)
        report = FileReport(path=str(p))
        try:
            st = p.stat()
            if not stat.S_ISREG(st.st_mode):
                report.error = "not a regular file"
                return report
            report.size = st.st_size
            if st.st_size == 0:
                return report
            chunks = _read_chunks(p, st.st_size)
        except OSError as exc:
            report.error = str(exc)
            return report

        ext = p.suffix.lower()
        findings: List[Finding] = []
        self._name_rules(p.name, ext, findings)

        report.detected_type = magic.identify(chunks[0])
        stats = [(entropy.shannon_entropy(c) if len(c) >= MIN_ENTROPY_SIZE else None,
                  entropy.is_text(c), c) for c in chunks]
        measured = [(e, t, c) for e, t, c in stats if e is not None]
        if measured:
            values = [e for e, _, _ in measured]
            report.entropy_mean = round(sum(values) / len(values), 3)
            report.entropy_max = round(max(values), 3)

        self._note_rules(p, ext, st.st_size, chunks[0], findings)
        if ext not in self.ignore_exts:
            self._content_rules(p, ext, report.detected_type, measured, findings)

        report.findings = findings
        report.score = min(100, sum(f.points for f in findings))
        if report.score >= self.high_risk_threshold:
            report.verdict = HIGH_RISK
        elif report.score >= self.suspicious_threshold:
            report.verdict = SUSPICIOUS
        return report

    # ------------------------------------------------------------------- rules
    @staticmethod
    def _name_rules(name: str, ext: str, out: List[Finding]) -> None:
        if signatures.is_ransom_note_name(name):
            out.append(Finding("ransom_note_filename", 30,
                               "file name looks like a ransom/recovery note"))
        if ext in signatures.KNOWN_RANSOM_EXTS:
            out.append(Finding("known_ransomware_extension", 35,
                               f"extension {ext} is used by known ransomware"))
        if signatures.appended_extension(name):
            out.append(Finding("appended_extension", 20,
                               "document extension followed by an extra unknown extension"))
        if signatures.has_contact_tag(name):
            out.append(Finding("contact_tag_in_name", 25,
                               "file name contains an e-mail or victim-ID tag"))

    @staticmethod
    def _note_rules(p: Path, ext: str, size: int, head: bytes, out: List[Finding]) -> None:
        if ext in signatures.SOURCE_EXTS or size > NOTE_MAX_FILE or not entropy.is_text(head):
            return
        try:
            hits = signatures.scan_text(_read_text(p))
        except OSError:
            return
        if hits:
            points = min(sum(w for _, w in hits), 70)
            out.append(Finding("ransom_note_content", points,
                               "text matches: " + ", ".join(n for n, _ in hits)))

    @staticmethod
    def _content_rules(p: Path, ext: str, detected: Optional[str], measured, out: List[Finding]) -> None:
        expected = magic.expected_types(ext)

        # A recognised format that is the wrong one for the extension.
        if detected and expected and detected not in expected:
            out.append(Finding("type_mismatch", 15,
                               f"content is '{detected}' but extension is {ext}"))

        # Zip-based formats whose structure at the end of the file is broken.
        if (detected == "zip" and ext in magic.ZIP_FAMILY and ext != ".jar"
                and not zipfile.is_zipfile(p)):
            out.append(Finding("corrupt_container", 30,
                               f"{ext} starts like a zip but its directory is damaged"))

        if not measured:
            return
        high_binary = [(e, t, c) for e, t, c in measured if e >= ENTROPY_HIGH and not t]
        if not high_binary or detected:      # a valid header means normal compressed data
            return
        all_high = len(high_binary) == len(measured)

        if ext in signatures.TEXT_EXTS:
            if all_high:
                out.append(Finding("encrypted_text_file", 65,
                                   f"{ext} file contains random-looking bytes, not text"))
            else:
                out.append(Finding("partially_encrypted", 40,
                                   f"{len(high_binary)} of {len(measured)} sampled blocks "
                                   f"are random while the rest is text"))
        elif expected:
            out.append(Finding("header_destroyed_high_entropy", 60,
                               f"no valid {ext} header and content looks encrypted"))
        elif ext in signatures.HIGH_ENTROPY_OK_EXTS:
            return
        else:
            out.append(Finding("high_entropy_unknown_type", 25,
                               "unrecognised format with random-looking content"))

        if entropy.looks_uniform(b"".join(c for _, _, c in high_binary)):
            out.append(Finding("uniform_byte_distribution", 10,
                               "byte histogram is flat, as with ciphertext"))
