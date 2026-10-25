"""Rule data: extensions, file-name patterns and ransom-note text patterns.

These lists are heuristics, not an exhaustive database. Extend them freely.
"""

from __future__ import annotations

import re
from typing import List, Tuple

# Extensions whose content should be readable text (entropy should be low).
TEXT_EXTS = {
    ".txt", ".md", ".rst", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".log", ".html", ".htm", ".css", ".js", ".ts", ".py",
    ".java", ".c", ".h", ".cpp", ".hpp", ".cs", ".go", ".rs", ".rb", ".php", ".sh",
    ".bat", ".ps1", ".sql", ".rtf", ".tex", ".srt", ".svg", ".ipynb",
}

# Source/doc files are not scanned for ransom-note *text* (avoids false positives
# on security tooling, tutorials and READMEs).
SOURCE_EXTS = {
    ".py", ".js", ".ts", ".java", ".c", ".h", ".cpp", ".hpp", ".cs", ".go", ".rs",
    ".rb", ".php", ".md", ".rst", ".ipynb", ".tex",
}

# Unknown extensions that are legitimately high-entropy (containers, images, backups).
HIGH_ENTROPY_OK_EXTS = {
    ".bin", ".dat", ".pak", ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".qcow2",
    ".tar", ".bak", ".pyc", ".pyd", ".whl", ".pickle", ".pkl", ".npy", ".npz",
    ".parquet", ".onnx", ".pt", ".pth", ".safetensors", ".gguf", ".sqlite-wal",
    ".cab", ".dmg", ".deb", ".rpm", ".woff", ".woff2", ".lz4", ".br",
}

# Extensions appended by well-known ransomware families (from public reports).
KNOWN_RANSOM_EXTS = {
    ".locked", ".locky", ".lockbit", ".lockfile", ".encrypted", ".crypt", ".crypted",
    ".crypto", ".cryptolocker", ".cry", ".crinf", ".r5a", ".xrtn", ".ecc", ".ezz",
    ".exx", ".micro", ".gws", ".kraken", ".darkness", ".nochance", ".oshit",
    ".cerber", ".cerber2", ".cerber3", ".wncry", ".wnry", ".wcry", ".wncryt",
    ".petya", ".mira", ".zepto", ".odin", ".thor", ".aesir", ".osiris",
    ".dharma", ".wallet", ".arena", ".phobos", ".eking", ".eight", ".ryk", ".ryuk",
    ".conti", ".revil", ".sodinokibi", ".blackcat", ".royal", ".akira", ".hive",
    ".basta", ".clop", ".cl0p", ".maze", ".egregor", ".darkside", ".babuk",
    ".avaddon", ".ragnar", ".gandcrab", ".krab", ".stop", ".djvu", ".djvuu",
    ".tfude", ".uudjvu", ".nemty", ".zeppelin", ".globeimposter", ".thanos",
    ".pysa", ".medusa", ".blacksuit", ".rhysida", ".8base", ".qilin",
}

# "report.docx.xyz123": a normal document extension followed by an unknown one.
COMMON_INNER_EXTS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".csv",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".mov",
    ".odt", ".ods", ".sql", ".db", ".mdb", ".psd", ".rtf", ".zip", ".rar", ".7z",
}
BENIGN_OUTER_EXTS = {
    ".bak", ".old", ".orig", ".tmp", ".temp", ".swp", ".part", ".crdownload",
    ".download", ".gz", ".bz2", ".xz", ".zip", ".sig", ".asc", ".sha256", ".md5",
    ".map", ".erb", ".example", ".sample", ".template", ".in", ".j2", ".ejs",
    ".lnk", ".url", ".copy", ".backup", ".1", ".2", ".3",
}


def appended_extension(name: str) -> bool:
    parts = name.lower().split(".")
    if len(parts) < 3:
        return False
    outer = "." + parts[-1]
    has_doc_ext = any("." + p in COMMON_INNER_EXTS for p in parts[1:-1])
    return (has_doc_ext
            and outer not in COMMON_INNER_EXTS
            and outer not in BENIGN_OUTER_EXTS
            and 2 <= len(parts[-1]) <= 14)


_CONTACT_TAG = re.compile(r"\[[^\]\s]+@[^\]\s]+\]")          # file.[mail@x.com].ext
_ID_TAG = re.compile(r"\.id[-\[_]?[0-9a-f]{8}\b", re.IGNORECASE)  # file.id-1A2B3C4D.ext


def has_contact_tag(name: str) -> bool:
    return bool(_CONTACT_TAG.search(name) or _ID_TAG.search(name))


_NOTE_NAMES = [re.compile(p) for p in (
    r"how[ _\-]?to[ _\-]?(?:recover|restore|decrypt|get[ _\-]?back|unlock)",
    r"(?:decrypt|recover|restore|unlock)[ _\-]?(?:my|your|all)?[ _\-]?(?:files|data|instructions|info)",
    r"(?:read[ _\-]?me|readme|instructions?|help)[ _\-]?(?:to[ _\-]?)?(?:decrypt|recover|restore|unlock)",
    r"your[ _\-]?files[ _\-]?(?:are|have|were)?[ _\-]?(?:been[ _\-]?)?(?:encrypted|locked)",
    r"^@?please[ _\-]?read[ _\-]?me@?",
    r"wana[ _\-]?decrypt",
    r"ransom[ _\-]?note",
)]


def is_ransom_note_name(name: str) -> bool:
    low = name.lower()
    return any(p.search(low) for p in _NOTE_NAMES)


# (rule name, compiled regex, weight). Several distinct hits are needed to matter.
_I = re.IGNORECASE
_NOTE_PATTERNS: List[Tuple[str, "re.Pattern[str]", int]] = [
    ("claims_files_encrypted",
     re.compile(r"your\s+(?:\w+\s+){0,3}?(?:files|data|documents|photos|databases)\s+"
                r"(?:have\s+been|are|were|got)\s+(?:encrypted|locked)", _I), 25),
    ("decryptor_mention",
     re.compile(r"decrypt(?:ion|or)?\s+(?:key|tool|software|program|service)", _I), 15),
    ("crypto_payment_demand",
     re.compile(r"(?:pay|payment|send|transfer|buy).{0,60}?\b(?:bitcoins?|btc|monero|xmr|cryptocurrency)\b", _I), 20),
    ("onion_address", re.compile(r"\b[a-z2-7]{16,56}\.onion\b", _I), 25),
    ("tor_browser", re.compile(r"\btor\s+browser\b", _I), 10),
    ("recover_files_offer",
     re.compile(r"(?:recover|restore|get\s+back)\s+(?:all\s+)?(?:your|the)\s+(?:encrypted\s+)?(?:files|data)", _I), 15),
    ("deadline_threat",
     re.compile(r"(?:within|in|after)\s+\d+\s*(?:hours?|days?).{0,80}?"
                r"(?:price|double|increase|delete|destroy|lost|publish|leak)", _I), 15),
    ("do_not_touch_files",
     re.compile(r"do\s+not\s+(?:try\s+to\s+)?(?:rename|modify|change|delete|remove)\s+"
                r"(?:the\s+)?(?:encrypted\s+)?files", _I), 10),
    ("private_key_threat",
     re.compile(r"(?:private|secret)\s+key.{0,60}?(?:server|destroy|delete)", _I), 15),
    ("data_theft_threat",
     re.compile(r"(?:stolen|exfiltrated|downloaded)\s+(?:your\s+)?(?:data|files|documents)", _I), 15),
    ("bitcoin_address",
     re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"), 10),
]


def scan_text(text: str) -> List[Tuple[str, int]]:
    """Return (rule name, weight) for every ransom-note pattern found in text."""
    return [(name, weight) for name, rx, weight in _NOTE_PATTERNS if rx.search(text)]
