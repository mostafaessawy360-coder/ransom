"""Statistical helpers that look at the *bytes* of a file.

Encrypted data is statistically indistinguishable from random noise:
  * Shannon entropy is close to 8 bits/byte
  * every byte value appears about equally often (chi-square near 255)
Normal documents, source code and text are far below that.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Entropy in bits per byte, 0.0 (all identical) .. 8.0 (perfectly random)."""
    n = len(data)
    if n == 0:
        return 0.0
    log2 = math.log2
    return -sum((c / n) * log2(c / n) for c in Counter(data).values())


def chi_square(data: bytes) -> float:
    """Chi-square statistic against a uniform byte distribution (255 d.o.f.).

    Truly random data gives about 255 (std. dev. about 22.6).
    """
    n = len(data)
    if n == 0:
        return 0.0
    expected = n / 256
    counts = Counter(data)
    return sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(256))


def looks_uniform(data: bytes, low: float = 180.0, high: float = 340.0,
                  min_len: int = 4096) -> bool:
    """True if the byte histogram is statistically flat, like ciphertext."""
    if len(data) < min_len:
        return False
    return low <= chi_square(data) <= high


def is_text(data: bytes, threshold: float = 0.95) -> bool:
    """Heuristic: does this chunk decode into mostly printable characters?

    Handles UTF-8 (incl. Arabic, CJK, ...) and UTF-16 with a BOM. Random bytes
    decode into lots of invalid sequences and control characters, so they fail.
    """
    if not data:
        return True
    encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    text = data.decode(encoding, errors="replace")
    if not text:
        return True
    good = sum(1 for ch in text
               if ch != "�" and (ch.isprintable() or ch in "\t\n\r"))
    return good / len(text) >= threshold
