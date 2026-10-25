"""Safe test data generator.

Nothing here is malware. "Encrypted" files are simply random bytes (os.urandom)
written under document-like names, which is exactly what real ciphertext looks
like to a content-based detector. Ransom notes are harmless text files.
"""

from __future__ import annotations

import os
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Tuple

NOTE = (
    "ATTENTION!\n\n"
    "Your files have been encrypted and cannot be opened.\n"
    "To get the decryption key you must pay 0.5 bitcoin within 72 hours,\n"
    "otherwise the price will double and your data will be lost.\n"
    "Download Tor Browser and visit abcdefghijklmnop.onion to recover your files.\n"
    "Do not rename or modify the encrypted files.\n\n"
    "(This is a harmless sample file created for testing the detector.)\n"
)

LOREM = ("The quarterly report shows steady growth across all regions. "
         "Customer satisfaction improved and support tickets dropped. ") * 200


def _png(width: int = 96, height: int = 96) -> bytes:
    raw = b"".join(b"\x00" + os.urandom(width * 3) for _ in range(height))

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


def generate_samples(dest) -> Tuple[Path, Path]:
    """Create dest/clean and dest/infected. Returns both paths."""
    dest = Path(dest)
    clean, infected = dest / "clean", dest / "infected"
    (infected / "archive").mkdir(parents=True, exist_ok=True)
    clean.mkdir(parents=True, exist_ok=True)

    # ---- legitimate files (some are high-entropy but have valid headers) ----
    (clean / "notes.txt").write_text(LOREM, encoding="utf-8")
    (clean / "arabic.txt").write_text("مرحبا بالعالم، هذا ملف نصي عادي. " * 300, encoding="utf-8")
    (clean / "data.csv").write_text("id,name,score\n" + "".join(f"{i},user{i},{i*3}\n" for i in range(800)))
    (clean / "script.py").write_text("print('hello')\n" * 400)
    (clean / "image.png").write_bytes(_png())
    (clean / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + os.urandom(20000) + b"\xff\xd9")
    with zipfile.ZipFile(clean / "report.docx", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document>" + LOREM + "</w:document>")
    with zipfile.ZipFile(clean / "backup.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("random.bin", os.urandom(30000))

    # ---- simulated ransomware victims ----
    (infected / "contract.docx").write_bytes(os.urandom(30000))            # header destroyed
    (infected / "budget.xlsx.locked").write_bytes(os.urandom(25000))       # appended extension
    (infected / "meeting_notes.txt").write_bytes(os.urandom(20000))        # text file, now noise
    (infected / "partial.txt").write_bytes(LOREM.encode()[:16384].ljust(16384) + os.urandom(32768))
    (infected / "holiday.jpg.id-1A2B3C4D.[helper@example.com].crypt").write_bytes(os.urandom(40000))
    (infected / "HOW_TO_RECOVER_FILES.txt").write_text(NOTE, encoding="utf-8")
    (infected / "archive" / "HOW_TO_RECOVER_FILES.txt").write_text(NOTE, encoding="utf-8")
    for i in range(1, 7):
        (infected / "archive" / f"document_{i}.lockbit").write_bytes(os.urandom(18000))
    return clean, infected


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "demo_samples"
    c, i = generate_samples(target)
    print(f"Created {c} and {i}")
