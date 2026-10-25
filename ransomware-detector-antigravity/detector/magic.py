"""File-type identification from the first bytes ("magic numbers").

A healthy .docx starts with the ZIP header, a healthy .jpg with FF D8 FF, and so
on. Ransomware that encrypts the whole file destroys that header, so a file whose
extension promises a format that its content does not have is a strong signal.
"""

from __future__ import annotations

from typing import Callable, Dict, FrozenSet, List, Optional, Tuple

_ZIP_EXTS = (".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jar",
             ".apk", ".epub", ".xpi", ".vsix", ".whl", ".nupkg")

Validator = Optional[Callable[[bytes], bool]]
# (type name, offset, magic bytes, extensions that normally carry this type, validator)
_Sig = Tuple[str, int, bytes, Tuple[str, ...], Validator]


def _bmp_ok(d: bytes) -> bool:
    return d[6:10] == b"\x00\x00\x00\x00"          # reserved fields are always 0


def _bz2_ok(d: bytes) -> bool:
    return d[3:4].isdigit() and d[3:4] != b"0"


_SIGS: List[_Sig] = [
    ("pdf", 0, b"%PDF-", (".pdf",), None),
    ("zip", 0, b"PK\x03\x04", _ZIP_EXTS, None),
    ("zip", 0, b"PK\x05\x06", _ZIP_EXTS, None),
    ("zip", 0, b"PK\x07\x08", _ZIP_EXTS, None),
    ("ole", 0, bytes.fromhex("D0CF11E0A1B11AE1"),
     (".doc", ".xls", ".ppt", ".msi", ".msg", ".vsd", ".pub"), None),
    ("png", 0, b"\x89PNG\r\n\x1a\n", (".png",), None),
    ("jpeg", 0, b"\xff\xd8\xff", (".jpg", ".jpeg", ".jpe", ".jfif"), None),
    ("gif", 0, b"GIF87a", (".gif",), None),
    ("gif", 0, b"GIF89a", (".gif",), None),
    ("7z", 0, b"7z\xbc\xaf\x27\x1c", (".7z",), None),
    ("rar", 0, b"Rar!\x1a\x07", (".rar",), None),
    ("gzip", 0, b"\x1f\x8b\x08", (".gz", ".tgz", ".svgz"), None),
    ("bzip2", 0, b"BZh", (".bz2", ".tbz2"), _bz2_ok),
    ("xz", 0, b"\xfd7zXZ\x00", (".xz", ".txz"), None),
    ("zstd", 0, b"\x28\xb5\x2f\xfd", (".zst",), None),
    ("mp3", 0, b"ID3", (".mp3",), None),
    ("mp3", 0, b"\xff\xfb", (".mp3",), None),
    ("mp3", 0, b"\xff\xf3", (".mp3",), None),
    ("mp3", 0, b"\xff\xf2", (".mp3",), None),
    ("mp3", 0, b"\xff\xfa", (".mp3",), None),
    ("mp4", 4, b"ftyp", (".mp4", ".m4a", ".m4v", ".mov", ".3gp", ".heic", ".heif", ".avif"), None),
    ("riff", 0, b"RIFF", (".wav", ".avi", ".webp"), None),
    ("sqlite", 0, b"SQLite format 3\x00", (".db", ".sqlite", ".sqlite3", ".db3"), None),
    ("bmp", 0, b"BM", (".bmp",), _bmp_ok),
    ("exe", 0, b"MZ", (".exe", ".dll", ".sys", ".scr", ".ocx"), None),
    ("elf", 0, b"\x7fELF", (".so", ".elf"), None),
    ("tiff", 0, b"II*\x00", (".tif", ".tiff"), None),
    ("tiff", 0, b"MM\x00*", (".tif", ".tiff"), None),
    ("ogg", 0, b"OggS", (".ogg", ".oga", ".ogv", ".opus"), None),
    ("matroska", 0, b"\x1a\x45\xdf\xa3", (".mkv", ".webm", ".mka"), None),
    ("flac", 0, b"fLaC", (".flac",), None),
    ("asf", 0, bytes.fromhex("3026B2758E66CF11"), (".wma", ".wmv", ".asf"), None),
    ("flv", 0, b"FLV\x01", (".flv",), None),
    ("psd", 0, b"8BPS", (".psd",), None),
    ("ico", 0, b"\x00\x00\x01\x00", (".ico",), None),
    ("woff", 0, b"wOFF", (".woff", ".woff2"), None),
    ("woff", 0, b"wOF2", (".woff", ".woff2"), None),
]

ZIP_FAMILY = frozenset(_ZIP_EXTS)

_EXT_TYPES: Dict[str, set] = {}
for _type, _off, _magic, _exts, _val in _SIGS:
    for _e in _exts:
        _EXT_TYPES.setdefault(_e, set()).add(_type)


def identify(data: bytes) -> Optional[str]:
    """Return the detected file type name, or None if no signature matches."""
    for ftype, offset, magic, _exts, validator in _SIGS:
        if data[offset:offset + len(magic)] == magic and (validator is None or validator(data)):
            return ftype
    return None


def expected_types(ext: str) -> FrozenSet[str]:
    """File types an extension normally carries (empty set = we have no opinion)."""
    return frozenset(_EXT_TYPES.get(ext.lower(), ()))
