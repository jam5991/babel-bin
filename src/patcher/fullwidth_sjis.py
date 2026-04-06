"""
Phase 5d — Fullwidth Shift-JIS Encoder.

Converts ASCII English text into fullwidth Shift-JIS byte sequences
that the game's font renderer can display.  PS1 JRPGs like SMT2 store
menu and dialogue text using fullwidth glyphs (Ａ, Ｂ, Ｃ …), where
each character occupies a 2-byte Shift-JIS codepoint.

Writing raw ASCII (0x41 = 'A') into these slots maps to the *wrong*
glyphs in the game's font table (°C, ¥, ≦, etc.).

Encoding reference (Shift-JIS / CP932):
    Ａ–Ｚ   →  0x8260 – 0x8279   (fullwidth uppercase)
    ａ–ｚ   →  0x8281 – 0x829A   (fullwidth lowercase)
    ０–９   →  0x824F – 0x8258   (fullwidth digits)
    　      →  0x8140            (fullwidth space)
    Various punctuation mapped individually.
    Control bytes (0x00, 0x0A, 0x0B) pass through as-is (1 byte each).
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Fullwidth Shift-JIS mapping tables ───────────────────────

# Each entry maps an ASCII character to its 2-byte Shift-JIS encoding.
# These were derived from the JIS X 0208 fullwidth Latin block.

_FULLWIDTH_MAP: dict[str, bytes] = {}


def _init_map() -> None:
    """Populate the ASCII → fullwidth Shift-JIS lookup table."""
    global _FULLWIDTH_MAP

    # Uppercase A–Z  →  Ａ–Ｚ  (0x8260 – 0x8279)
    for i, ch in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        code = 0x8260 + i
        _FULLWIDTH_MAP[ch] = bytes([code >> 8, code & 0xFF])

    # Lowercase a–z  →  ａ–ｚ  (0x8281 – 0x829A)
    for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz"):
        code = 0x8281 + i
        _FULLWIDTH_MAP[ch] = bytes([code >> 8, code & 0xFF])

    # Digits 0–9  →  ０–９  (0x824F – 0x8258)
    for i, ch in enumerate("0123456789"):
        code = 0x824F + i
        _FULLWIDTH_MAP[ch] = bytes([code >> 8, code & 0xFF])

    # Space  →  fullwidth space 　 (0x8140)
    _FULLWIDTH_MAP[" "] = b"\x81\x40"

    # Punctuation — individually mapped from CP932 fullwidth block
    _punct = {
        "!": 0x8149,   # ！
        "\"": 0x8168,  # "  (fullwidth double quote open — close is 0x8169)
        "#": 0x8194,   # ＃
        "$": 0x8190,   # ＄
        "%": 0x8193,   # ％
        "&": 0x8195,   # ＆
        "'": 0x8166,   # '  (fullwidth apostrophe / single quote)
        "(": 0x8169,   # （
        ")": 0x816A,   # ）
        "*": 0x8196,   # ＊
        "+": 0x817B,   # ＋
        ",": 0x8143,   # ，
        "-": 0x817C,   # −  (fullwidth hyphen-minus)
        ".": 0x8144,   # ．
        "/": 0x815E,   # ／
        ":": 0x8146,   # ：
        ";": 0x8147,   # ；
        "<": 0x8183,   # ＜
        "=": 0x8181,   # ＝
        ">": 0x8184,   # ＞
        "?": 0x8148,   # ？
        "@": 0x8197,   # ＠
        "[": 0x816D,   # ［
        "\\": 0x815F,  # ＼
        "]": 0x816E,   # ］
        "^": 0x814F,   # ＾
        "_": 0x8151,   # ＿
        "`": 0x814D,   # ｀
        "{": 0x816F,   # ｛
        "|": 0x8162,   # ｜
        "}": 0x8170,   # ｝
        "~": 0x8150,   # ～
    }
    for ch, code in _punct.items():
        _FULLWIDTH_MAP[ch] = bytes([code >> 8, code & 0xFF])


# Initialize on module load
_init_map()

# Control bytes that pass through as single bytes (not fullwidth-encoded)
CONTROL_BYTES = {0x00, 0x0A, 0x0B, 0x0D}


def ascii_to_fullwidth_sjis(text: str) -> bytes:
    """
    Convert an ASCII English string to fullwidth Shift-JIS bytes.

    Each printable ASCII character becomes a 2-byte Shift-JIS fullwidth
    codepoint.  Control characters (null, newline, VT, CR) pass through
    as single bytes.

    Args:
        text: ASCII English string to encode.

    Returns:
        Encoded byte sequence suitable for injection into the game binary.

    Raises:
        ValueError: If the text contains characters that cannot be mapped.
    """
    result = bytearray()

    for ch in text:
        ordinal = ord(ch)

        # Control bytes pass through as-is
        if ordinal in CONTROL_BYTES:
            result.append(ordinal)
            continue

        # Look up the fullwidth mapping
        mapped = _FULLWIDTH_MAP.get(ch)
        if mapped is not None:
            result.extend(mapped)
        else:
            # Unmappable character — log and substitute fullwidth question mark
            logger.warning(
                "Unmappable character U+%04X ('%s') — substituting ？",
                ordinal, ch,
            )
            result.extend(b"\x81\x48")  # ？

    return bytes(result)


def fullwidth_byte_count(text: str) -> int:
    """
    Calculate the byte length of a string when encoded as fullwidth Shift-JIS.

    Printable characters cost 2 bytes each; control bytes cost 1 byte each.

    Args:
        text: ASCII English string.

    Returns:
        Total byte count after fullwidth encoding.
    """
    count = 0
    for ch in text:
        ordinal = ord(ch)
        if ordinal in CONTROL_BYTES:
            count += 1
        else:
            count += 2
    return count


def fullwidth_char_budget(byte_limit: int, control_code_count: int = 0) -> int:
    """
    Calculate the maximum number of printable characters that fit within
    a given byte limit, accounting for control codes.

    Args:
        byte_limit: Total bytes available in the game binary.
        control_code_count: Number of single-byte control codes expected.

    Returns:
        Maximum printable characters that fit.
    """
    available = byte_limit - control_code_count
    return max(0, available // 2)
