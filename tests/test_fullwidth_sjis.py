"""
Tests for the fullwidth Shift-JIS encoder (src/patcher/fullwidth_sjis.py).

Validates that ASCII English text is correctly encoded to the fullwidth
Shift-JIS byte sequences used by the game's font renderer.
"""

import pytest

from src.patcher.fullwidth_sjis import (
    ascii_to_fullwidth_sjis,
    fullwidth_byte_count,
    fullwidth_char_budget,
)


class TestAsciiToFullwidthSjis:
    """Tests for ascii_to_fullwidth_sjis()."""

    def test_uppercase_letters(self):
        """A-Z should map to fullwidth Ａ-Ｚ (0x8260-0x8279)."""
        result = ascii_to_fullwidth_sjis("A")
        assert result == b"\x82\x60"

        result = ascii_to_fullwidth_sjis("Z")
        assert result == b"\x82\x79"

    def test_lowercase_letters(self):
        """a-z should map to fullwidth ａ-ｚ (0x8281-0x829A)."""
        result = ascii_to_fullwidth_sjis("a")
        assert result == b"\x82\x81"

        result = ascii_to_fullwidth_sjis("z")
        assert result == b"\x82\x9A"

    def test_digits(self):
        """0-9 should map to fullwidth ０-９ (0x824F-0x8258)."""
        result = ascii_to_fullwidth_sjis("0")
        assert result == b"\x82\x4F"

        result = ascii_to_fullwidth_sjis("9")
        assert result == b"\x82\x58"

    def test_space(self):
        """Space should map to fullwidth space (0x8140)."""
        result = ascii_to_fullwidth_sjis(" ")
        assert result == b"\x81\x40"

    def test_item_encoding(self):
        """
        The exact case from the bug report:
        Original game bytes: 82 68 82 73 82 64 82 6C = ＩＴＥＭ
        We must produce exactly these bytes for 'ITEM'.
        """
        result = ascii_to_fullwidth_sjis("ITEM")
        assert result == b"\x82\x68\x82\x73\x82\x64\x82\x6C"

    def test_item_not_ascii(self):
        """Verify we do NOT produce ASCII bytes — that was the bug."""
        result = ascii_to_fullwidth_sjis("ITEM")
        # ASCII 'ITEM' would be 0x49 0x54 0x45 0x4D
        assert result != b"\x49\x54\x45\x4D"

    def test_punctuation(self):
        """Common punctuation should map to fullwidth equivalents."""
        result = ascii_to_fullwidth_sjis("!")
        assert result == b"\x81\x49"

        result = ascii_to_fullwidth_sjis("?")
        assert result == b"\x81\x48"

        result = ascii_to_fullwidth_sjis(".")
        assert result == b"\x81\x44"

        result = ascii_to_fullwidth_sjis(",")
        assert result == b"\x81\x43"

    def test_control_byte_null_passthrough(self):
        """Null terminator (0x00) should pass through as a single byte."""
        result = ascii_to_fullwidth_sjis("\x00")
        assert result == b"\x00"
        assert len(result) == 1

    def test_control_byte_newline_passthrough(self):
        """Newline (0x0A) should pass through as a single byte."""
        result = ascii_to_fullwidth_sjis("\x0A")
        assert result == b"\x0A"
        assert len(result) == 1

    def test_control_byte_vt_passthrough(self):
        """VT / wait-for-input (0x0B) should pass through as a single byte."""
        result = ascii_to_fullwidth_sjis("\x0B")
        assert result == b"\x0B"
        assert len(result) == 1

    def test_mixed_text_and_controls(self):
        """Text with embedded control codes should encode correctly."""
        # "Hi\nBye\x00" → Ｈ(2) + ｉ(2) + \n(1) + Ｂ(2) + ｙ(2) + ｅ(2) + \x00(1) = 12 bytes
        result = ascii_to_fullwidth_sjis("Hi\nBye\x00")
        expected = (
            b"\x82\x67"    # Ｈ
            b"\x82\x89"    # ｉ
            b"\x0A"        # newline (passthrough)
            b"\x82\x61"    # Ｂ
            b"\x82\x99"    # ｙ
            b"\x82\x85"    # ｅ
            b"\x00"        # null (passthrough)
        )
        assert result == expected

    def test_empty_string(self):
        """Empty string produces empty bytes."""
        assert ascii_to_fullwidth_sjis("") == b""

    def test_encoding_is_valid_cp932(self):
        """
        The fullwidth bytes we produce should be decodable as cp932,
        yielding the expected fullwidth Unicode characters.
        """
        result = ascii_to_fullwidth_sjis("ITEM")
        decoded = result.decode("cp932")
        assert decoded == "ＩＴＥＭ"

    def test_full_alphabet_roundtrip(self):
        """Every letter should roundtrip through cp932 to its fullwidth form."""
        import string
        for ch in string.ascii_uppercase:
            encoded = ascii_to_fullwidth_sjis(ch)
            decoded = encoded.decode("cp932")
            # The fullwidth form should be the Unicode fullwidth equivalent
            expected = chr(ord("Ａ") + ord(ch) - ord("A"))
            assert decoded == expected, f"Failed for '{ch}'"

        for ch in string.ascii_lowercase:
            encoded = ascii_to_fullwidth_sjis(ch)
            decoded = encoded.decode("cp932")
            expected = chr(ord("ａ") + ord(ch) - ord("a"))
            assert decoded == expected, f"Failed for '{ch}'"


class TestFullwidthByteCount:
    """Tests for fullwidth_byte_count()."""

    def test_all_printable(self):
        """Each printable char costs 2 bytes."""
        assert fullwidth_byte_count("ITEM") == 8  # 4 chars × 2 bytes
        assert fullwidth_byte_count("Hello World") == 22  # 11 chars × 2 bytes

    def test_with_controls(self):
        """Control bytes cost 1 byte each."""
        # "Hi\n" = H(2) + i(2) + \n(1) = 5
        assert fullwidth_byte_count("Hi\n") == 5

    def test_empty(self):
        assert fullwidth_byte_count("") == 0

    def test_only_controls(self):
        """Only control bytes = 1 byte each."""
        assert fullwidth_byte_count("\x00\x0A\x0B") == 3


class TestFullwidthCharBudget:
    """Tests for fullwidth_char_budget()."""

    def test_basic(self):
        """8 bytes should fit 4 fullwidth characters."""
        assert fullwidth_char_budget(8) == 4

    def test_with_controls(self):
        """Subtract control code bytes first, then divide by 2."""
        # 10 bytes, 2 control codes = 8 available / 2 = 4 chars
        assert fullwidth_char_budget(10, control_code_count=2) == 4

    def test_odd_remaining(self):
        """Odd remaining bytes should floor-divide."""
        # 9 bytes, 0 controls = 9 / 2 = 4 chars (floor)
        assert fullwidth_char_budget(9) == 4

    def test_zero_budget(self):
        assert fullwidth_char_budget(0) == 0

    def test_negative_clamps_to_zero(self):
        """If control codes exceed the budget, clamp to 0."""
        assert fullwidth_char_budget(2, control_code_count=5) == 0
