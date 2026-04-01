"""
Phase 2a — Shannon Entropy Calculator & Shift-JIS Text Detection.

Scans raw binary data using a sliding-window entropy analysis to classify
regions as plaintext, structured data, or compressed/encrypted blocks.
Also detects Shift-JIS encoded text clusters for translation targeting.

Reference:
    Lyda, R., & Hamrock, J. (2007). "Using Entropy Analysis to Find
    Encrypted and Packed Malware." IEEE Security & Privacy, 5(2), 40-45.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class RegionType(Enum):
    """Classification of a binary region by entropy."""
    PLAINTEXT = "plaintext"
    STRUCTURED = "structured"
    COMPRESSED = "compressed"


@dataclass
class EntropyRegion:
    """A contiguous region with a measured entropy value."""
    offset: int
    length: int
    entropy: float
    region_type: RegionType


@dataclass
class TextRegion:
    """A detected Shift-JIS text cluster in the binary."""
    offset: int
    length: int
    encoding: str
    confidence: float
    decoded_preview: str     # First N characters of decoded text


def shannon_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy (bits per byte) for a block of data.

    Returns a value between 0.0 (all identical bytes) and 8.0 (perfectly random).
    """
    if not data:
        return 0.0

    length = len(data)
    freq = [0] * 256

    for byte in data:
        freq[byte] += 1

    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def scan_entropy(
    data: bytes,
    window_size: int = 256,
    step_size: int = 64,
    compressed_threshold: float = 7.0,
    structured_threshold: float = 4.0,
) -> list[EntropyRegion]:
    """
    Perform sliding-window entropy analysis over binary data.

    Args:
        data: Raw binary content to scan.
        window_size: Size of the sliding window in bytes.
        step_size: Step between consecutive windows.
        compressed_threshold: Entropy above this → compressed/encrypted.
        structured_threshold: Entropy between this and compressed → structured.

    Returns:
        List of EntropyRegion objects, one per window.
    """
    regions: list[EntropyRegion] = []
    data_len = len(data)

    for offset in range(0, data_len - window_size + 1, step_size):
        window = data[offset:offset + window_size]
        entropy = shannon_entropy(window)

        if entropy >= compressed_threshold:
            rtype = RegionType.COMPRESSED
        elif entropy >= structured_threshold:
            rtype = RegionType.STRUCTURED
        else:
            rtype = RegionType.PLAINTEXT

        regions.append(EntropyRegion(
            offset=offset,
            length=window_size,
            entropy=entropy,
            region_type=rtype,
        ))

    logger.info(
        "Entropy scan: %d windows | %d compressed | %d structured | %d plaintext",
        len(regions),
        sum(1 for r in regions if r.region_type == RegionType.COMPRESSED),
        sum(1 for r in regions if r.region_type == RegionType.STRUCTURED),
        sum(1 for r in regions if r.region_type == RegionType.PLAINTEXT),
    )

    return regions


# ── Shift-JIS Detection ─────────────────────────────────────

def _is_sjis_lead_byte(b: int) -> bool:
    """Check if a byte is a valid Shift-JIS lead (first) byte."""
    return (0x81 <= b <= 0x9F) or (0xE0 <= b <= 0xEF)


def _is_sjis_trail_byte(b: int) -> bool:
    """Check if a byte is a valid Shift-JIS trail (second) byte."""
    return (0x40 <= b <= 0x7E) or (0x80 <= b <= 0xFC)


def find_sjis_clusters(
    data: bytes,
    min_cluster_size: int = 8,
) -> list[TextRegion]:
    """
    Scan binary data for clusters of valid Shift-JIS encoded text.

    Uses a two-pass approach:
        1. Heuristic scan for consecutive valid Shift-JIS byte pairs
        2. Strict cp932 C-codec validation to confirm encoding

    Args:
        data: Raw binary data to scan.
        min_cluster_size: Minimum consecutive Shift-JIS bytes to flag.

    Returns:
        List of TextRegion objects with decoded previews.
    """
    clusters: list[TextRegion] = []
    data_len = len(data)
    i = 0

    while i < data_len:
        # Look for a Shift-JIS lead byte
        if not _is_sjis_lead_byte(data[i]):
            i += 1
            continue

        # Start tracking a potential cluster
        cluster_start = i
        valid_chars = 0

        while i < data_len - 1:
            b = data[i]

            # Two-byte Shift-JIS character
            if _is_sjis_lead_byte(b) and (i + 1 < data_len) and _is_sjis_trail_byte(data[i + 1]):
                valid_chars += 1
                i += 2
            # ASCII printable (single-byte, valid in Shift-JIS)
            elif 0x20 <= b <= 0x7E:
                valid_chars += 1
                i += 1
            # Common control codes
            elif b in (0x0A, 0x0D, 0x00):
                # Null terminator ends the cluster
                if b == 0x00:
                    break
                i += 1
            else:
                break

        cluster_len = i - cluster_start

        # Prevent infinite loop if an orphaned lead byte stalled the pointer
        if cluster_len == 0:
            i += 1
            continue

        if cluster_len < min_cluster_size or valid_chars < 3:
            continue

        # Validate with strict C-codec decoding
        chunk = data[cluster_start:cluster_start + cluster_len]
        try:
            decoded = chunk.decode("cp932", errors="strict")
            preview = decoded[:60].replace("\n", "↵").replace("\x00", "∅")
            
            clusters.append(TextRegion(
                offset=cluster_start,
                length=cluster_len,
                encoding="cp932",
                confidence=1.0,
                decoded_preview=preview,
            ))
        except UnicodeDecodeError:
            # Not valid Shift-JIS, skip it
            pass

    logger.info("Found %d Shift-JIS text clusters", len(clusters))
    return clusters


def analyze_binary(
    data: bytes,
    window_size: int = 256,
    step_size: int = 64,
    compressed_threshold: float = 7.0,
    structured_threshold: float = 4.0,
    min_cluster_size: int = 8,
) -> tuple[list[EntropyRegion], list[TextRegion]]:
    """
    Full binary analysis: entropy scan + Shift-JIS text detection.

    Returns:
        Tuple of (entropy_regions, text_clusters).
    """
    entropy_regions = scan_entropy(
        data, window_size, step_size,
        compressed_threshold, structured_threshold,
    )
    text_clusters = find_sjis_clusters(
        data, min_cluster_size,
    )

    return entropy_regions, text_clusters
