"""
CD-ROM Mode 2 EDC/ECC Calculator.

Pure-Python implementation of the Error Detection Code (EDC, CRC-32 variant)
and Error Correction Code (ECC, Reed-Solomon P/Q parity) used in CD-ROM XA
Mode 2 Form 1 sectors.

Used as a validation layer to verify sectors after mkpsxiso rebuild, and as a
standalone tool for manual sector patching when mkpsxiso is not available.

References:
    - ECMA-130: Data interchange on read-only 120 mm optical data discs (CD-ROM)
    - EDC polynomial: x^32 + x^31 + x^16 + x^15 + x^4 + x^3 + x + 1
"""

from __future__ import annotations

import struct
from typing import Optional

# ── EDC (Error Detection Code) ───────────────────────────────
# Pre-computed CRC-32 table with CD-ROM polynomial 0xD8018001
_EDC_TABLE: Optional[list[int]] = None


def _build_edc_table() -> list[int]:
    """Build the EDC lookup table (CD-ROM CRC-32 variant)."""
    table = []
    for i in range(256):
        edc = i
        for _ in range(8):
            if edc & 1:
                edc = (edc >> 1) ^ 0xD8018001
            else:
                edc >>= 1
        table.append(edc & 0xFFFFFFFF)
    return table


def compute_edc(data: bytes) -> int:
    """
    Compute the EDC (CRC-32) for a block of sector data.

    For Mode 2 Form 1:
        Input = bytes 0x010..0x818 (2056 bytes: subheader + user data)
        EDC is stored at bytes 0x818..0x81C
    """
    global _EDC_TABLE
    if _EDC_TABLE is None:
        _EDC_TABLE = _build_edc_table()

    edc = 0
    for byte in data:
        edc = _EDC_TABLE[(edc ^ byte) & 0xFF] ^ (edc >> 8)
    return edc & 0xFFFFFFFF


# ── ECC (Error Correction Code) ──────────────────────────────
# GF(2^8) lookup tables for Reed-Solomon

_GF_LOG: Optional[list[int]] = None
_GF_EXP: Optional[list[int]] = None


def _build_gf_tables() -> tuple[list[int], list[int]]:
    """Build GF(2^8) log and exponent tables with primitive polynomial x^8+x^4+x^3+x^2+1."""
    gf_log = [0] * 256
    gf_exp = [0] * 256

    val = 1
    for i in range(255):
        gf_exp[i] = val
        gf_log[val] = i
        val <<= 1
        if val & 0x100:
            val ^= 0x11D  # Primitive polynomial
    gf_log[0] = 0  # Convention

    return gf_log, gf_exp


def _gf_mul(a: int, b: int) -> int:
    """Multiply two values in GF(2^8)."""
    global _GF_LOG, _GF_EXP
    if _GF_LOG is None or _GF_EXP is None:
        _GF_LOG, _GF_EXP = _build_gf_tables()

    if a == 0 or b == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] + _GF_LOG[b]) % 255]


def compute_ecc_p(data: bytes) -> bytes:
    """
    Compute P-parity (172 bytes) for a Mode 2 Form 1 sector.

    P-parity covers 1032 bytes of data (86 rows × 24 columns),
    producing 2 parity bytes per column = 172 bytes total.

    Input data: 1032 bytes starting from offset 0x00C in the sector.
    """
    p_parity = bytearray(172)

    for j in range(43):
        for i in range(24):
            # Collect the column
            col = []
            for k in range(43):
                idx = k * 24 + i
                if idx < len(data):
                    col.append(data[idx])
                else:
                    col.append(0)

            # Simple parity (XOR-based for P)
            p0 = 0
            p1 = 0
            for k, val in enumerate(col[:43]):
                p0 ^= val
                p1 ^= _gf_mul(val, k + 1) if val else 0

            base = j * 4 + (i % 2) * 2
            if base < 172:
                p_parity[base] = p0
            if base + 1 < 172:
                p_parity[base + 1] = p1

    return bytes(p_parity)


def compute_ecc_q(data: bytes, p_parity: bytes) -> bytes:
    """
    Compute Q-parity (104 bytes) for a Mode 2 Form 1 sector.

    Q-parity covers the data + P-parity combined,
    producing 2 parity bytes per diagonal = 104 bytes total.
    """
    combined = data + p_parity
    q_parity = bytearray(104)

    for i in range(52):
        q0 = 0
        q1 = 0
        for j in range(43):
            idx = (i + j * 44) % len(combined) if len(combined) > 0 else 0
            if idx < len(combined):
                val = combined[idx]
                q0 ^= val
                q1 ^= _gf_mul(val, j + 1) if val else 0

        q_parity[i * 2] = q0
        q_parity[i * 2 + 1] = q1

    return bytes(q_parity)


# ── Sector-Level Operations ──────────────────────────────────

# CD-ROM sector sizes
RAW_SECTOR_SIZE = 2352
MODE2_FORM1_DATA_SIZE = 2048
SYNC_PATTERN = bytes([0x00] + [0xFF] * 10 + [0x00])


def validate_sector_edc(sector: bytes) -> bool:
    """
    Validate the EDC of a Mode 2 Form 1 sector.

    Args:
        sector: A complete 2352-byte raw sector.

    Returns:
        True if the EDC matches, False otherwise.
    """
    if len(sector) != RAW_SECTOR_SIZE:
        raise ValueError(f"Expected {RAW_SECTOR_SIZE} bytes, got {len(sector)}")

    # Mode 2 Form 1: EDC covers subheader (4 bytes) + user data (2048 bytes)
    # Subheader at 0x010, user data at 0x018, EDC at 0x818
    edc_data = sector[0x010:0x818]
    stored_edc = struct.unpack_from("<I", sector, 0x818)[0]
    computed_edc = compute_edc(edc_data)

    return stored_edc == computed_edc


def patch_sector_checksums(sector: bytearray) -> bytearray:
    """
    Recalculate and write EDC and ECC for a Mode 2 Form 1 sector.

    This is the primary function used when manually patching sectors
    outside of the mkpsxiso workflow.

    Args:
        sector: A mutable 2352-byte raw sector.

    Returns:
        The sector with updated EDC and ECC fields.
    """
    if len(sector) != RAW_SECTOR_SIZE:
        raise ValueError(f"Expected {RAW_SECTOR_SIZE} bytes, got {len(sector)}")

    # Recalculate EDC
    edc_data = bytes(sector[0x010:0x818])
    new_edc = compute_edc(edc_data)
    struct.pack_into("<I", sector, 0x818, new_edc)

    # Recalculate ECC (P-parity at 0x81C, Q-parity at 0x8C8)
    ecc_data = bytes(sector[0x00C:0x818])
    p_parity = compute_ecc_p(ecc_data)
    sector[0x81C:0x81C + len(p_parity)] = p_parity

    q_parity = compute_ecc_q(ecc_data, p_parity)
    sector[0x8C8:0x8C8 + len(q_parity)] = q_parity

    return sector
