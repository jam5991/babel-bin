"""
Phase 3b — Compression Bypass via Native Re-execution.

Rather than reimplementing the game's bespoke compression algorithms in
Python, this module locates the native compression/decompression routines
in the executable and runs them through the Unicorn-based PS1 emulator.

Workflow:
    1. Use Capstone to disassemble and identify compression loop patterns
    2. Load the game's executable into the emulator
    3. Execute the native decompressor to unpack compressed text blocks
    4. After translation, execute the native compressor to repack

Falls back to common PS1 compression algorithms (LZSS) if emulation fails.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

from src.emu.unicorn_psx import PSXEmulator, PSX_RAM_BASE

logger = logging.getLogger(__name__)

# ── Capstone Disassembler ────────────────────────────────────
_disasm = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
_disasm.detail = True


@dataclass
class CompressionRoutine:
    """A discovered compression or decompression routine."""
    address: int             # RAM address of the routine entry
    type: str                # "compress" or "decompress"
    confidence: float        # 0.0–1.0 confidence in the classification
    algorithm_hint: str      # "lzss", "rle", "huffman", "unknown"
    size_estimate: int       # Approximate size of the routine in bytes


@dataclass
class DecompressedBlock:
    """Result of decompressing a data block."""
    original_data: bytes     # The compressed input
    decompressed_data: bytes # The decompressed output
    original_size: int       # Compressed size
    decompressed_size: int   # Decompressed size
    method: str              # "emulated" or "fallback_lzss"


# ── Pattern Matching ─────────────────────────────────────────

def find_compression_routines(
    exe_data: bytes,
    ram_base: int = 0x80010000,
    max_scan_size: int = 0x100000,
) -> list[CompressionRoutine]:
    """
    Scan a PS-X executable for compression/decompression routines using
    MIPS disassembly pattern matching.

    Looks for characteristic patterns:
        - Tight loops with byte load/store (lbu/sb)
        - Sliding window references (common in LZSS)
        - Bit-shift operations for flag processing
        - Counter-based loop termination

    Args:
        exe_data: Raw executable bytes (including 2048-byte header).
        ram_base: RAM load address of the executable.
        max_scan_size: Maximum bytes to scan from the code segment.

    Returns:
        List of discovered routines sorted by confidence.
    """
    code = exe_data[2048:]  # Skip PS-X EXE header
    scan_size = min(len(code), max_scan_size)

    routines: list[CompressionRoutine] = []
    window_size = 256  # Analyze 256-byte windows

    for offset in range(0, scan_size - window_size, 4):  # MIPS = 4-byte aligned
        window = code[offset:offset + window_size]
        address = ram_base + offset

        score, algo_hint, routine_type = _analyze_window(window, address)

        if score >= 0.6:
            routines.append(CompressionRoutine(
                address=address,
                type=routine_type,
                confidence=score,
                algorithm_hint=algo_hint,
                size_estimate=window_size,
            ))

    # Deduplicate overlapping discoveries
    routines = _deduplicate_routines(routines)

    # Sort by confidence
    routines.sort(key=lambda r: r.confidence, reverse=True)

    logger.info(
        "Found %d candidate compression routines (top confidence: %.1f%%)",
        len(routines),
        routines[0].confidence * 100 if routines else 0,
    )

    return routines


def _analyze_window(
    window: bytes,
    base_address: int,
) -> tuple[float, str, str]:
    """
    Analyze a code window for compression routine patterns.

    Returns:
        (confidence_score, algorithm_hint, routine_type)
    """
    instructions = list(_disasm.disasm(window, base_address))

    if len(instructions) < 8:
        return 0.0, "unknown", "unknown"

    # Count instruction patterns
    has_lbu = 0      # Load byte unsigned (reading compressed data)
    has_sb = 0       # Store byte (writing decompressed data)
    has_srl_sll = 0  # Shift operations (bit flag processing)
    has_andi = 0     # Bitwise AND (mask operations)
    has_branch = 0   # Branch instructions (loops)
    has_addiu = 0    # Address increments

    for insn in instructions:
        mnemonic = insn.mnemonic
        if mnemonic == "lbu":
            has_lbu += 1
        elif mnemonic == "sb":
            has_sb += 1
        elif mnemonic in ("srl", "sll", "sra"):
            has_srl_sll += 1
        elif mnemonic == "andi":
            has_andi += 1
        elif mnemonic.startswith("b") and mnemonic not in ("break",):
            has_branch += 1
        elif mnemonic == "addiu":
            has_addiu += 1

    # Score the window
    score = 0.0

    # Must have byte loads AND stores (core of any compressor/decompressor)
    if has_lbu >= 2 and has_sb >= 2:
        score += 0.3

    # Bit manipulation suggests flag-based compression (LZSS, Huffman)
    if has_srl_sll >= 2 or has_andi >= 2:
        score += 0.2

    # Must have loops
    if has_branch >= 2:
        score += 0.2

    # Address increments suggest sequential processing
    if has_addiu >= 3:
        score += 0.1

    # High ratio of byte ops suggests data processing, not game logic
    total = len(instructions)
    byte_ratio = (has_lbu + has_sb) / total if total > 0 else 0
    if byte_ratio > 0.15:
        score += 0.2

    # Determine algorithm hint
    algo_hint = "unknown"
    if has_srl_sll >= 3 and has_andi >= 2:
        algo_hint = "lzss"  # LZSS uses bit flags for literal vs. reference
    elif has_sb > has_lbu * 2:
        algo_hint = "rle"   # RLE writes more than it reads
    elif has_srl_sll >= 5:
        algo_hint = "huffman"

    # Determine if this is compress or decompress
    # Decompressors typically read more (lbu) than they write (sb)
    routine_type = "decompress" if has_lbu >= has_sb else "compress"

    return min(score, 1.0), algo_hint, routine_type


def _deduplicate_routines(routines: list[CompressionRoutine]) -> list[CompressionRoutine]:
    """Remove overlapping routine discoveries, keeping the highest confidence."""
    if not routines:
        return routines

    routines.sort(key=lambda r: r.address)
    deduped = [routines[0]]

    for routine in routines[1:]:
        prev = deduped[-1]
        # If this routine overlaps with the previous one
        if routine.address < prev.address + prev.size_estimate:
            # Keep the one with higher confidence
            if routine.confidence > prev.confidence:
                deduped[-1] = routine
        else:
            deduped.append(routine)

    return deduped


# ── Emulated Decompression ──────────────────────────────────

# Scratch space in PS1 RAM for input/output buffers
_INPUT_BUFFER = 0x80180000
_OUTPUT_BUFFER = 0x80190000
_BUFFER_SIZE = 0x10000  # 64 KB each


def decompress_via_emulation(
    emu: PSXEmulator,
    compressed_data: bytes,
    routine_address: int,
    max_output_size: int = _BUFFER_SIZE,
) -> Optional[DecompressedBlock]:
    """
    Decompress a data block by running the game's native decompressor in the emulator.

    Convention (common PS1 decompressor signature):
        $a0 = pointer to compressed input
        $a1 = pointer to output buffer
        $v0 = decompressed size (return value)

    Args:
        emu: Initialized PSXEmulator with the game's executable loaded.
        compressed_data: The compressed data block.
        routine_address: RAM address of the native decompression routine.
        max_output_size: Maximum output buffer size.

    Returns:
        DecompressedBlock, or None if emulation fails.
    """
    if len(compressed_data) > _BUFFER_SIZE:
        logger.warning(
            "Compressed block (%d bytes) exceeds buffer size (%d bytes)",
            len(compressed_data), _BUFFER_SIZE,
        )
        return None

    try:
        # Write compressed data to input buffer
        emu.load_data(_INPUT_BUFFER, compressed_data)

        # Clear output buffer
        emu.load_data(_OUTPUT_BUFFER, b"\x00" * max_output_size)

        # Execute the decompression routine
        result = emu.execute_function(
            routine_address,
            args=[_INPUT_BUFFER, _OUTPUT_BUFFER],
        )

        if result.timed_out:
            logger.warning("Decompression emulation timed out at 0x%08X", result.stopped_at)
            return None

        # Read the decompressed output
        decompressed_size = result.return_value
        if decompressed_size == 0 or decompressed_size > max_output_size:
            logger.warning(
                "Suspicious decompressed size: %d (return value from 0x%08X)",
                decompressed_size, routine_address,
            )
            # Try reading until first null run as fallback
            decompressed_size = min(max_output_size, 0x8000)

        output = emu.read_memory(_OUTPUT_BUFFER, decompressed_size)

        return DecompressedBlock(
            original_data=compressed_data,
            decompressed_data=output,
            original_size=len(compressed_data),
            decompressed_size=len(output),
            method="emulated",
        )

    except Exception as e:
        logger.error("Emulated decompression failed: %s", e)
        return None


def compress_via_emulation(
    emu: PSXEmulator,
    data: bytes,
    routine_address: int,
) -> Optional[bytes]:
    """
    Compress a data block using the game's native compressor.

    Same calling convention as decompress, but in reverse.
    """
    if len(data) > _BUFFER_SIZE:
        logger.warning("Data block too large for compression buffer")
        return None

    try:
        emu.load_data(_INPUT_BUFFER, data)
        emu.load_data(_OUTPUT_BUFFER, b"\x00" * _BUFFER_SIZE)

        result = emu.execute_function(
            routine_address,
            args=[_INPUT_BUFFER, _OUTPUT_BUFFER],
        )

        if result.timed_out:
            logger.warning("Compression emulation timed out")
            return None

        compressed_size = result.return_value
        if compressed_size == 0 or compressed_size > _BUFFER_SIZE:
            logger.warning("Suspicious compressed size: %d", compressed_size)
            return None

        return emu.read_memory(_OUTPUT_BUFFER, compressed_size)

    except Exception as e:
        logger.error("Emulated compression failed: %s", e)
        return None


# ── Fallback: Pure-Python LZSS ───────────────────────────────

def decompress_lzss(
    data: bytes,
    window_size: int = 4096,
    lookahead_size: int = 18,
) -> bytes:
    """
    Fallback LZSS decompressor for common PS1 compression.

    Standard LZSS format:
        - 1 flag byte per 8 items
        - Flag bit = 1: literal byte follows
        - Flag bit = 0: (offset, length) reference follows (2 bytes)
    """
    output = bytearray()
    pos = 0
    data_len = len(data)

    while pos < data_len:
        # Read flag byte
        if pos >= data_len:
            break
        flags = data[pos]
        pos += 1

        for bit in range(8):
            if pos >= data_len:
                break

            if flags & (1 << bit):
                # Literal byte
                output.append(data[pos])
                pos += 1
            else:
                # Back-reference
                if pos + 1 >= data_len:
                    break

                b0 = data[pos]
                b1 = data[pos + 1]
                pos += 2

                # Decode offset and length
                offset = ((b1 & 0xF0) << 4) | b0
                length = (b1 & 0x0F) + 3  # Minimum match = 3

                # Copy from sliding window
                for _ in range(length):
                    if offset < len(output):
                        output.append(output[len(output) - offset - 1])
                    else:
                        output.append(0)

    return bytes(output)


def compress_lzss(
    data: bytes,
    window_size: int = 4096,
    lookahead_size: int = 18,
) -> bytes:
    """
    Fallback LZSS compressor matching the PS1 decompressor format.

    Note: This produces valid but potentially suboptimal compression.
    The emulated native compressor is preferred when available.
    """
    output = bytearray()
    pos = 0
    data_len = len(data)

    while pos < data_len:
        flag_byte = 0
        flag_pos = len(output)
        output.append(0)  # Placeholder for flag byte
        items: list[bytes] = []

        for bit in range(8):
            if pos >= data_len:
                break

            # Search for a match in the sliding window
            best_offset = 0
            best_length = 0
            search_start = max(0, pos - window_size)

            for search_pos in range(search_start, pos):
                length = 0
                while (
                    length < lookahead_size
                    and pos + length < data_len
                    and data[search_pos + length] == data[pos + length]
                ):
                    length += 1
                    if search_pos + length >= pos:
                        break

                if length > best_length:
                    best_length = length
                    best_offset = pos - search_pos - 1

            if best_length >= 3:
                # Encode as back-reference
                b0 = best_offset & 0xFF
                b1 = ((best_offset >> 4) & 0xF0) | ((best_length - 3) & 0x0F)
                items.append(bytes([b0, b1]))
                pos += best_length
            else:
                # Encode as literal
                flag_byte |= (1 << bit)
                items.append(bytes([data[pos]]))
                pos += 1

        output[flag_pos] = flag_byte
        for item in items:
            output.extend(item)

    return bytes(output)
