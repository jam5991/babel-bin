"""
Phase 5b — Pointer Arithmetic.

Converts between PS1 RAM addresses (`0x80XXXXXX`) and file offsets.
Handles complex pointer loads in MIPS, particularly the common `lui`/`addiu`
and `lui`/`ori` pairs used to load 32-bit addresses into registers.
"""

from __future__ import annotations

import logging
import struct

from src.iso.extractor import PSXExecutable

logger = logging.getLogger(__name__)

# PS-X EXE header size is always 2048 bytes
HEADER_SIZE = 2048


def ram_to_file_offset(ram_addr: int, exe: PSXExecutable) -> int:
    """
    Convert a PS1 RAM address to a file offset within the executable.

    The executable code segment begins immediately after the 2048-byte header
    and is loaded directly into RAM at `exe.ram_dest`.
    """
    if ram_addr < exe.ram_dest:
        raise ValueError(
            f"RAM address 0x{ram_addr:08X} is below executable load "
            f"address (0x{exe.ram_dest:08X})"
        )
        
    offset_in_code = ram_addr - exe.ram_dest
    file_offset = HEADER_SIZE + offset_in_code
    
    return file_offset


def file_offset_to_ram(file_offset: int, exe: PSXExecutable) -> int:
    """
    Convert a file offset within the executable to its loaded PS1 RAM address.
    """
    if file_offset < HEADER_SIZE:
        raise ValueError("File offset points inside the PS-X header (0-2047)")
        
    offset_in_code = file_offset - HEADER_SIZE
    ram_addr = exe.ram_dest + offset_in_code
    
    return ram_addr


def write_direct_pointer(data: bytearray, file_offset: int, pointer_val: int) -> None:
    """
    Write a 32-bit little-endian absolute pointer value.
    Typically used for pointer tables or arrays of addresses.
    """
    struct.pack_into("<I", data, file_offset, pointer_val & 0xFFFFFFFF)


def write_split_pointer(
    data: bytearray,
    file_offset_high: int,
    file_offset_low: int,
    pointer_val: int,
    mode: str = "lui_addiu"
) -> None:
    """
    Update a split 32-bit pointer loaded across two MIPS instructions.

    MIPS loading a 32-bit address typically looks like:
        lui $reg, 0x8001      # Load Upper Immediate (high 16 bits)
        ...
        addiu $reg, $reg, 0x4A20 # Add Immediate Unsigned (low 16 bits)

    Due to sign-extension in MIPS, if the low 16 bits have their MSB set
    (i.e., >= 0x8000), the `addiu` will subtract from the upper half.
    To compensate, the upper half must be incremented by 1.

    Alternatively, `lui` followed by `ori` (Bitwise OR Immediate) does not
    sign-extend, so no compensation is needed.
    """
    upper_16 = (pointer_val >> 16) & 0xFFFF
    lower_16 = pointer_val & 0xFFFF

    if mode == "lui_addiu":
        # Handle sign extension compensation
        if lower_16 >= 0x8000:
            upper_16 = (upper_16 + 1) & 0xFFFF
    elif mode == "lui_ori":
        # No compensation needed
        pass
    else:
        raise ValueError(f"Unknown split pointer mode: {mode}")

    # MIPS instructions are 32-bit little-endian.
    # The immediate value is always in the lower 16 bits of the instruction word.
    
    # Read the current instruction words
    high_word = struct.unpack_from("<I", data, file_offset_high)[0]
    low_word = struct.unpack_from("<I", data, file_offset_low)[0]

    # Clear the old 16-bit immediate values (retain the opcodes/registers)
    high_word = (high_word & 0xFFFF0000) | upper_16
    low_word = (low_word & 0xFFFF0000) | lower_16

    # Write the modified instruction words back
    struct.pack_into("<I", data, file_offset_high, high_word)
    struct.pack_into("<I", data, file_offset_low, low_word)
    
    logger.debug(
        "Updated split pointer (%s) to 0x%08X: high=0x%04X, low=0x%04X",
        mode, pointer_val, upper_16, lower_16
    )
