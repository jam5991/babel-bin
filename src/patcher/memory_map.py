"""
Phase 5a — Memory Map free space allocator.

Scans the game executable for contiguous regions of null bytes ("code caves").
Tracks available and used space to allocate room for expanded translations
and injected assembly hooks (like the VWF renderer).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from src.iso.extractor import PSXExecutable

logger = logging.getLogger(__name__)

# Typical padding byte used by compilers (null or NOPs)
CAVE_BYTE = 0x00


@dataclass
class Cave:
    """A discovered contiguous region of free space in the executable."""
    file_offset: int         # Offset within the .bin file
    ram_address: int         # Destination address in PS1 memory
    size: int                # Total size in bytes
    used: int = 0            # Bytes allocated so far

    @property
    def free_space(self) -> int:
        return self.size - self.used


class MemoryMap:
    """
    Manages the executable's free space (code caves).
    Tracks allocations to ensure we don't overwrite used space.
    """

    # PS1 physical RAM ceiling (KSEG0)
    PSX_RAM_END = 0x80200000
    # Reserve space for the stack (the kernel default SP is 0x801FFF00)
    PSX_STACK_RESERVE = 0x10000   # 64 KB headroom

    def __init__(self, exe: PSXExecutable, data: bytearray, min_cave_size: int = 64):
        """
        Initialize the memory map by placing a code cave after the loaded code.

        The PS1 BIOS ``Exec()`` syscall loads exactly ``t_size`` bytes from
        file offset 0x800 into RAM at ``ram_dest``.  The physical file on CD
        is often *larger* than ``2048 + t_size`` due to ISO 9660 sector
        padding — those extra bytes are **never loaded into RAM**.

        We therefore:

        1. Place the cave at file offset ``2048 + orig_t_size`` — right after
           the last byte the BIOS loads.  This reuses any existing CD padding
           in the file (no wasted space).
        2. Extend ``t_size`` by exactly the cave size so the BIOS now loads
           the cave too.
        3. Only grow the physical file if the cave extends past the current EOF.
        4. Guard against RAM overflow: ``ram_dest + new_t_size`` must stay
           below ``0x80200000 - stack_reserve``.
        5. Sector-align ``new_t_size`` (multiple of 2048) for the disc reader.

        Args:
            exe:  Parsed PS-X EXE header.
            data: Raw executable bytearray (modified **in-place**).
            min_cave_size: Minimum usable cave bytes; raises if we cannot fit.
        """
        import struct

        self.exe = exe
        self.min_cave_size = min_cave_size

        HEADER_SIZE = 2048
        SECTOR_SIZE = 2048

        orig_file_len = len(data)
        orig_t_size = struct.unpack_from("<I", data, 0x1C)[0]

        # --- Available RAM for a cave -----------------------------------------
        # The BIOS loads orig_t_size bytes into RAM at ram_dest.  The absolute
        # ceiling is end-of-RAM (0x80200000).  We leave a small stack margin
        # but keep it realistic — many PS1 RPGs leave < 4 KB for the stack.
        max_loadable = self.PSX_RAM_END - exe.ram_dest
        available_for_cave = max(0, max_loadable - orig_t_size - self.PSX_STACK_RESERVE)

        # Target 64 KB; fall back to whatever fits.
        desired = 64 * 1024
        extension_size = min(desired, available_for_cave)

        # Sector-align downward so new_t_size is a clean multiple of 2048
        extension_size = (extension_size // SECTOR_SIZE) * SECTOR_SIZE

        if extension_size < min_cave_size:
            # ── No room for a cave — fall back to in-place-only mode ──────────
            # This is common for large RPGs (e.g. SMT2 fills ~1.95 MB).
            # In-place replacement still works: Shift-JIS is 2 bytes/char while
            # ASCII is 1 byte/char, so English translations almost always fit.
            self.caves = []
            logger.warning(
                "MemoryMap: no room for a code cave "
                "(t_size=0x%X, available=%d bytes, need>=%d).  "
                "Falling back to in-place text replacement only.",
                orig_t_size, available_for_cave, min_cave_size,
            )
            return

        # --- Place the cave right after the loaded code -----------------------
        cave_file_offset = HEADER_SIZE + orig_t_size
        cave_ram_address = exe.ram_dest + orig_t_size

        # Grow the physical file only if the cave extends past the current EOF
        needed_file_size = cave_file_offset + extension_size
        if needed_file_size > orig_file_len:
            data.extend(b"\x00" * (needed_file_size - orig_file_len))
        # (If the cave fits inside existing CD padding, no extension needed —
        #  the padding bytes are already zeroed.)

        # --- Update the PS-X header -------------------------------------------
        new_t_size = orig_t_size + extension_size
        # Sector-align upward for the BIOS disc reader
        new_t_size = ((new_t_size + SECTOR_SIZE - 1) // SECTOR_SIZE) * SECTOR_SIZE
        struct.pack_into("<I", data, 0x1C, new_t_size)

        self.caves = [Cave(
            file_offset=cave_file_offset,
            ram_address=cave_ram_address,
            size=extension_size,
        )]

        logger.info(
            "MemoryMap: %d KB cave at RAM 0x%08X (file offset 0x%X)  "
            "t_size: 0x%X → 0x%X  RAM ceiling: 0x%08X",
            extension_size // 1024,
            cave_ram_address,
            cave_file_offset,
            orig_t_size,
            new_t_size,
            exe.ram_dest + new_t_size,
        )

    def allocate(self, size: int, alignment: int = 4) -> int | None:
        """
        Allocate space in the first available cave.

        Args:
            size: Number of bytes to allocate.
            alignment: Byte alignment required for the allocated address.

        Returns:
            The RAM address allocated, or None if no cave is large enough.
        """
        for cave in self.caves:
            # Calculate alignment padding needed
            current_addr = cave.ram_address + cave.used
            padding = (alignment - (current_addr % alignment)) % alignment
            
            total_needed = size + padding
            
            if cave.free_space >= total_needed:
                allocated_addr = current_addr + padding
                cave.used += total_needed
                logger.debug(
                    "Allocated %d bytes (padding: %d) at 0x%08X",
                    size, padding, allocated_addr
                )
                return allocated_addr
                
        logger.warning("Memory allocation failed: no cave large enough for %d bytes", size)
        return None

    def get_total_free_space(self) -> int:
        """Get the total available space across all caves."""
        return sum(cave.free_space for cave in self.caves)
