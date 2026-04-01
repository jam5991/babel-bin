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

    def __init__(self, exe: PSXExecutable, data: bytes, min_cave_size: int = 64):
        """
        Initialize the memory map by scanning the executable for caves.

        Args:
            exe: Parsed PS-X EXE header.
            data: Raw executable bytes.
            min_cave_size: Minimum contiguous bytes to consider it a usable cave.
        """
        self.exe = exe
        self.min_cave_size = min_cave_size
        self.caves: list[Cave] = self._scan_caves(data)
        
        total_free = sum(c.size for c in self.caves)
        logger.info(
            "MemoryMap initialized: discovered %d code caves (total: %d bytes / %.1f KB)",
            len(self.caves), total_free, total_free / 1024,
        )

    def _scan_caves(self, data: bytes) -> list[Cave]:
        """Scan the executable for blocks of CAVE_BYTE."""
        caves = []
        data_len = len(data)
        
        # Start immediately after the 2048-byte header
        header_size = 2048
        i = header_size

        while i < data_len:
            if data[i] == CAVE_BYTE:
                start = i
                # Count consecutive cave bytes
                while i < data_len and data[i] == CAVE_BYTE:
                    i += 1
                
                size = i - start
                
                if size >= self.min_cave_size:
                    # Found a valid cave
                    offset_from_code_start = start - header_size
                    ram_address = self.exe.ram_dest + offset_from_code_start
                    
                    caves.append(Cave(
                        file_offset=start,
                        ram_address=ram_address,
                        size=size,
                    ))
            else:
                i += 1

        return caves

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
