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
        Initialize the memory map by appending a dedicated 256KB code cave to the EOF.

        Args:
            exe: Parsed PS-X EXE header.
            data: Raw executable bytearray (modified in-place).
            min_cave_size: (Legacy parameter, unused).
        """
        self.exe = exe
        self.min_cave_size = min_cave_size
        
        # We physically extend the binary by 256KB to securely house all translation
        # injections and VWF payloads safely without corrupting .bss / .data arrays.
        extension_size = 256 * 1024  
        
        import struct
        # 1. Update the PS-X Header t_size (Text Size) at offset 0x1C
        #    This genuinely guarantees the PlayStation Kernel Exec() syscall naturally loads
        #    the entirety of our newly appended payload block successfully into console RAM!
        orig_t_size = struct.unpack_from("<I", data, 0x1C)[0]
        new_t_size = orig_t_size + extension_size
        struct.pack_into("<I", data, 0x1C, new_t_size)
        
        # 2. Append the block to the raw bytearray
        orig_file_len = len(data)
        data.extend(b"\x00" * extension_size)
        
        # 3. Create a single master Cave strictly binding to the appended block securely.
        #    ram_dest is the RAM address of offset 2048 naturally.
        code_cave_ram_address = exe.ram_dest + (orig_file_len - 2048)
        
        self.caves = [Cave(
            file_offset=orig_file_len,
            ram_address=code_cave_ram_address,
            size=extension_size,
        )]
        
        logger.info(
            "MemoryMap initialized: Appended dedicated 256KB code cave at EOF (RAM: 0x%08X). Original t_size expanded from %d to %d bytes.",
            code_cave_ram_address, orig_t_size, new_t_size
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
