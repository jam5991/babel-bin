"""
Tests for the MemoryMap code-cave allocator.

Validates the invariants that prevent black-screen boot failures:
1. Cave is placed right after orig_t_size (not at file end)
2. new_t_size = orig_t_size + cave (BIOS loads the cave)
3. ram_dest + new_t_size never overflows PS1's 2 MB physical RAM
4. new_t_size is sector-aligned (multiple of 2048)
5. Graceful fallback to empty caves when RAM is full
"""

import struct
import pytest
from pathlib import Path

from src.iso.extractor import PSXExecutable
from src.patcher.memory_map import MemoryMap, Cave

HEADER_SIZE = 2048
SECTOR_SIZE = 2048


def _make_exe(
    ram_dest: int = 0x80010000,
    t_size: int = 0x80000,      # 512 KB of code
    file_padding: int = 0,       # extra bytes past t_size (simulates CD padding)
) -> tuple[PSXExecutable, bytearray]:
    """Build a synthetic PS-X EXE for testing."""
    header = bytearray(HEADER_SIZE)
    header[0:8] = b"PS-X EXE"
    struct.pack_into("<I", header, 0x10, ram_dest)       # initial_pc
    struct.pack_into("<I", header, 0x14, ram_dest)       # initial_gp
    struct.pack_into("<I", header, 0x18, ram_dest)       # ram_dest
    struct.pack_into("<I", header, 0x1C, t_size)         # t_size
    struct.pack_into("<I", header, 0x28, 0)              # bss_start
    struct.pack_into("<I", header, 0x2C, 0)              # bss_size
    struct.pack_into("<I", header, 0x30, 0x801FFF00)     # sp

    data = bytearray(header + b"\xCC" * t_size + b"\x00" * file_padding)

    exe = PSXExecutable(
        path=Path("SLPM_869.24"),
        initial_pc=ram_dest,
        initial_gp=ram_dest,
        ram_dest=ram_dest,
        file_size=t_size,
        bss_start=0,
        bss_size=0,
        stack_addr=0x801FFF00,
    )
    return exe, data


# ── Core placement ──────────────────────────────────────────────

def test_cave_placed_after_t_size():
    """Cave must start at file offset HEADER + orig_t_size,
    NOT at the file end (which includes CD padding)."""
    t_size = 0x80000  # 512 KB
    exe, data = _make_exe(t_size=t_size, file_padding=4096)

    mm = MemoryMap(exe, data)
    cave = mm.caves[0]

    assert cave.file_offset == HEADER_SIZE + t_size
    assert cave.ram_address == exe.ram_dest + t_size


def test_t_size_covers_cave():
    """new_t_size = orig_t_size + cave, so the BIOS loads the cave."""
    t_size = 0x80000
    exe, data = _make_exe(t_size=t_size)

    mm = MemoryMap(exe, data)
    cave = mm.caves[0]

    new_t_size = struct.unpack_from("<I", data, 0x1C)[0]
    bios_loads_up_to = HEADER_SIZE + new_t_size
    cave_end = cave.file_offset + cave.size

    assert bios_loads_up_to >= cave_end


def test_t_size_sector_aligned():
    """t_size must be a multiple of 2048 (CD sector size)."""
    exe, data = _make_exe(t_size=0x80000, file_padding=123)
    MemoryMap(exe, data)

    new_t_size = struct.unpack_from("<I", data, 0x1C)[0]
    assert new_t_size % SECTOR_SIZE == 0


# ── Large executables (like SMT2) ───────────────────────────────

def test_large_exe_with_cd_padding():
    """Simulates SMT2: large t_size + lots of CD padding.
    Cave should reuse existing padding, no file growth."""
    t_size = 0x1C0000   # ~1.75 MB (leaves ~128KB headroom)
    file_padding = 0x2F000
    exe, data = _make_exe(t_size=t_size, file_padding=file_padding)

    orig_file_len = len(data)
    mm = MemoryMap(exe, data)
    cave = mm.caves[0]

    # Cave placed inside the existing padding
    assert cave.file_offset == HEADER_SIZE + t_size
    assert cave.file_offset < orig_file_len
    # File should NOT have grown
    assert len(data) == orig_file_len

    # RAM stays within bounds
    new_t_size = struct.unpack_from("<I", data, 0x1C)[0]
    ram_end = exe.ram_dest + new_t_size
    assert ram_end <= 0x80200000


def test_exe_fills_ram_graceful_fallback():
    """SMT2-like scenario: t_size=0x1EF000 fills nearly all RAM.
    MemoryMap must NOT crash — it creates an empty cave list instead."""
    # This matches real SMT2: t_size=0x1EF000, leaves only ~3.8KB
    exe, data = _make_exe(t_size=0x1EF000)
    orig_t_size_before = struct.unpack_from("<I", data, 0x1C)[0]

    mm = MemoryMap(exe, data)

    # Should have no caves, not a crash
    assert mm.caves == []

    # Header must NOT have been modified (no cave = no t_size change)
    assert struct.unpack_from("<I", data, 0x1C)[0] == orig_t_size_before

    # File must NOT have grown
    assert len(data) == HEADER_SIZE + 0x1EF000

    # Allocation must return None
    assert mm.allocate(1) is None


def test_file_extends_only_when_needed():
    """If there's no CD padding, the file must grow to accommodate the cave."""
    t_size = 0x80000  # 512 KB, no padding
    exe, data = _make_exe(t_size=t_size, file_padding=0)
    orig_len = len(data)

    mm = MemoryMap(exe, data)

    assert len(data) > orig_len
    assert mm.caves[0].file_offset == orig_len


# ── RAM overflow protection ─────────────────────────────────────

def test_ram_overflow_prevented():
    """Cave size must shrink to fit within 2MB RAM."""
    exe, data = _make_exe(t_size=0x1D8000)
    mm = MemoryMap(exe, data)

    new_t_size = struct.unpack_from("<I", data, 0x1C)[0]
    ram_end = exe.ram_dest + new_t_size
    assert ram_end <= 0x80200000


# ── Allocation ──────────────────────────────────────────────────

def test_allocate_returns_cave_address():
    exe, data = _make_exe()
    mm = MemoryMap(exe, data)

    addr = mm.allocate(128, alignment=4)
    assert addr is not None
    assert addr >= mm.caves[0].ram_address
    assert addr < mm.caves[0].ram_address + mm.caves[0].size


def test_allocate_exhausted_returns_none():
    exe, data = _make_exe()
    mm = MemoryMap(exe, data)

    cave_size = mm.caves[0].size
    addr = mm.allocate(cave_size, alignment=1)
    assert addr is not None

    assert mm.allocate(1) is None
