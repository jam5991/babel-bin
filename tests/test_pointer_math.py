import pytest
import struct

from src.iso.extractor import PSXExecutable
from src.patcher.pointer_math import ram_to_file_offset, file_offset_to_ram, write_split_pointer

@pytest.fixture
def mock_exe():
    from pathlib import Path
    return PSXExecutable(
        path=Path("mock.bin"),
        initial_pc=0x80010000,
        initial_gp=0x80010000,
        ram_dest=0x80010000,
        file_size=0x1000,
        bss_start=0x80011000,
        bss_size=0x100,
        stack_addr=0x801FFF00
    )


def test_ram_to_file(mock_exe):
    # 2048 is PS-X header size
    assert ram_to_file_offset(0x80010000, mock_exe) == 2048
    assert ram_to_file_offset(0x80011000, mock_exe) == 2048 + 4096

    with pytest.raises(ValueError):
        ram_to_file_offset(0x8000FFFF, mock_exe)


def test_file_to_ram(mock_exe):
    assert file_offset_to_ram(2048, mock_exe) == 0x80010000
    assert file_offset_to_ram(2048 + 4096, mock_exe) == 0x80011000

    with pytest.raises(ValueError):
        file_offset_to_ram(2000, mock_exe)


def test_write_split_pointer():
    data = bytearray(8)
    
    # Initially LUI $t0, 0x0000 (0x3C080000)
    # ADDIU $t0, $t0, 0x0000 (0x25080000)
    struct.pack_into("<I", data, 0, 0x3C080000)
    struct.pack_into("<I", data, 4, 0x25080000)

    # 1. Target with positive 16-bit low (e.g. 0x8001 4A20)
    # No sign extension compensation needed
    target = 0x80014A20
    write_split_pointer(data, 0, 4, target, mode="lui_addiu")
    assert struct.unpack_from("<I", data, 0)[0] == 0x3C088001
    assert struct.unpack_from("<I", data, 4)[0] == 0x25084A20

    # 2. Target with negative 16-bit low (e.g. 0x8001 9A20 -> sign bit is set)
    # Sign extension compensation needed
    target = 0x80019A20
    write_split_pointer(data, 0, 4, target, mode="lui_addiu")
    assert struct.unpack_from("<I", data, 0)[0] == 0x3C088002 # 0x8001 + 1
    assert struct.unpack_from("<I", data, 4)[0] == 0x25089A20

    # 3. Mode lui_ori (no compensation regardless of sign bit)
    struct.pack_into("<I", data, 0, 0x3C080000)
    struct.pack_into("<I", data, 4, 0x35080000) # ORI
    target = 0x80019A20
    write_split_pointer(data, 0, 4, target, mode="lui_ori")
    assert struct.unpack_from("<I", data, 0)[0] == 0x3C088001 # No +1
    assert struct.unpack_from("<I", data, 4)[0] == 0x35089A20
