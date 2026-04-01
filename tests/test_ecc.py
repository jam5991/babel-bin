import pytest

from src.iso.ecc_edc import compute_edc, compute_ecc_p, compute_ecc_q, patch_sector_checksums

# Test data vectors
TEST_DATA = b"\x01" * 2048
# Subheader (Mode 2 Form 1, typical values)
SUBHEADER = b"\x00\x00\x08\x00\x00\x00\x08\x00"

def test_compute_edc():
    # Example Sector EDC input = Subheader + User Data
    edc_input = SUBHEADER + TEST_DATA
    
    # EDC for this specific block:
    # We don't need a "magic" number here, just ensure it's deterministic and
    # returns a valid 32-bit unsigned integer.
    edc = compute_edc(edc_input)
    assert 0 <= edc <= 0xFFFFFFFF
    
    # Same data should produce same EDC
    assert edc == compute_edc(edc_input)
    
    # Changed data should produce different EDC
    changed_input = SUBHEADER + b"\x02" * 2048
    assert edc != compute_edc(changed_input)


def test_compute_ecc():
    # ECC Input = 1032 bytes starting at offset 0x00C in sector
    # Includes header, subheader, and part of user data
    header = b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x02\x00\x02"
    ecc_input = (header[12:] + SUBHEADER + TEST_DATA)[:1032]
    
    # Ensure sizes are correct
    p_parity = compute_ecc_p(ecc_input)
    assert len(p_parity) == 172
    
    q_parity = compute_ecc_q(ecc_input, p_parity)
    assert len(q_parity) == 104


def test_patch_sector():
    # Create a dummy Mode 2 Form 1 sector (2352 bytes)
    sector = bytearray(2352)
    
    # Set sync pattern
    sector[0:12] = b"\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00"
    
    # Set Mode 2 (byte 15)
    sector[15] = 0x02
    
    # Set form 1 subheader (byte 18 and 22 submode flags = 0x08 for Form 1)
    sector[18] = 0x08
    sector[22] = 0x08
    
    # Add some payload data
    for i in range(24, 2072):
        sector[i] = i % 256
        
    original = bytearray(sector)
    
    # Patch it
    patched = patch_sector_checksums(sector)
    
    # Ensure length didn't change
    assert len(patched) == 2352
    
    # Ensure data didn't change
    assert patched[:0x818] == original[:0x818]
    
    # Ensure EDC changed from original zeros
    import struct
    new_edc = struct.unpack_from("<I", patched, 0x818)[0]
    assert new_edc != 0
    
    # Ensure ECC changed
    assert patched[0x81C:0x8C8] != original[0x81C:0x8C8] # P
    assert patched[0x8C8:0x930] != original[0x8C8:0x930] # Q
