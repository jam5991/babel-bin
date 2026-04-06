#!/usr/bin/env python3
"""
SMT2 PS1 Text Analyzer
======================
Analyzes the ZZZZZZZZ.ZZZ game data archive to find and decode text data.

Strategy: Instead of trying to decompress ZZZZZZZZ.ZZZ, we look at the 
relationship between the SNES version's text format and the PS1 version.
The PS1 version is a port of the SNES version, so the text encoding is 
likely similar or identical.

The SNES SMT2 uses a custom 2-byte text encoding where:
- Byte 1 = Row in the font table (0-based)  
- Byte 2 = Column in the font table (0-based)
- Special control codes for newlines, pauses, etc.

For PS1, the text is compressed inside ZZZZZZZZ.ZZZ and decompressed into
RAM by the function at 0x800CE000, which uses a ring buffer with 4096-byte
window (LZSS-style compression).
"""

import struct
from pathlib import Path
import sys
import json


class SMT2TextAnalyzer:
    """Analyzes SMT2 PS1 text data."""
    
    def __init__(self, workspace_dir: str = "workspace/1_extracted/files"):
        self.workspace = Path(workspace_dir)
        self.exe_path = self.workspace / "SLPM_869.24"
        self.zzz_path = self.workspace / "ZZZZZZZZ.ZZZ"
        self.exe_data = self.exe_path.read_bytes()
        
        # RAM base for EXE: file offset 0x800 → RAM 0x80010000
        self.exe_file_offset = 0x800
        self.ram_base = 0x80010000
        
        # Build font table
        self.font_table = self._build_font_table()
        
    def file_to_ram(self, file_offset: int) -> int:
        """Convert EXE file offset to RAM address."""
        return self.ram_base + (file_offset - self.exe_file_offset)
    
    def ram_to_file(self, ram_addr: int) -> int:
        """Convert RAM address to EXE file offset."""
        return (ram_addr - self.ram_base) + self.exe_file_offset
    
    def _build_font_table(self) -> list:
        """Build the complete font table from the EXE."""
        table_start = 0x0D79EC
        chars = []
        i = table_start
        
        while i < table_start + 500 and i + 1 < len(self.exe_data):
            b = self.exe_data[i]
            
            if b == 0:
                i += 1
                continue
            
            if (0x81 <= b <= 0x9F or 0xE0 <= b <= 0xEF) and i + 1 < len(self.exe_data):
                b2 = self.exe_data[i + 1]
                try:
                    char = bytes([b, b2]).decode('shift_jis')
                    chars.append(char)
                except:
                    chars.append('?')
                i += 2
            else:
                break
        
        return chars
    
    def analyze_zzz_structure(self):
        """Analyze ZZZZZZZZ.ZZZ for internal structure."""
        zzz = self.zzz_path.read_bytes()
        print(f"ZZZZZZZZ.ZZZ: {len(zzz):,} bytes ({len(zzz)/1024/1024:.1f} MB)")
        
        # Check if the file has internal sector boundaries (2048 bytes = 1 CD sector)
        # PS1 games often organize data by CD sectors
        sector_size = 2048
        n_sectors = len(zzz) // sector_size
        print(f"Sectors (2048B): {n_sectors:,}")
        
        # Look for sector headers or patterns every 2048 bytes
        print("\nChecking sector alignment patterns:")
        patterns = {}
        for i in range(0, min(n_sectors, 1000)):
            sector_start = i * sector_size
            first_bytes = tuple(zzz[sector_start:sector_start+4])
            if first_bytes not in patterns:
                patterns[first_bytes] = 0
            patterns[first_bytes] += 1
        
        print(f"  Unique sector start patterns: {len(patterns)}")
        for pattern, count in sorted(patterns.items(), key=lambda x: -x[1])[:10]:
            hex_str = ' '.join(f'{b:02X}' for b in pattern)
            print(f"    {hex_str}: {count} sectors")
    
    def find_text_in_zzz(self):
        """Search for text data within ZZZZZZZZ.ZZZ using known strings."""
        zzz = self.zzz_path.read_bytes()
        
        # Search for known Shift-JIS strings that MUST be in the game
        test_strings = [
            ("ホーク", "Hawk (character name)"),
            ("アレフ", "Aleph (character name)"),
            ("メシア", "Messiah"),
            ("ガイア", "Gaia"),
            ("東京", "Tokyo"),
            ("悪魔", "Akuma (demon)"),
            ("合体", "Gattai (fusion)"),
            ("仲魔", "Nakama (ally demon)"),
            ("命", "Life/inochi"),
            ("力", "Power/chikara"),
        ]
        
        print("\n=== Searching ZZZZZZZZ.ZZZ for known strings ===")
        for text, description in test_strings:
            encoded = text.encode('shift_jis')
            count = zzz.count(encoded)
            if count > 0:
                idx = zzz.find(encoded)
                sector = idx // 2048
                print(f"  {description} ({text}): {count} hits, first at 0x{idx:08X} (sector {sector})")
            else:
                print(f"  {description} ({text}): NOT FOUND")
    
    def try_lzss_decompress(self, data: bytes, max_output: int = 65536) -> bytes:
        """Attempt LZSS decompression with 4096-byte ring buffer."""
        output = bytearray()
        ring = bytearray(4096)
        ring_pos = 0xFEE  # Standard LZSS init position
        
        i = 0
        while i < len(data) and len(output) < max_output:
            flags = data[i]
            i += 1
            
            for bit in range(8):
                if i >= len(data) or len(output) >= max_output:
                    break
                
                if flags & (1 << bit):
                    # Literal byte
                    b = data[i]
                    i += 1
                    output.append(b)
                    ring[ring_pos] = b
                    ring_pos = (ring_pos + 1) & 0xFFF
                else:
                    # Reference: 2 bytes encode (offset, length)
                    if i + 1 >= len(data):
                        break
                    b1 = data[i]
                    b2 = data[i + 1]
                    i += 2
                    
                    offset = b1 | ((b2 & 0xF0) << 4)
                    length = (b2 & 0x0F) + 3
                    
                    for j in range(length):
                        b = ring[(offset + j) & 0xFFF]
                        output.append(b)
                        ring[ring_pos] = b
                        ring_pos = (ring_pos + 1) & 0xFFF
        
        return bytes(output)
    
    def try_decompress_zzz_blocks(self):
        """Try LZSS decompression at various offsets in ZZZZZZZZ.ZZZ."""
        zzz = self.zzz_path.read_bytes()
        
        print("\n=== Attempting LZSS decompression at various offsets ===")
        
        # Try every sector boundary for first few MB
        for sector_offset in range(0, min(len(zzz), 512 * 2048), 2048):
            try:
                decompressed = self.try_lzss_decompress(
                    zzz[sector_offset:sector_offset + 8192], 
                    max_output=4096
                )
                
                # Check if decompressed data contains Shift-JIS text
                sjis_count = 0
                for j in range(len(decompressed) - 1):
                    b1 = decompressed[j]
                    if (0x81 <= b1 <= 0x9F or 0xE0 <= b1 <= 0xEF):
                        b2 = decompressed[j + 1]
                        if 0x40 <= b2 <= 0xFC and b2 != 0x7F:
                            sjis_count += 1
                
                if sjis_count > 20:
                    # Try to decode
                    try:
                        text = decompressed.decode('shift_jis', errors='replace')
                        printable = ''.join(c if c.isprintable() else '·' for c in text[:80])
                        print(f"  Sector {sector_offset//2048}: {sjis_count} SJIS chars -> {printable}")
                    except:
                        print(f"  Sector {sector_offset//2048}: {sjis_count} SJIS chars (decode failed)")
            except Exception as e:
                pass
    
    def analyze_all_files(self):
        """Analyze all files on the disc for text content."""
        print("\n=== File sizes and text content ===")
        for fpath in sorted(self.workspace.rglob('*')):
            if fpath.is_dir() or fpath.name == 'ZZZZZZZZ.ZZZ':
                continue
            data = fpath.read_bytes()
            
            # Count SJIS chars
            sjis_count = 0
            for j in range(len(data) - 1):
                b1 = data[j]
                if (0x81 <= b1 <= 0x9F or 0xE0 <= b1 <= 0xEF):
                    b2 = data[j + 1]
                    if 0x40 <= b2 <= 0xFC and b2 != 0x7F:
                        sjis_count += 1
            
            rel = fpath.relative_to(self.workspace)
            print(f"  {str(rel):30s}  {len(data):>10,}B  SJIS: {sjis_count:>5}")


if __name__ == "__main__":
    analyzer = SMT2TextAnalyzer()
    
    print(f"Font table: {len(analyzer.font_table)} characters")
    print(f"First 20: {''.join(analyzer.font_table[:20])}")
    print()
    
    analyzer.find_text_in_zzz()
    analyzer.analyze_zzz_structure()
    analyzer.try_decompress_zzz_blocks()
