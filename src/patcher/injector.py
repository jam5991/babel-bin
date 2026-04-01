"""
Phase 5c — Binary Injector.

Writes the translated English text sequences into the game binary, updates
all related pointers to reference the new locations, and injects the
Variable Width Font (VWF) rendering hook.
"""

from __future__ import annotations

import logging
from pathlib import Path

from src.analysis.ghidra_bridge import PointerMap
from src.iso.extractor import PSXExecutable
from src.patcher.memory_map import MemoryMap
from src.patcher.pointer_math import ram_to_file_offset, write_direct_pointer, write_split_pointer

logger = logging.getLogger(__name__)


class Injector:
    """
    applies translated text and pointer updates to the game executable.
    """

    def __init__(self, exe: PSXExecutable, data: bytearray, memory_map: MemoryMap):
        self.exe = exe
        self.data = data
        self.memory_map = memory_map

    def inject_text(
        self,
        translations: list[tuple[int, bytes, int]],
        pointer_map: PointerMap,
        force_caves: bool = False
    ) -> None:
        """
        Inject translated text and update all references.

        Args:
            translations: List of (original_ram_address, translated_bytes, original_length).
            pointer_map: Ghidra pointer analysis containing XREFs.
            force_caves: If True, allocate *all* English text in code caves,
                         bypassing in-place replacement.
        """
        for orig_addr, eng_bytes, orig_length in translations:
            new_addr = orig_addr
            
            eng_len = len(eng_bytes)

            # Determine where to write the text
            if force_caves or eng_len > orig_length:
                # Need to relocate completely
                new_addr = self.memory_map.allocate(eng_len, alignment=1)
                if new_addr is None:
                    raise RuntimeError(f"Failed to allocate {eng_len} bytes for translated text")
                    
                target_offset = ram_to_file_offset(new_addr, self.exe)
                logger.debug("Relocated text from 0x%08X to 0x%08X", orig_addr, new_addr)
            else:
                # It fits in the original location
                target_offset = ram_to_file_offset(orig_addr, self.exe)

            # Write the text
            self.data[target_offset:target_offset + eng_len] = eng_bytes
            
            # Pad with nulls if we overwrote in-place and the new text is shorter
            if new_addr == orig_addr and eng_len < orig_length:
                pad_len = orig_length - eng_len
                self.data[target_offset+eng_len:target_offset+orig_length] = b"\x00" * pad_len

            # Update pointers if we relocated
            if new_addr != orig_addr:
                self._update_pointers(orig_addr, new_addr, pointer_map)

    def _update_pointers(
        self,
        old_target: int,
        new_target: int,
        pointer_map: PointerMap
    ) -> None:
        """Find and update all pointers targeting this text."""
        updates_made = 0
        
        # Look for table entries pointing to the old address
        for entry in pointer_map.pointer_entries:
            if entry.target_address == old_target:
                if entry.instruction_type == "direct":
                    write_direct_pointer(self.data, entry.file_offset, new_target)
                    updates_made += 1
                elif entry.instruction_type in ("lui_addiu", "lui_ori"):
                    # We need the High instructions file offset, which we assume is entry.file_offset
                    # and the low instruction offset. In a real scenario, Ghidra output would need
                    # to specify both addresses. For this implementation, we assume they are adjacent
                    # (offset + 4). 
                    # This is a simplification for the pipeline's structure.
                    write_split_pointer(
                        self.data,
                        entry.file_offset,
                        entry.file_offset + 4,
                        new_target,
                        mode=entry.instruction_type
                    )
                    updates_made += 1

        if updates_made == 0:
            logger.warning("Allocated text at 0x%08X (was 0x%08X), but found 0 pointers to update!", new_target, old_target)
        else:
            logger.debug("Updated %d pointers for relocation 0x%08X -> 0x%08X", updates_made, old_target, new_target)

    def inject_vwf_hook(self, vwf_bin_path: Path, target_hook_addr: int | None = None) -> None:
        """
        Inject the Variable Width Font payload.
        
        This copies the pre-compiled MIPS hook into a code cave and
        overwrites the original font rendering call to jump to our hook.
        """
        if not vwf_bin_path.exists():
            logger.warning("VWF binary not found at %s. Skipping VWF injection.", vwf_bin_path)
            return

        vwf_bytes = vwf_bin_path.read_bytes()
        
        # Allocate space for the hook
        hook_addr = self.memory_map.allocate(len(vwf_bytes), alignment=4)
        if hook_addr is None:
            raise RuntimeError("Not enough free space to inject VWF hook.")
            
        hook_offset = ram_to_file_offset(hook_addr, self.exe)
        
        # Write the hook payload
        self.data[hook_offset:hook_offset+len(vwf_bytes)] = vwf_bytes
        logger.info("Injected VWF hook payload (length %d) at 0x%08X", len(vwf_bytes), hook_addr)

        if target_hook_addr:
            target_offset = ram_to_file_offset(target_hook_addr, self.exe)
            # Typical hook mechanism: write a J (Jump) instruction or JAL (Jump and Link)
            # JAL instruction encoding: opcode (000011) | target (26 bits)
            # MIPS jumps target = (addr >> 2) & 0x03FFFFFF
            jal_target = (hook_addr >> 2) & 0x03FFFFFF
            jal_instruction = 0x0C000000 | jal_target
            
            # Write the JAL instruction, overwriting the old rendering call
            write_direct_pointer(self.data, target_offset, jal_instruction)
            logger.info("Hooked rendering subroutine at 0x%08X to jump to 0x%08X", target_hook_addr, hook_addr)
        else:
            logger.warning("VWF target hook address not provided. Payload injected, but execution flow not hijacked.")
