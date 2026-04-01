"""
Phase 3a — PS1 CPU Emulator (MIPS R3000A via Unicorn Engine).

Sets up a virtual PS1 memory environment and provides an interface to
execute isolated MIPS functions extracted from the game's executable.

Used primarily to run the game's native compression/decompression routines
rather than reimplementing them in Python.

Reference:
    Quynh, N. A., & Vu, D. (2015). "Unicorn: Next Generation CPU Emulator
    Framework." Presented at Black Hat USA.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from unicorn import (
    Uc, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_LITTLE_ENDIAN,
    UC_HOOK_INTR, UC_HOOK_CODE,
)
from unicorn.mips_const import (
    UC_MIPS_REG_PC, UC_MIPS_REG_SP, UC_MIPS_REG_RA,
    UC_MIPS_REG_GP, UC_MIPS_REG_V0, UC_MIPS_REG_V1,
    UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3,
    UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2,
    UC_MIPS_REG_AT, UC_MIPS_REG_ZERO,
)

logger = logging.getLogger(__name__)

# ── PS1 Memory Map Constants ────────────────────────────────
PSX_RAM_BASE = 0x80000000      # KSEG0 cached RAM
PSX_RAM_SIZE = 0x200000        # 2 MB
PSX_STACK_TOP = 0x801FFF00     # Default stack pointer
PSX_SCRATCH = 0x1F800000       # Scratchpad RAM (1 KB)
PSX_SCRATCH_SIZE = 0x400

# Sentinel address: functions returning here signal completion
_SENTINEL_ADDR = 0x80200000
_SENTINEL_SIZE = 0x1000

# Argument registers in order
_ARG_REGS = [UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3]


@dataclass
class EmulationResult:
    """Result of executing a function in the emulator."""
    return_value: int         # Value in $v0 after execution
    v1_value: int             # Value in $v1 (some functions return 64-bit via v0:v1)
    instructions_executed: int
    stopped_at: int           # PC value where execution stopped
    timed_out: bool           # True if max_instructions was reached


@dataclass
class BIOSHook:
    """A registered BIOS syscall hook."""
    function_id: int
    handler: Callable
    name: str


class PSXEmulator:
    """
    MIPS R3000A emulator wrapping Unicorn Engine for PS1 binary analysis.

    Provides:
        - PS1 memory layout (2MB RAM at KSEG0)
        - BIOS syscall interception
        - Function execution with argument passing
        - Memory read/write access
    """

    def __init__(self) -> None:
        self._mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN)
        self._instruction_count = 0
        self._bios_hooks: dict[int, BIOSHook] = {}

        # Map PS1 memory regions
        self._mu.mem_map(PSX_RAM_BASE, PSX_RAM_SIZE)       # Main RAM
        self._mu.mem_map(_SENTINEL_ADDR, _SENTINEL_SIZE)    # Return sentinel
        self._mu.mem_map(PSX_SCRATCH, PSX_SCRATCH_SIZE)     # Scratchpad

        # Write a `jr $ra; nop` at the sentinel (in case code falls through)
        self._mu.mem_write(_SENTINEL_ADDR, b"\x08\x00\xE0\x03\x00\x00\x00\x00")

        # Set up instruction counter hook
        self._mu.hook_add(UC_HOOK_CODE, self._hook_code)

        # Set up BIOS interrupt hook
        self._mu.hook_add(UC_HOOK_INTR, self._hook_interrupt)

        logger.info(
            "PSX emulator initialized: RAM 0x%08X–0x%08X, stack at 0x%08X",
            PSX_RAM_BASE, PSX_RAM_BASE + PSX_RAM_SIZE, PSX_STACK_TOP,
        )

    def _hook_code(self, mu: Uc, address: int, size: int, user_data: object) -> None:
        """Instruction execution hook for counting."""
        self._instruction_count += 1

    def _hook_interrupt(self, mu: Uc, intno: int, user_data: object) -> None:
        """
        BIOS syscall interception.

        PS1 BIOS calls use `syscall` (exception code 8) with the function
        table index in $t1 and sub-function in $t0.
        """
        if intno == 8:  # Syscall exception
            t1 = mu.reg_read(UC_MIPS_REG_T1)
            t0 = mu.reg_read(UC_MIPS_REG_T0)

            func_id = (t1 << 8) | t0

            hook = self._bios_hooks.get(func_id)
            if hook:
                logger.debug("BIOS call intercepted: %s (0x%04X)", hook.name, func_id)
                hook.handler(mu)
            else:
                logger.debug("Unhandled BIOS call: table=0x%02X func=0x%02X", t1, t0)
                # Default: return 0 and continue
                mu.reg_write(UC_MIPS_REG_V0, 0)

    def register_bios_hook(
        self,
        table: int,
        function: int,
        handler: Callable,
        name: str = "unnamed",
    ) -> None:
        """Register a Python handler for a PS1 BIOS syscall."""
        func_id = (table << 8) | function
        self._bios_hooks[func_id] = BIOSHook(
            function_id=func_id,
            handler=handler,
            name=name,
        )
        logger.debug("Registered BIOS hook: %s (table=0x%02X, func=0x%02X)", name, table, function)

    def load_executable(self, exe_data: bytes, ram_dest: int) -> None:
        """
        Load a PS-X executable's code segment into emulated RAM.

        Args:
            exe_data: Raw bytes of the executable (including 2048-byte header).
            ram_dest: RAM address where the code should be loaded (from EXE header).
        """
        # Skip the 2048-byte PS-X EXE header
        code = exe_data[2048:]

        # Ensure it fits in RAM
        offset = ram_dest - PSX_RAM_BASE
        if offset < 0 or offset + len(code) > PSX_RAM_SIZE:
            raise ValueError(
                f"Executable at 0x{ram_dest:08X} ({len(code)} bytes) "
                f"exceeds PS1 RAM bounds"
            )

        self._mu.mem_write(ram_dest, code)
        logger.info(
            "Loaded %d bytes at 0x%08X (RAM offset 0x%06X)",
            len(code), ram_dest, offset,
        )

    def load_data(self, address: int, data: bytes) -> None:
        """Write raw data to emulated memory."""
        self._mu.mem_write(address, data)

    def read_memory(self, address: int, size: int) -> bytes:
        """Read raw bytes from emulated memory."""
        return bytes(self._mu.mem_read(address, size))

    def write_u32(self, address: int, value: int) -> None:
        """Write a 32-bit little-endian value."""
        self._mu.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def read_u32(self, address: int) -> int:
        """Read a 32-bit little-endian value."""
        return struct.unpack("<I", bytes(self._mu.mem_read(address, 4)))[0]

    def execute_function(
        self,
        address: int,
        args: Optional[list[int]] = None,
        max_instructions: int = 1_000_000,
    ) -> EmulationResult:
        """
        Execute a MIPS function at the given RAM address.

        Sets up the stack, loads arguments into $a0–$a3, sets $ra to a
        sentinel address, and runs until the function returns (jumps to
        the sentinel) or max_instructions is reached.

        Args:
            address: RAM address of the function entry point.
            args: Up to 4 integer arguments (loaded into $a0–$a3).
            max_instructions: Safety limit to prevent infinite loops.

        Returns:
            EmulationResult with return value and execution stats.
        """
        args = args or []

        # Reset instruction counter
        self._instruction_count = 0

        # Set up registers
        self._mu.reg_write(UC_MIPS_REG_SP, PSX_STACK_TOP)
        self._mu.reg_write(UC_MIPS_REG_RA, _SENTINEL_ADDR)  # Return → sentinel

        # Load function arguments
        for i, arg in enumerate(args[:4]):
            self._mu.reg_write(_ARG_REGS[i], arg & 0xFFFFFFFF)

        # Execute
        timed_out = False
        try:
            self._mu.emu_start(
                address,
                _SENTINEL_ADDR,
                count=max_instructions,
            )
        except Exception as e:
            logger.warning("Emulation stopped: %s", e)
            timed_out = self._instruction_count >= max_instructions

        # Read results
        pc = self._mu.reg_read(UC_MIPS_REG_PC)
        v0 = self._mu.reg_read(UC_MIPS_REG_V0)
        v1 = self._mu.reg_read(UC_MIPS_REG_V1)

        result = EmulationResult(
            return_value=v0,
            v1_value=v1,
            instructions_executed=self._instruction_count,
            stopped_at=pc,
            timed_out=timed_out,
        )

        logger.debug(
            "Function 0x%08X returned: $v0=0x%08X, %d instructions, stopped at 0x%08X",
            address, v0, self._instruction_count, pc,
        )

        return result
