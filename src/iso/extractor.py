"""
Phase 1 — ISO 9660 Extraction.

Wraps `dumpsxiso` (from the mkpsxiso toolchain) to extract a PSX .bin
image into its constituent files, producing an XML layout descriptor
that Phase 6 (repacker) uses to rebuild the image after patching.

Falls back to raw pycdlib extraction if dumpsxiso is unavailable.
"""

from __future__ import annotations

import logging
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────
PSX_EXE_MAGIC = b"PS-X EXE"
PSX_EXE_HEADER_SIZE = 2048


@dataclass
class PSXExecutable:
    """Parsed header of a PS-X EXE file."""

    path: Path
    initial_pc: int        # Program counter entry point
    initial_gp: int        # Global pointer
    ram_dest: int          # RAM address where the EXE is loaded
    file_size: int         # Size of the text segment (code + data)
    bss_start: int         # Uninitialized data region start
    bss_size: int          # Uninitialized data region size
    stack_addr: int        # Initial stack pointer


@dataclass
class ExtractionResult:
    """Output of the extraction phase."""

    output_dir: Path                     # Root of extracted files
    layout_xml: Optional[Path]           # mkpsxiso XML layout (None if pycdlib fallback)
    executable: Optional[PSXExecutable]  # The discovered PS-X EXE
    files: list[Path] = field(default_factory=list)  # All extracted files


def parse_psx_exe_header(exe_path: Path) -> PSXExecutable:
    """
    Parse the 2048-byte header of a PS-X EXE file.

    The header layout (little-endian):
        0x000 – 0x007  ASCII "PS-X EXE"
        0x010          Initial PC (uint32)
        0x014          Initial GP (uint32)
        0x018          RAM destination address (uint32)
        0x01C          File size / text size (uint32)
        0x028          BSS start (uint32)
        0x02C          BSS size (uint32)
        0x030          Initial SP (uint32)
    """
    data = exe_path.read_bytes()[:PSX_EXE_HEADER_SIZE]

    if data[:8] != PSX_EXE_MAGIC:
        raise ValueError(f"{exe_path.name} is not a valid PS-X EXE (missing magic bytes)")

    (initial_pc,) = struct.unpack_from("<I", data, 0x10)
    (initial_gp,) = struct.unpack_from("<I", data, 0x14)
    (ram_dest,) = struct.unpack_from("<I", data, 0x18)
    (file_size,) = struct.unpack_from("<I", data, 0x1C)
    (bss_start,) = struct.unpack_from("<I", data, 0x28)
    (bss_size,) = struct.unpack_from("<I", data, 0x2C)
    (stack_addr,) = struct.unpack_from("<I", data, 0x30)

    return PSXExecutable(
        path=exe_path,
        initial_pc=initial_pc,
        initial_gp=initial_gp,
        ram_dest=ram_dest,
        file_size=file_size,
        bss_start=bss_start,
        bss_size=bss_size,
        stack_addr=stack_addr,
    )


def _find_executable(extracted_dir: Path) -> Optional[PSXExecutable]:
    """Scan extracted files for the PS-X EXE by checking the magic bytes."""
    for f in sorted(extracted_dir.rglob("*")):
        if not f.is_file() or f.stat().st_size < PSX_EXE_HEADER_SIZE:
            continue
        try:
            header = f.read_bytes()[:8]
            if header == PSX_EXE_MAGIC:
                logger.info("Found PS-X executable: %s", f.name)
                return parse_psx_exe_header(f)
        except (PermissionError, OSError):
            continue
    return None


def extract_with_dumpsxiso(
    bin_path: Path,
    output_dir: Path,
) -> ExtractionResult:
    """
    Extract a PSX .bin image using dumpsxiso.

    Produces:
      - A directory of extracted files
      - An XML layout file for later rebuilding with mkpsxiso
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    layout_xml = output_dir / "layout.xml"
    files_dir = output_dir / "files"

    cmd = [
        "dumpsxiso",
        str(bin_path),
        "-x", str(files_dir),
        "-s", str(layout_xml),
    ]

    logger.info("Running: %s", " ".join(cmd))

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"dumpsxiso failed (exit {result.returncode}):\n{result.stderr}"
        )

    # Collect all extracted files
    extracted_files = sorted(f for f in files_dir.rglob("*") if f.is_file())
    logger.info("Extracted %d files to %s", len(extracted_files), files_dir)

    # Find the executable
    exe = _find_executable(files_dir)
    if exe:
        logger.info(
            "PS-X EXE: %s | RAM: 0x%08X | PC: 0x%08X",
            exe.path.name,
            exe.ram_dest,
            exe.initial_pc,
        )

    return ExtractionResult(
        output_dir=files_dir,
        layout_xml=layout_xml,
        executable=exe,
        files=extracted_files,
    )


def extract_with_pycdlib(
    bin_path: Path,
    output_dir: Path,
) -> ExtractionResult:
    """
    Fallback extraction using pycdlib for standard ISO 9660 images.

    Note: pycdlib does not handle raw Mode 2/2352 PSX .bin files directly.
    This is intended for pre-converted ISO images or data tracks.
    """
    import pycdlib
    from io import BytesIO

    output_dir.mkdir(parents=True, exist_ok=True)

    iso = pycdlib.PyCdlib()
    iso.open(str(bin_path))

    extracted_files = []

    for dirpath, _, filenames in iso.walk(iso_path="/"):
        for filename in filenames:
            iso_path = f"{dirpath}/{filename}" if dirpath != "/" else f"/{filename}"
            local_path = output_dir / filename

            buf = BytesIO()
            iso.get_file_from_iso_fp(buf, iso_path=iso_path)

            local_path.write_bytes(buf.getvalue())
            extracted_files.append(local_path)
            logger.debug("Extracted: %s (%d bytes)", filename, local_path.stat().st_size)

    iso.close()

    exe = _find_executable(output_dir)

    return ExtractionResult(
        output_dir=output_dir,
        layout_xml=None,
        executable=exe,
        files=sorted(extracted_files),
    )


def extract(
    bin_path: Path,
    output_dir: Path,
    force_pycdlib: bool = False,
) -> ExtractionResult:
    """
    Extract a PSX .bin image, preferring dumpsxiso over pycdlib.

    Args:
        bin_path: Path to the .bin CD-ROM image.
        output_dir: Directory to write extracted files into.
        force_pycdlib: Skip dumpsxiso and use pycdlib directly.

    Returns:
        ExtractionResult with paths and parsed EXE header.
    """
    if not bin_path.exists():
        raise FileNotFoundError(f"Input image not found: {bin_path}")

    if output_dir.exists():
        logger.warning("Cleaning existing extraction directory: %s", output_dir)
        shutil.rmtree(output_dir)

    if not force_pycdlib and shutil.which("dumpsxiso"):
        logger.info("Using dumpsxiso for extraction")
        return extract_with_dumpsxiso(bin_path, output_dir)
    else:
        if not force_pycdlib:
            logger.warning(
                "dumpsxiso not found in PATH — falling back to pycdlib. "
                "This may not work for raw PSX .bin images."
            )
        return extract_with_pycdlib(bin_path, output_dir)
