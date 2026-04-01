"""
Phase 6 — ISO 9660 Repacking.

Wraps `mkpsxiso` to rebuild a PSX .bin/.cue image from the modified
files and the XML layout descriptor produced during extraction.
"""

from __future__ import annotations

import logging
import subprocess
import shutil
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def repack(
    layout_xml: Path,
    output_bin: Path,
    output_cue: Optional[Path] = None,
) -> Path:
    """
    Rebuild a PSX .bin image from the extraction layout XML and modified files.

    mkpsxiso automatically:
      - Reconstructs the ISO 9660 directory structure
      - Calculates EDC and ECC checksums for every sector
      - Produces a CUE sheet alongside the BIN

    Args:
        layout_xml: Path to the layout.xml produced by dumpsxiso.
        output_bin: Desired path for the output .bin file.
        output_cue: Optional path for the .cue file. Defaults to output_bin with .cue extension.

    Returns:
        Path to the produced .bin file.

    Raises:
        FileNotFoundError: If mkpsxiso is not in PATH or layout_xml missing.
        RuntimeError: If mkpsxiso fails.
    """
    if not shutil.which("mkpsxiso"):
        raise FileNotFoundError(
            "mkpsxiso not found in PATH. Install it into the conda environment:\n"
            "  See README.md → 'Installing External Tools'"
        )

    if not layout_xml.exists():
        raise FileNotFoundError(
            f"Layout XML not found: {layout_xml}\n"
            "This file is produced during extraction (Phase 1). "
            "Re-run extraction with dumpsxiso."
        )

    if output_cue is None:
        output_cue = output_bin.with_suffix(".cue")

    # Ensure output directory exists
    output_bin.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "mkpsxiso",
        str(layout_xml),
        "-o", str(output_bin),
        "-c", str(output_cue),
    ]

    logger.info("Running: %s", " ".join(cmd))

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"mkpsxiso failed (exit {result.returncode}):\n{result.stderr}"
        )

    # Validate output
    if not output_bin.exists() or output_bin.stat().st_size == 0:
        raise RuntimeError(
            f"mkpsxiso completed but output file is missing or empty: {output_bin}"
        )

    size_mb = output_bin.stat().st_size / (1024 * 1024)
    logger.info("Rebuilt image: %s (%.1f MB)", output_bin, size_mb)
    logger.info("CUE sheet: %s", output_cue)

    return output_bin
