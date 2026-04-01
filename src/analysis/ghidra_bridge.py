"""
Phase 2b — Ghidra Headless Bridge.

Manages headless Ghidra invocations to run the FindShiftJIS.java and
TracePointers.java scripts against the game's executable binary.

Parses the JSON output to produce structured pointer maps linking
text offsets → pointer addresses → XREF chains.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TextReference:
    """A Shift-JIS text array discovered by Ghidra."""
    offset: int              # File offset of the text
    ram_address: int         # RAM address once loaded
    length: int              # Byte length
    decoded_text: str        # Decoded content (preview)
    xrefs: list[int] = field(default_factory=list)  # RAM addresses referencing this text


@dataclass
class PointerEntry:
    """A single pointer table entry mapping a pointer to its target text."""
    pointer_address: int     # RAM address of the pointer itself
    target_address: int      # RAM address the pointer points to
    instruction_type: str    # "lui_addiu", "lui_ori", "direct", etc.
    file_offset: int         # File offset of the pointer


@dataclass
class PointerMap:
    """Complete pointer analysis results from Ghidra."""
    text_refs: list[TextReference] = field(default_factory=list)
    pointer_entries: list[PointerEntry] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


def _get_ghidra_path() -> str:
    """Resolve the path to Ghidra's analyzeHeadless script."""
    # Check environment variable first
    env_path = os.environ.get("GHIDRA_HEADLESS_PATH", "")
    if env_path and Path(env_path).exists():
        return env_path

    # Check common Homebrew locations
    brew_paths = [
        "/opt/homebrew/Cellar/ghidra",
        "/usr/local/Cellar/ghidra",
    ]
    for brew_base in brew_paths:
        brew_path = Path(brew_base)
        if brew_path.exists():
            # Find the latest version
            versions = sorted(brew_path.iterdir(), reverse=True)
            for version_dir in versions:
                candidate = version_dir / "libexec" / "support" / "analyzeHeadless"
                if candidate.exists():
                    return str(candidate)

    raise FileNotFoundError(
        "Ghidra analyzeHeadless not found. Set GHIDRA_HEADLESS_PATH in your .env file.\n"
        "Example: GHIDRA_HEADLESS_PATH=/opt/homebrew/Cellar/ghidra/12.0.4/libexec/support/analyzeHeadless"
    )


def _get_scripts_dir() -> Path:
    """Locate the ghidra_scripts/ directory in the project root."""
    # Walk up from this file to find the project root
    current = Path(__file__).resolve()
    for parent in current.parents:
        scripts_dir = parent / "ghidra_scripts"
        if scripts_dir.is_dir():
            return scripts_dir

    raise FileNotFoundError(
        "ghidra_scripts/ directory not found. "
        "Ensure FindShiftJIS.java and TracePointers.java exist in the project root."
    )


def run_ghidra_analysis(
    binary_path: Path,
    output_dir: Path,
    timeout: int = 300,
    auto_analysis: bool = True,
) -> PointerMap:
    """
    Run Ghidra headless analysis with the BabelBin scripts.

    Executes:
        1. FindShiftJIS.java — scans for Shift-JIS text arrays
        2. TracePointers.java — traces XREFs backward to map pointer tables

    Args:
        binary_path: Path to the PS-X executable.
        output_dir: Directory for Ghidra project and JSON output.
        timeout: Maximum seconds for the analysis.
        auto_analysis: Whether to run Ghidra's auto-analysis first.

    Returns:
        PointerMap with all discovered text references and pointers.
    """
    analyze_headless = _get_ghidra_path()
    scripts_dir = _get_scripts_dir()

    output_dir.mkdir(parents=True, exist_ok=True)
    project_dir = output_dir / "ghidra_project"
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = "BabelBin_Analysis"

    # Build command
    cmd = [
        analyze_headless,
        str(project_dir),
        project_name,
        "-import", str(binary_path),
        "-scriptPath", str(scripts_dir),
        "-postScript", "FindShiftJIS.java", str(output_dir),
        "-postScript", "TracePointers.java", str(output_dir),
        "-overwrite",  # Overwrite existing project
    ]

    if not auto_analysis:
        cmd.append("-noanalysis")

    # Set processor to MIPS R3000 little-endian
    cmd.extend(["-processor", "MIPS:LE:32:default"])

    logger.info("Starting Ghidra headless analysis (timeout: %ds)...", timeout)
    logger.debug("Command: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            logger.error("Ghidra stderr: %s", result.stderr[-2000:] if result.stderr else "")
            raise RuntimeError(
                f"Ghidra analysis failed (exit {result.returncode}). "
                "Check the binary format and Ghidra installation."
            )

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Ghidra analysis timed out after {timeout}s. "
            "Try increasing the timeout in config/default.yaml."
        )

    # Parse results
    return _parse_ghidra_output(output_dir)


def _parse_ghidra_output(output_dir: Path) -> PointerMap:
    """Parse the JSON files produced by the Ghidra scripts."""
    pointer_map = PointerMap()

    # Parse text references
    text_refs_file = output_dir / "shift_jis_refs.json"
    if text_refs_file.exists():
        try:
            raw = json.loads(text_refs_file.read_text(encoding="utf-8"))
            for entry in raw:
                pointer_map.text_refs.append(TextReference(
                    offset=entry.get("offset", 0),
                    ram_address=entry.get("ram_address", 0),
                    length=entry.get("length", 0),
                    decoded_text=entry.get("decoded_text", ""),
                    xrefs=entry.get("xrefs", []),
                ))
            logger.info("Loaded %d text references from Ghidra", len(pointer_map.text_refs))
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to parse %s: %s", text_refs_file, e)
    else:
        logger.warning("No text references file found: %s", text_refs_file)

    # Parse pointer entries
    pointers_file = output_dir / "pointer_map.json"
    if pointers_file.exists():
        try:
            raw = json.loads(pointers_file.read_text(encoding="utf-8"))

            # Extract metadata
            pointer_map.metadata = raw.get("metadata", {})

            for entry in raw.get("pointers", []):
                pointer_map.pointer_entries.append(PointerEntry(
                    pointer_address=entry.get("pointer_address", 0),
                    target_address=entry.get("target_address", 0),
                    instruction_type=entry.get("instruction_type", "unknown"),
                    file_offset=entry.get("file_offset", 0),
                ))
            logger.info("Loaded %d pointer entries from Ghidra", len(pointer_map.pointer_entries))
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to parse %s: %s", pointers_file, e)
    else:
        logger.warning("No pointer map file found: %s", pointers_file)

    return pointer_map
