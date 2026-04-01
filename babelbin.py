#!/usr/bin/env python3
"""
BabelBin CLI Entry Point.

Usage:
  python babelbin.py --input <game.bin> --output <translated.bin>
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
import dotenv
import yaml
from rich.logging import RichHandler

from src.pipeline import Pipeline


def setup_logging() -> None:
    """Configure structured console logging via rich."""
    logging.basicConfig(
        level="INFO",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)]
    )


def load_config(profile_path: Path | None = None) -> dict:
    """Load default config and override with game profile if provided."""
    config_dir = Path("config")
    default_path = config_dir / "default.yaml"
    
    if not default_path.exists():
        raise FileNotFoundError(f"Missing default config: {default_path}")
        
    with open(default_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
        
    if profile_path:
        if not profile_path.exists():
            raise FileNotFoundError(f"Missing game profile: {profile_path}")
        with open(profile_path, "r", encoding="utf-8") as f:
            profile = yaml.safe_load(f)
            # Simple top-level dictionary merge
            for key, value in profile.items():
                if isinstance(value, dict) and isinstance(config.get(key), dict):
                    config[key].update(value)
                else:
                    config[key] = value
                    
    return config


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option(
    "--input",
    "-i",
    "input_bin",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to the original PSX .bin / .iso file",
)
@click.option(
    "--output",
    "-o",
    "output_bin",
    type=click.Path(path_type=Path),
    required=True,
    help="Path for the newly generated output .bin file",
)
@click.option(
    "--profile",
    "-p",
    type=click.Path(exists=True, path_type=Path),
    help="Path to a game-specific YAML profile (e.g., config/game_profiles/SMT2.yaml)",
)
@click.option(
    "--model",
    "-m",
    default="gpt-4o",
    show_default=True,
    help="LLM model to use for translation",
)
@click.option(
    "--complex-realloc",
    is_flag=True,
    help="Force all English text into code caves, bypassing the byte-length limit loop",
)
@click.option(
    "--dump-only",
    is_flag=True,
    help="Stop after extraction and analysis (Phases 1-2). Output JSON and Ghidra project.",
)
@click.option(
    "--vwf-hook",
    type=str,
    help="Manually override the VWF injection hex address (e.g., 0x80014B20)",
)
def cli(
    input_bin: Path,
    output_bin: Path,
    profile: Path | None,
    model: str,
    complex_realloc: bool,
    dump_only: bool,
    vwf_hook: str | None,
) -> None:
    """
    BabelBin: AI-Assisted PS1 Reverse Engineering Pipeline.
    
    Translates Shift-JIS blobs into English binaries, one pointer at a time.
    """
    setup_logging()
    logger = logging.getLogger("babelbin")
    
    # Load environment variables (.env)
    dotenv.load_dotenv()
    
    # Check for required tools
    import shutil
    if not shutil.which("analyzeHeadless") and not dotenv.get_key(".env", "GHIDRA_HEADLESS_PATH"):
         logger.warning("Ghidra analyzeHeadless not found. Ensure it is installed and the path is set in .env")

    # Load configuration
    try:
        config = load_config(profile)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)
        
    # Apply CLI overrides
    if model:
        config["llm"]["model"] = model
    if vwf_hook:
        try:
            config["vwf"]["hook_address"] = int(vwf_hook, 16)
        except ValueError:
            logger.error(f"Invalid hex address for --vwf-hook: {vwf_hook}")
            sys.exit(1)

    logger.info("Configuration loaded out of %s", profile.name if profile else "default.yaml")

    # Build and run the pipeline
    pipeline = Pipeline(config)
    
    try:
        pipeline.run(
            input_bin=input_bin,
            output_bin=output_bin,
            force_caves=complex_realloc,
            dump_only=dump_only,
        )
    except Exception as e:
        logger.exception("Pipeline failed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    cli()
