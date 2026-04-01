"""
BabelBin Pipeline Orchestrator.

Ties together all 6 phases into a cohesive state machine:
1. ISO Extraction
2. Binary Analysis (Entropy + Ghidra)
3. Emulated Compression/Decompression
4. LLM Translation
5. Reallocation & Patching
6. Repacking
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from src.iso.extractor import extract, PSXExecutable
from src.iso.repacker import repack
from src.analysis.entropy import analyze_binary, EntropyRegion, TextRegion
from src.analysis.ghidra_bridge import run_ghidra_analysis, PointerMap
from src.emu.unicorn_psx import PSXEmulator
from src.emu.decompress import find_compression_routines
from src.llm.engine import TranslationEngine, TranslationRequest
from src.patcher.memory_map import MemoryMap
from src.patcher.injector import Injector

logger = logging.getLogger(__name__)


class Pipeline:
    """Manages the full reverse-engineering and translation lifecycle."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        
        # Determine paths
        ws_root = Path(config.get("workspace", {}).get("root", "workspace"))
        self.dirs = {
            "extract": ws_root / "1_extracted",
            "analysis": ws_root / "2_analysis",
            "translate": ws_root / "3_translated",
            "patch": ws_root / "4_patched",
        }
        
    def setup_workspace(self) -> None:
        """Create workspace directories."""
        for d in self.dirs.values():
            d.mkdir(parents=True, exist_ok=True)
            
    def run(
        self,
        input_bin: Path,
        output_bin: Path,
        force_caves: bool = False,
        dump_only: bool = False,
    ) -> None:
        """Execute the full pipeline."""
        
        self.setup_workspace()
        logger.info("Starting BabelBin pipeline for %s", input_bin)
        
        # --- PHASE 1: EXACT -----------------------------------------
        logger.info("\n=== PHASE 1: EXTRACTION ===")
        extract_result = extract(input_bin, self.dirs["extract"])
        
        if not extract_result.executable:
            raise RuntimeError("No PS-X executable found in the CD image.")
            
        exe = extract_result.executable
        exe_data = exe.path.read_bytes()
        
        # --- PHASE 2: ANALYZE ---------------------------------------
        logger.info("\n=== PHASE 2: BINARY ANALYSIS ===")
        
        # 2a. Entropy
        entropy_regions, text_clusters = analyze_binary(
            exe_data,
            window_size=self.config["entropy"]["window_size"],
            compressed_threshold=self.config["entropy"]["compressed_threshold"]
        )
        
        # 2b. Ghidra Headless
        pointer_map = run_ghidra_analysis(
            exe.path,
            self.dirs["analysis"],
            timeout=self.config["ghidra"]["timeout"]
        )
        
        if dump_only:
            logger.info("\n=== HALTING (--dump-only) ===")
            return
            
        # --- PHASE 3: EMULATE ---------------------------------------
        logger.info("\n=== PHASE 3: COMPRESSION ANALYSIS (EMULATION) ===")
        routines = find_compression_routines(exe_data, ram_base=exe.ram_dest)
        
        # (Emulation decompression logic would execute here on structured regions
        # identified by the entropy scanner. Skipped in standard mode if dealing
        # only with plaintext Shift-JIS clusters)
        
        # --- PHASE 4: TRANSLATE -------------------------------------
        logger.info("\n=== PHASE 4: LLM TRANSLATION ===")
        
        engine = TranslationEngine(
            provider=self.config["llm"]["provider"],
            model=self.config["llm"]["model"],
            temperature=self.config["llm"]["temperature"],
            max_retries=self.config["llm"]["max_retries"]
        )
        
        # Format strings for translation
        requests = []
        for text_ref in pointer_map.text_refs:
            req = TranslationRequest(
                source_text=text_ref.decoded_text,
                byte_limit=text_ref.length if not force_caves else 1024,
                glossary=self.config["llm"].get("glossary", {})
            )
            requests.append(req)
            
        logger.info("Translating %d strings...", len(requests))
        
        import json
        import dataclasses
        from src.llm.engine import TranslationResult
        
        cache_path = self.dirs["translate"] / "translations.json"
        results = []
        
        if cache_path.exists():
            logger.info("Loading cached translations from %s", cache_path)
            with open(cache_path, "r", encoding="utf-8") as f:
                cached_data = json.load(f)
                for item in cached_data:
                    results.append(TranslationResult(**item))
        else:
            logger.info("No cache found. Calling live LLM API...")
            results = engine.translate_batch(requests)
            
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump([dataclasses.asdict(r) for r in results], f, ensure_ascii=False, indent=2)
            logger.info("Saved %d translations to cache.", len(results))
        
        translated_payloads = []
        for ref, result in zip(pointer_map.text_refs, results):
            eng_str = result.translated_text if result.translated_text else f"Translated: {ref.decoded_text[:10]}"
            eng_bytes = eng_str.encode("ascii", errors="replace") + b"\x00"
            translated_payloads.append((ref.ram_address, eng_bytes, ref.length))

        # --- PHASE 5: PATCH & REALLOCATE ----------------------------
        logger.info("\n=== PHASE 5: CODE CAVE INJECTION ===")
        
        # Instantiate a mutable payload map so EOF expansion can dynamically patch the headers
        patched_data = bytearray(exe_data)
        
        memory_map = MemoryMap(
            exe, 
            patched_data, 
            min_cave_size=self.config["patching"]["min_cave_size"]
        )
        
        injector = Injector(exe, patched_data, memory_map)
        
        injector.inject_text(translated_payloads, pointer_map, force_caves)
        
        # Write patched executable to workspace
        patched_exe_path = self.dirs["patch"] / exe.path.name
        patched_exe_path.write_bytes(patched_data)
        logger.info("Saved patched executable: %s", patched_exe_path)
        
        # Copy patched executable back to extraction layout for repacking
        shutil.copy2(patched_exe_path, exe.path)
        
        # --- PHASE 6: REPACK ----------------------------------------
        logger.info("\n=== PHASE 6: ISO REPACKING ===")
        
        if extract_result.layout_xml:
            repack(extract_result.layout_xml, output_bin)
        else:
            logger.warning("No mkpsxiso layout.xml. Cannot repack (Fallback extraction was used).")
            
        logger.info("\n=== PIPELINE COMPLETE ===")
        logger.info("Output: %s", output_bin)

