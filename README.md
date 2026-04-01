# BabelBin

> **Turning Shift-JIS blobs into English binaries, one pointer at a time.**

[](https://www.python.org/downloads/)
[](https://ghidra-sre.org/)
[](https://www.unicorn-engine.org/)
[](https://opensource.org/licenses/MIT)

BabelBin is a zero-touch, AI-assisted reverse engineering pipeline designed to automate the translation of legacy PlayStation 1 (PSX) `.bin`/`.cue` CD-ROM images.

By wrapping the probabilistic nature of Large Language Models (LLMs) in a rigid, deterministic framework of MIPS assembly analysis, memory reallocation, and ISO 9660 sector rebuilding, BabelBin achieves a true **"Bin-In, Bin-Out"** localization workflow.

-----

## 🧠 The Architecture

Retro console localization is traditionally bottlenecked by proprietary compression, hidden pointer tables, and strict hardware memory limits. BabelBin bypasses manual hex-hunting by utilizing a six-stage automated pipeline:

1.  **Ingestion & Entropy Mapping (`pycdlib`)**
      * Mounts the Mode 2 / Form 1 & 2 `.bin` image and extracts the ISO 9660 file system.
      * Scans the extracted executable (`SLPS_XXX.XX`) and archives for high-density Shift-JIS clusters.
      * Performs **Shannon Entropy** calculations to isolate highly compressed data blocks without relying on file extensions or magic bytes.
2.  **Heuristic Pointer Discovery (`Ghidra Headless`)**
      * Passes the primary executable to a headless Ghidra instance equipped with custom MIPS R3000A scripts.
      * Maps XREFs (Cross-References) backward from discovered Shift-JIS arrays to their exact 32-bit memory pointers.
3.  **Compression Bypass via Native Re-execution (`Unicorn Engine`)**
      * Rather than writing custom Python decompressors for bespoke 90s algorithms, BabelBin uses the Unicorn Engine to emulate the PS1 CPU.
      * It rips the game's native compression routines directly from the executable, loads them into virtual memory, and forces the game's own code to compress the new English text.
4.  **Constraint-Bound LLM Translation**
      * Feeds text arrays to a high-context LLM API with strict conversational context.
      * Enforces absolute byte-length limits. If the translated English string exceeds the original Japanese byte count, the orchestrator rejects the output and prompts the LLM to abbreviate.
5.  **Code Cave Reallocation & VWF Injection**
      * When English text exceeds the physical constraints of the original memory block, the orchestrator locates "dead space" (code caves) within the executable.
      * Injects the expanded text and automatically rewrites the original MIPS pointer table.
      * Injects a pre-compiled **Variable Width Font (VWF)** assembly hook to override the game's default 16x16 fixed-width rendering.
6.  **Repacking & Cryptographic Checksums (`mkpsxiso`)**
      * Rebuilds the translated assets into a fresh ISO 9660 directory structure.
      * Recalculates all EDC and ECC checksums for every modified CD sector, outputting a fully bootable `.bin`.

-----

## 📂 Repository Structure

Because this application bridges Python orchestration, Java-based Ghidra scripts, MIPS assembly payloads, and temporary binary workspaces, the structure isolates probabilistic AI components from deterministic binary math.

```text
BabelBin/
├── .env.example                # Template for API keys and Ghidra paths
├── .gitignore                  # Ignores /workspace, .bin, .cue, and large dumps
├── README.md                   # This document
├── requirements.txt            # Python dependencies (pycdlib, capstone, unicorn, openai)
├── babelbin.py                 # The main CLI entry point (The Orchestrator)
│
├── config/
│   ├── default.yaml            # Default pipeline settings (LLM temp, retry limits)
│   └── game_profiles/          # Heuristic tweaks for specific engines (e.g., SMT2.yaml)
│
├── src/
│   ├── __init__.py
│   ├── pipeline.py             # The state machine managing the 6-stage process
│   │
│   ├── iso/                    # Phase 1 & 6: File System
│   │   ├── extractor.py        # Wraps pycdlib to unpack ISO 9660
│   │   ├── repacker.py         # Wraps mkpsxiso to rebuild the image
│   │   └── ecc_edc.py          # Cryptographic sector checksum recalculator
│   │
│   ├── analysis/               # Phase 2: Binary Analysis
│   │   ├── entropy.py          # Shannon entropy calculator for finding compressed data
│   │   └── ghidra_bridge.py    # Python wrapper to call Ghidra Headless asynchronously
│   │
│   ├── emu/                    # Phase 3: Native Re-execution
│   │   ├── unicorn_psx.py      # MIPS R3000A emulator setup via Unicorn Engine
│   │   └── decompress.py       # Hooks to run native compression routines in virtual RAM
│   │
│   ├── llm/                    # Phase 4: Translation & Constraints
│   │   ├── engine.py           # API calls (OpenAI/Anthropic)
│   │   ├── prompts.py          # Strict context and byte-constraint system prompts
│   │   └── validator.py        # The firewall rejecting LLM output if it exceeds byte limits
│   │
│   └── patcher/                # Phase 5: Reallocation & Injection
│       ├── memory_map.py       # Tracks free space ("code caves") in the executable
│       ├── pointer_math.py     # Calculates new 32-bit offsets for the expanded text
│       └── injector.py         # Writes the new text, updated pointers, and VWF hooks
│
├── ghidra_scripts/             # Executed *inside* Ghidra, not by the main Python app
│   ├── FindShiftJIS.java       # Scans binaries for Japanese encoding arrays
│   └── TracePointers.java      # Follows XREFs backward to map the pointer table
│
├── asm/                        # Raw MIPS R3000A payloads
│   ├── vwf_hook.s              # Assembly source for Variable Width Font rendering
│   └── vwf_hook.bin            # Pre-compiled binary ready for injection
│
├── tests/                      # Unit tests for deterministic logic
│   ├── test_ecc.py
│   ├── test_pointer_math.py
│   └── test_entropy.py
│
└── workspace/                  # (GIT IGNORED) Temporary working directory
    ├── 1_extracted/            # Raw files dumped from the input .bin
    ├── 2_analysis/             # The JSON pointer maps exported by Ghidra
    ├── 3_translated/           # The intermediate English text files
    └── 4_patched/              # Modified executables waiting to be repacked
```

-----

## 🚀 Installation & Usage

### Prerequisites

  * [Conda](https://docs.conda.io/en/latest/) (Anaconda or Miniconda)
  * [Ghidra 11.0+](https://ghidra-sre.org/) (installed via Homebrew or manually)
  * A valid OpenAI or Anthropic API key

### Setup

```bash
git clone https://github.com/yourusername/BabelBin.git
cd BabelBin

# Create the conda environment (includes Python 3.11, Java 21+, and all dependencies)
conda env create -f environment.yml
conda activate babelbin
```

### Installing External Tools

**Ghidra** (via Homebrew on macOS):

```bash
brew install ghidra
```

**mkpsxiso** (built from source — the binaries are placed inside the conda env):

```bash
git clone --recurse-submodules https://github.com/Lameguy64/mkpsxiso.git /tmp/mkpsxiso
cd /tmp/mkpsxiso
cmake --preset release
cmake --build --preset release

# Copy into your conda environment's bin (no sudo required)
cp build/Release/mkpsxiso build/Release/dumpsxiso "$CONDA_PREFIX/bin/"
```

### Environment Variables

Create a `.env` file in the root directory (see `.env.example`):

```ini
OPENAI_API_KEY=your_openai_api_key_here
# Or, for Anthropic:
# ANTHROPIC_API_KEY=your_anthropic_api_key_here

GHIDRA_HEADLESS_PATH=/path/to/ghidra/support/analyzeHeadless
```

### Basic CLI Usage

```bash
conda activate babelbin
python babelbin.py --input /path/to/game_JP.bin --output /path/to/game_EN.bin --model gpt-4o
```

### Advanced Flags

  * `--complex-realloc`: Forces the engine to use code caves for all text, bypassing the LLM byte-length retry loop.
  * `--dump-only`: Stops the pipeline after Phase 2, exporting the mapped JSON and Ghidra project for manual inspection.
  * `--vwf-hook <address>`: Manually define the memory address for the VWF assembly injection if the heuristic engine fails.

-----

## 🔬 Scientific Foundations & Citations

The BabelBin architecture synthesizes the last decade of research in cybersecurity, malware analysis, and machine learning, applying vulnerability discovery techniques to retro game localization.

1.  **Entropy Mapping for Compression Detection:**
      * Lyda, R., & Hamrock, J. (2007). *"Using Entropy Analysis to Find Encrypted and Packed Malware."* IEEE Security & Privacy, 5(2), 40-45.
      * *Application:* Slicing out headerless, highly compressed data blocks from the game's executable based on statistical noise limits.
2.  **Symbolic Execution & Pointer Math:**
      * Shoshitaishvili, Y., et al. (2016). *"SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis."* IEEE Symposium on Security and Privacy (S\&P).
      * *Application:* Utilizing algebraic modeling of MIPS assembly to automate the tracing of cross-references (XREFs) and map the pointer tables.
3.  **ML-Driven Assembly NLP:**
      * Li, X., et al. (2021). *"PalmTree: Learning an Assembly Language Model for Instruction Embedding."* ACM SIGSAC Conference on Computer and Communications Security (CCS).
      * *Application:* Classifying unknown compression loops dynamically by treating MIPS instruction sequences as a semantic language.
4.  **Native Re-execution (Dynamic Instrumentation):**
      * Quynh, N. A., & Vu, D. (2015). *"Unicorn: Next Generation CPU Emulator Framework."* Presented at Black Hat USA.
      * *Application:* Safely emulating the PS1 CPU inside a Python subprocess to force the game's native code to compress the injected English text.
5.  **Constraint-Based LLM Generation:**
      * Poesia, G., et al. (2022). *"Synchromesh: Reliable Code Generation from Pre-trained Language Models."* International Conference on Learning Representations (ICLR).
      * *Application:* Enforcing strict 16-bit and 32-bit width parameters onto the LLM output to prevent memory corruption during the translation phase.

-----

## ⚠️ Compatibility & Disclaimer

BabelBin's heuristic engine targets text-heavy and mechanically complex titles (e.g., *Dragon Quest VII*, *Shin Megami Tensei*, *Chrono Trigger*). Games utilizing highly custom streaming file systems (e.g., certain Squaresoft multiplexed `.STR` files) may require manual file extraction before running the pipeline.

**On Non-Determinism:** BabelBin is a hybrid system. While binary extraction, pointer mathematics, and ISO rebuilding are mathematically *deterministic*, the LLM translation phase is *probabilistic*. Running the pipeline on the same `.bin` twice may result in slightly different English phrasing. The Python orchestrator (`validator.py`) exists specifically to cage this non-determinism, ensuring that regardless of the AI's output, the resulting binary remains mathematically valid and bootable.
