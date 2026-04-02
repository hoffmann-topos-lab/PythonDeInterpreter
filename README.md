# Python Deinterpreter

A Python bytecode decompiler for CPython 3.12 (`.pyc`) and MicroPython (`.mpy`) files with a PySide6 GUI. Reconstructs approximate source code through a multi-stage pipeline: disassembly, CFG construction, stack simulation, pattern detection, AST recovery, and code generation. Includes native disassembly for ARM Thumb-2, x86/x64, Xtensa, and RISC-V architectures.

## Requirements

- **Python 3.12** — the decompiler engine relies on Python 3.12's `dis` and `marshal` modules
- **PySide6** — required for the graphical interface
- **mpy-cross** *(optional)* — only needed if you want to compile `.mpy` test files yourself

### Setup

```bash
# Create a virtual environment with Python 3.12
python3.12 -m venv venv

# Install PySide6
venv/bin/pip install PySide6

# (Optional) Install mpy-cross for compiling MicroPython test files
venv/bin/pip install mpy-cross
```

## Supported Formats

| Format | Version | Extension |
|--------|---------|-----------|
| CPython bytecode | 3.12 | `.pyc` |
| MicroPython bytecode | v6.x (mpy-cross v1.27) | `.mpy` |

### Native Code Architectures (`.mpy` only)

Functions compiled with `@micropython.native` or `@micropython.viper` are disassembled into readable assembly. Supported architectures:

- **x86 / x64**
- **ARM Thumb / Thumb-2** (armv6m, armv7m, armv7em, armv7emsp, armv7emdp)
- **Xtensa** (ESP8266 CALL0 ABI, ESP32 windowed ABI)
- **RISC-V** (RV32IMC / RV64IMC)

## Usage

### Graphical Interface

Launch the GUI to open, inspect, and navigate decompiled bytecode:

```bash
venv/bin/python main.py
```

The interface has three panels:

1. **Left panel** — lists strings, functions, constants, and exception handlers found in the bytecode
2. **Center panel** — displays the raw bytecode disassembly
3. **Right panel** — shows the recovered Python source code

Additional GUI features:
- **Annotations** — rename variables/functions and add comments, saved alongside the binary as `.annotations.json`
- **CFG Viewer** — visualize the control flow graph of any function
- **Diff View** — compare decompilations of two files side by side
- **Statistics** — opcode distribution, import list, and general metrics
- **Python Console** — interactive console with access to the current session's data

### Command-Line Interface (Pipeline Stages)

Inspect individual pipeline stages for debugging and analysis:

#### CPython `.pyc`

```bash
python3.12 Decompiler/debug_stages.py <file.pyc> --stage <stage> [--debug]
```

Available stages:

| Stage | Description |
|-------|-------------|
| `dis` | Raw `dis` module output for each code object |
| `parse` | Parsed instruction list with jump targets |
| `blocks` | Basic blocks (leader detection) |
| `cfg` | Control flow graph (edges and successors) |
| `stack` | Stack simulation results (expressions and statements per block) |
| `patterns` | High-level pattern detection (if/loop/try-except) |
| `recovered_ast` | Recovered AST structure |
| `gen_code` | Final recovered Python source code |

#### MicroPython `.mpy`

```bash
python3.12 MicroPython/mpy_debug_stages.py <file.mpy> --stage <stage> [--debug]
```

Available stages:

| Stage | Description |
|-------|-------------|
| `dis` | Hex dump of raw bytecode bytes |
| `parse` | Decoded MicroPython instructions (vuint encoding) |
| `blocks` | Basic blocks |
| `cfg` | Control flow graph |
| `stack` | Stack simulation results |
| `patterns` | High-level pattern detection |
| `native_asm` | Native code disassembly (`@micropython.native`/`@micropython.viper` functions) |
| `gen_code` | Final recovered Python source code |

> **Tip:** `debug_stages.py` auto-detects `.mpy` files and delegates to the MicroPython pipeline, so you can also use `Decompiler/debug_stages.py <file.mpy> --stage <stage>`.

### Engine (Full Pipeline)

Run the complete decompilation pipeline directly, outputting all sections to stdout:

```bash
# CPython
cd Decompiler
python3.12 engine.py <file.pyc>

# MicroPython (run from project root)
python3.12 MicroPython/mpy_engine.py <file.mpy>
```

Output is divided into sections separated by markers:
- `===== BYTECODE =====` — disassembled bytecode
- `===== BYTECODE_META =====` — metadata (function names, types, offsets)
- `===== RECOVERED =====` — recovered Python source code
