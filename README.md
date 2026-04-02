# PythonDeInterpreter
A Python bytecode decompiler for CPython 3.12 (.pyc) and MicroPython (.mpy) files with a PySide6 GUI. Reconstructs source code through a multi-stage pipeline: disassembly, CFG construction, stack simulation, pattern detection, AST recovery, and code generation. Includes native disassembly for ARM,  x86, Xtensa, and RISC-V.  
