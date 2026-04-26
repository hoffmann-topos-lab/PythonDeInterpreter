# Python Decompiler — MCP Server

Servidor MCP que expõe o decompilador (CPython 3.12 `.pyc` + MicroPython `.mpy`) como ferramentas chamáveis por um modelo LLM (Claude Desktop, Claude Code, ou qualquer cliente MCP).

## Instalação

Na raiz do projeto (`v1.1/`):

```bash
python3.12 -m venv venv
venv/bin/python -m pip install -r requirements.txt
```

O `requirements.txt` já inclui `mcp[cli]`.

## Rodar localmente (stdio)

```bash
venv/bin/python -m mcp_server.server
```

O server fala MCP por stdio; rodá-lo diretamente não é útil sem um cliente.

### Inspector (UI de debug)

```bash
venv/bin/python -m mcp.cli dev mcp_server/server.py
```

## Registrar no Claude Code / Claude Desktop

`~/.claude/settings.json` (user) ou `.claude/settings.json` (projeto):

```json
{
  "mcpServers": {
    "python-decompiler": {
      "command": "/ABS/CAMINHO/PARA/v1.1/venv/bin/python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/ABS/CAMINHO/PARA/v1.1"
    }
  }
}
```


## Catálogo de ferramentas (58)

| Categoria | Tools |
|-----------|-------|
| Arquivo / metadados | `detect_file_format`, `get_file_info`, `get_pyc_header`, `get_mpy_header`, `validate_file` |
| Pipeline completo | `decompile_file`, `decompile_to_source`, `get_bytecode_disassembly`, `get_engine_meta` |
| Estágios | `stage_dis`, `stage_parse`, `stage_blocks`, `stage_cfg`, `stage_stack`, `stage_patterns`, `stage_recovered_ast`, `stage_gen_code` |
| Code objects | `list_code_objects`, `list_code_object_names`, `get_code_object_metadata`, `get_co_consts`, `get_code_object_source`, `get_code_object_bytecode` |
| Análise | `list_constants`, `list_strings`, `list_imports`, `list_exception_handlers`, `list_functions`, `count_instructions`, `count_functions`, `get_file_stats`, `get_mpy_summary` |
| Busca / xref | `search_bytecode`, `search_recovered`, `find_xrefs`, `find_calls_to`, `find_string_references`, `find_opcode_usage` |
| Código nativo (`.mpy`) | `list_native_functions`, `detect_architecture`, `disassemble_native_function`, `dump_native_bytes`, `strip_native_prelude` |
| Anotações (renames/comentários) | `annotation_load`, `annotation_list_renames`, `annotation_add_rename`, `annotation_remove_rename`, `annotation_list_comments`, `annotation_add_comment`, `annotation_remove_comment`, `annotation_apply_to_source`, `annotation_clear` |
| Diff | `diff_recovered`, `diff_bytecode`, `diff_summary` |
| Samples / projeto | `list_sample_files`, `read_sample_source`, `get_project_info` |

## Arquitetura

```
mcp_server/
├── server.py        # FastMCP entry point
├── config.py        # limites, paths
├── cache.py         # cache por (path, mtime)
├── runner.py        # bridge para Decompiler/, MicroPython/, utils/
├── formats.py       # detecção .pyc / .mpy
├── pagination.py    # truncate/slice/paginate helpers
├── errors.py        # exceções tipadas
└── tools/
    ├── file_info.py
    ├── pipeline.py
    ├── stages.py
    ├── code_objects.py
    ├── analysis.py
    ├── search.py
    ├── native.py
    ├── annotations.py
    ├── diff.py
    └── samples.py
```

- `runner.py` reusa `Decompiler/engine_runner.run_engine` e `MicroPython/mpy_engine_runner.run_mpy_engine` para o pipeline ponta-a-ponta.
- Para estágios granulares, importa diretamente `disasm`, `stack_sim`, `patterns`, `utils/cfg`, `utils/ast_recover`, etc.
- Tudo que pode ser reaproveitado é cacheado por `(caminho, mtime, size)` — chamadas repetidas na mesma sessão não reexecutam o pipeline.

## Limites e paginação

Tools que retornam texto grande (disassembly, código recuperado) aceitam `offset` / `limit` ou aplicam `truncate_text` com marca `truncated: true`. Ajuste via `mcp_server/config.py`:

```python
MAX_TEXT_CHARS = 200_000   # limite padrão de caracteres por resposta
MAX_LIST_ITEMS = 500       # limite padrão de itens por lista
```
