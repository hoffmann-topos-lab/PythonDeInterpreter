from PySide6.QtCore import QThread, Signal
from Decompiler.engine_runner import run_engine


class EngineWorker(QThread):
    """Executa o runner de engine em thread separada para não bloquear a UI."""

    result = Signal(str, str, dict)  # (bytecode_txt, recovered_txt, meta)
    error = Signal(str)              # mensagem de erro

    def __init__(self, path: str, runner=None):
        super().__init__()
        self._path   = path
        self._runner = runner if runner is not None else run_engine

    def run(self):
        try:
            byte_txt, rec_txt, meta = self._runner(self._path)
            self.result.emit(byte_txt, rec_txt, meta)
        except Exception as exc:
            self.error.emit(str(exc))
