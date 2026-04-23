from PySide6.QtCore import QThread, Signal
from Decompiler.engine_runner import run_engine


class EngineWorker(QThread):


    result = Signal(int, str, str, dict) 
    error = Signal(int, str)            

    def __init__(self, path: str, sid: int = -1, runner=None):
        super().__init__()
        self._path   = path
        self._sid    = sid
        self._runner = runner if runner is not None else run_engine

    def run(self):
        try:
            byte_txt, rec_txt, meta = self._runner(self._path)
            self.result.emit(self._sid, byte_txt, rec_txt, meta)
        except Exception as exc:
            self.error.emit(self._sid, str(exc))
