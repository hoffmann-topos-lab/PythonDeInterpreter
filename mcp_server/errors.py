class DecompilerError(Exception):
    pass


class FileFormatError(DecompilerError):
    pass


class CodeObjectNotFoundError(DecompilerError):
    pass


class UnsupportedOperationError(DecompilerError):
    pass
