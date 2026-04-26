import os
from typing import Any, Callable

_cache: dict[tuple, Any] = {}


def _file_key(path: str) -> tuple[str, float, int]:
    st = os.stat(path)
    return (os.path.abspath(path), st.st_mtime, st.st_size)


def get_or_compute(path: str, artifact: str, factory: Callable[[], Any]) -> Any:
    try:
        fkey = _file_key(path)
    except OSError as e:
        raise FileNotFoundError(f"cannot stat {path}: {e}") from e

    key = (fkey, artifact)
    if key in _cache:
        return _cache[key]

    value = factory()
    _cache[key] = value
    return value


def invalidate(path: str) -> None:
    try:
        target = os.path.abspath(path)
    except OSError:
        return
    keys = [k for k in _cache if k[0][0] == target]
    for k in keys:
        _cache.pop(k, None)


def clear() -> None:
    _cache.clear()
