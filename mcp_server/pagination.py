from .config import MAX_TEXT_CHARS, MAX_LIST_ITEMS


def truncate_text(text: str, max_chars: int = MAX_TEXT_CHARS) -> dict:
    total = len(text)
    if total <= max_chars:
        return {"text": text, "truncated": False, "total_chars": total}
    return {
        "text": text[:max_chars],
        "truncated": True,
        "total_chars": total,
        "returned_chars": max_chars,
    }


def slice_text(text: str, offset: int = 0, limit: int | None = None) -> dict:
    total = len(text)
    if offset < 0:
        offset = 0
    if limit is None:
        limit = MAX_TEXT_CHARS
    end = min(total, offset + limit)
    chunk = text[offset:end]
    return {
        "text": chunk,
        "offset": offset,
        "returned_chars": len(chunk),
        "total_chars": total,
        "has_more": end < total,
    }


def paginate_list(items: list, offset: int = 0, limit: int | None = None) -> dict:
    if limit is None:
        limit = MAX_LIST_ITEMS
    if offset < 0:
        offset = 0
    total = len(items)
    end = min(total, offset + limit)
    chunk = items[offset:end]
    return {
        "items": chunk,
        "offset": offset,
        "returned": len(chunk),
        "total": total,
        "has_more": end < total,
    }
