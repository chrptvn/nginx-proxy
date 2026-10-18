"""Case-insensitive, order-preserving HTTP header collection.

``Headers`` keeps the original header-name casing and ordering (both matter
for TLS/HTTP fingerprinting) while offering case-insensitive lookups and
support for repeated field names (``Cookie``, ``Set-Cookie``, ...).
"""

from __future__ import annotations

from typing import Iterable, Iterator


class Headers:
    __slots__ = ("_items",)

    def __init__(self, items: Iterable[tuple[str, str]] = ()) -> None:
        self._items: list[list[str]] = [[name, value] for name, value in items]

    # -- basics -------------------------------------------------------------

    def copy(self) -> "Headers":
        return Headers((name, value) for name, value in self._items)

    def names(self) -> list[str]:
        return [name for name, _ in self._items]

    def to_list(self) -> list[tuple[str, str]]:
        return [(name, value) for name, value in self._items]

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter((name, value) for name, value in self._items)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self.has(name)

    # -- lookups ------------------------------------------------------------

    def get(self, name: str, default: str | None = None) -> str | None:
        lower = name.lower()
        for key, value in self._items:
            if key.lower() == lower:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        lower = name.lower()
        return [value for key, value in self._items if key.lower() == lower]

    def has(self, name: str) -> bool:
        lower = name.lower()
        return any(key.lower() == lower for key, _ in self._items)

    # -- mutations ----------------------------------------------------------

    def add(self, name: str, value: str) -> None:
        self._items.append([name, value])

    def set(self, name: str, value: str) -> None:
        """Replace every occurrence of ``name`` with a single header.

        The first occurrence keeps its position so header ordering is stable.
        """
        lower = name.lower()
        rebuilt: list[list[str]] = []
        replaced = False
        for key, existing in self._items:
            if key.lower() == lower:
                if not replaced:
                    rebuilt.append([name, value])
                    replaced = True
            else:
                rebuilt.append([key, existing])
        if not replaced:
            rebuilt.append([name, value])
        self._items = rebuilt

    def remove(self, name: str) -> bool:
        lower = name.lower()
        kept = [pair for pair in self._items if pair[0].lower() != lower]
        removed = len(kept) != len(self._items)
        self._items = kept
        return removed

    def remove_prefix(self, prefix: str) -> bool:
        lower = prefix.lower()
        kept = [pair for pair in self._items if not pair[0].lower().startswith(lower)]
        removed = len(kept) != len(self._items)
        self._items = kept
        return removed

    def clear(self) -> None:
        self._items.clear()
