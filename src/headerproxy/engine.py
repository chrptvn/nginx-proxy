"""Rule matching and header rewriting.

The :class:`Engine` keeps an immutable, in-memory snapshot of every session's
rules, rebuilt from the store after each API mutation.  The proxy hot path
only ever reads the current snapshot of the *active* session, so data-plane
access is a dictionary lookup — no SQLite on the request path.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from .headers import Headers
from .store import Override, Store


@dataclass(frozen=True)
class Rule:
    """A single header override with its resolved filter pattern."""

    id: int
    direction: str
    action: str  # "set" | "remove"
    header: str
    value: str | None
    priority: int
    enabled: bool
    filter_id: int | None
    host: str  # resolved from the filter, "*" when unfiltered
    path: str
    comment: str | None

    @classmethod
    def from_override(cls, o: Override, host: str, path: str) -> "Rule":
        return cls(
            id=o.id,
            direction=o.direction,
            action=o.action,
            header=o.header,
            value=o.value,
            priority=o.priority,
            enabled=o.enabled,
            filter_id=o.filter_id,
            host=host,
            path=path,
            comment=o.comment,
        )

    def matches(self, host: str, hostport: str, path: str) -> bool:
        """Check the filter patterns against a request's authority + path.

        ``host`` is the lowercase hostname without port; ``hostport`` is
        ``host:port``; ``path`` is the URL path without the query string.
        A host pattern containing an explicit ``:port`` is matched against
        ``hostport``, otherwise against ``host``.
        """
        pattern = self.host.lower()
        subject = hostport.lower() if ":" in pattern else host.lower()
        if not fnmatchcase(subject, pattern):
            return False
        return fnmatchcase(path or "/", self.path)


@dataclass(frozen=True)
class SessionRules:
    """Immutable ruleset for one session."""

    name: str
    stealth: bool
    request_rules: tuple[Rule, ...] = field(default_factory=tuple)
    response_rules: tuple[Rule, ...] = field(default_factory=tuple)


EMPTY_RULES = SessionRules(name="", stealth=False)


class Engine:
    """Read-optimized view of the store; call :meth:`reload` after mutations."""

    def __init__(self, store: Store) -> None:
        self._store = store
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionRules] = {}
        self._active = "default"

    def reload(self) -> None:
        active = self._store.active_session_name()
        sessions: dict[str, SessionRules] = {}
        for session in self._store.list_sessions():
            filters = {f.id: f for f in self._store.list_filters(session.name)}
            request: list[Rule] = []
            response: list[Rule] = []
            for override in self._store.list_overrides(session.name):
                if override.filter_id is not None and override.filter_id in filters:
                    f = filters[override.filter_id]
                    host, path = f.host, f.path
                else:
                    host, path = "*", "*"
                rule = Rule.from_override(override, host, path)
                (request if rule.direction == "request" else response).append(rule)
            # Applied in ascending priority order so a higher priority rule
            # is applied later and wins; insertion order breaks ties.
            key = lambda r: (r.priority, r.id)  # noqa: E731
            sessions[session.name] = SessionRules(
                name=session.name,
                stealth=session.stealth,
                request_rules=tuple(sorted(request, key=key)),
                response_rules=tuple(sorted(response, key=key)),
            )
        with self._lock:
            self._sessions = sessions
            self._active = active if active in sessions else "default"

    def current(self) -> SessionRules:
        with self._lock:
            return self._sessions.get(self._active, EMPTY_RULES)

    def for_session(self, name: str) -> SessionRules:
        with self._lock:
            return self._sessions.get(name, EMPTY_RULES)

    def active_name(self) -> str:
        with self._lock:
            return self._active


def apply_rules(
    rules: tuple[Rule, ...], headers: Headers, host: str, hostport: str, path: str
) -> list[int]:
    """Apply matching rules in-place; return the ids that fired."""
    applied: list[int] = []
    for rule in rules:
        if not rule.enabled or not rule.matches(host, hostport, path):
            continue
        if rule.action == "set":
            headers.set(rule.header, rule.value or "")
        else:
            headers.remove(rule.header)
        applied.append(rule.id)
    return applied
