"""SQLite persistence for sessions, header overrides, and traffic filters.

The store is the source of truth; an in-memory snapshot used by the proxy hot
path is rebuilt from it by :mod:`headerproxy.engine` after every mutation.

Data model
----------
sessions
    A named, independently addressable set of overrides + filters.  Exactly
    one session is *active* at a time; the proxy applies the active session's
    rules to every request.  Each session also carries a ``stealth`` toggle.

overrides
    A header manipulation rule: ``set`` or ``remove`` a named header on the
    request or the response, optionally scoped by a filter, with a priority
    for deterministic ordering.

filters
    A traffic matcher (``host`` glob + optional ``path`` glob) that overrides
    can reference to restrict where they apply.  Overrides without a filter
    match all traffic.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    name       TEXT PRIMARY KEY,
    stealth    INTEGER NOT NULL DEFAULT 1,
    active     INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS filters (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session    TEXT NOT NULL REFERENCES sessions(name) ON DELETE CASCADE,
    host       TEXT NOT NULL,
    path       TEXT NOT NULL DEFAULT '*',
    comment    TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS overrides (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session    TEXT NOT NULL REFERENCES sessions(name) ON DELETE CASCADE,
    direction  TEXT NOT NULL CHECK (direction IN ('request', 'response')),
    action     TEXT NOT NULL CHECK (action IN ('set', 'remove')),
    header     TEXT NOT NULL,
    value      TEXT,
    filter_id  INTEGER REFERENCES filters(id) ON DELETE SET NULL,
    priority   INTEGER NOT NULL DEFAULT 0,
    comment    TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_overrides_session ON overrides(session);
CREATE INDEX IF NOT EXISTS idx_filters_session ON filters(session);
"""


class StoreError(Exception):
    """Raised for user-facing store violations (duplicates, missing rows...)."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Session:
    name: str
    stealth: bool
    active: bool
    created_at: str
    updated_at: str
    override_count: int = 0
    filter_count: int = 0


@dataclass(frozen=True)
class Override:
    id: int
    session: str
    direction: str  # "request" | "response"
    action: str  # "set" | "remove"
    header: str
    value: str | None
    filter_id: int | None
    priority: int
    comment: str | None
    enabled: bool
    created_at: str


@dataclass(frozen=True)
class Filter:
    id: int
    session: str
    host: str
    path: str
    comment: str | None
    created_at: str


class Store:
    """Thread-safe wrapper around a single SQLite connection (WAL mode)."""

    def __init__(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA busy_timeout=5000")
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- sessions -----------------------------------------------------------

    def ensure_default_session(self, stealth_default: bool = True) -> None:
        with self._lock:
            row = self._db.execute(
                "SELECT name FROM sessions WHERE name = 'default'"
            ).fetchone()
            if row is None:
                now = _now()
                self._db.execute(
                    "INSERT INTO sessions (name, stealth, active, created_at, updated_at)"
                    " VALUES ('default', ?, 1, ?, ?)",
                    (1 if stealth_default else 0, now, now),
                )
                self._db.commit()

    def list_sessions(self) -> list[Session]:
        with self._lock:
            rows = self._db.execute(
                """
                SELECT s.*,
                       (SELECT COUNT(*) FROM overrides o WHERE o.session = s.name) AS override_count,
                       (SELECT COUNT(*) FROM filters f WHERE f.session = s.name)   AS filter_count
                FROM sessions s ORDER BY s.active DESC, s.name
                """
            ).fetchall()
        return [self._session_from_row(r) for r in rows]

    def get_session(self, name: str) -> Session:
        with self._lock:
            row = self._db.execute(
                """
                SELECT s.*,
                       (SELECT COUNT(*) FROM overrides o WHERE o.session = s.name) AS override_count,
                       (SELECT COUNT(*) FROM filters f WHERE f.session = s.name)   AS filter_count
                FROM sessions s WHERE s.name = ?
                """,
                (name,),
            ).fetchone()
        if row is None:
            raise StoreError(f"session '{name}' does not exist")
        return self._session_from_row(row)

    def get_active_session(self) -> Session:
        with self._lock:
            row = self._db.execute(
                "SELECT name FROM sessions WHERE active = 1"
            ).fetchone()
        if row is None:  # should not happen; recover deterministically
            with self._lock:
                self._db.execute(
                    "UPDATE sessions SET active = CASE WHEN name='default' THEN 1 ELSE 0 END"
                )
                self._db.commit()
            return self.get_session("default")
        return self.get_session(row["name"])

    def create_session(self, name: str, stealth: bool = True) -> Session:
        self._validate_name(name)
        now = _now()
        with self._lock:
            exists = self._db.execute(
                "SELECT 1 FROM sessions WHERE name = ?", (name,)
            ).fetchone()
            if exists:
                raise StoreError(f"session '{name}' already exists")
            self._db.execute(
                "INSERT INTO sessions (name, stealth, active, created_at, updated_at)"
                " VALUES (?, ?, 0, ?, ?)",
                (name, 1 if stealth else 0, now, now),
            )
            self._db.commit()
        return self.get_session(name)

    def set_session_stealth(self, name: str, stealth: bool) -> Session:
        with self._lock:
            self._require_session(name)
            self._db.execute(
                "UPDATE sessions SET stealth = ?, updated_at = ? WHERE name = ?",
                (1 if stealth else 0, _now(), name),
            )
            self._db.commit()
        return self.get_session(name)

    def activate_session(self, name: str) -> Session:
        with self._lock:
            self._require_session(name)
            self._db.execute("UPDATE sessions SET active = 0 WHERE active = 1")
            self._db.execute(
                "UPDATE sessions SET active = 1, updated_at = ? WHERE name = ?",
                (_now(), name),
            )
            self._db.commit()
        return self.get_session(name)

    def save_session(self, name: str) -> Session:
        """Persist the active session's configuration under ``name``.

        Saving onto the active session's own name is an explicit checkpoint.
        Otherwise the target session (if any) is replaced wholesale with a
        copy of the active session's filters and overrides.
        """
        self._validate_name(name)
        with self._lock:
            active = self.get_active_session()
            if name == active.name:
                self._db.execute(
                    "UPDATE sessions SET updated_at = ? WHERE name = ?",
                    (_now(), name),
                )
                self._db.commit()
                return self.get_session(name)

            now = _now()
            self._require_session(active.name)
            self._db.execute("DELETE FROM sessions WHERE name = ?", (name,))
            self._db.execute(
                "INSERT INTO sessions (name, stealth, active, created_at, updated_at)"
                " VALUES (?, ?, 0, ?, ?)",
                (name, 1 if active.stealth else 0, now, now),
            )
            # Copy filters, remembering the id mapping to re-point overrides.
            id_map: dict[int, int] = {}
            for f in self.list_filters(active.name):
                cur = self._db.execute(
                    "INSERT INTO filters (session, host, path, comment, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (name, f.host, f.path, f.comment, now),
                )
                id_map[f.id] = int(cur.lastrowid)
            for o in self.list_overrides(active.name):
                self._db.execute(
                    "INSERT INTO overrides (session, direction, action, header, value,"
                    " filter_id, priority, comment, enabled, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        name,
                        o.direction,
                        o.action,
                        o.header,
                        o.value,
                        id_map.get(o.filter_id) if o.filter_id is not None else None,
                        o.priority,
                        o.comment,
                        1 if o.enabled else 0,
                        now,
                    ),
                )
            self._db.commit()
        return self.get_session(name)

    def delete_session(self, name: str) -> None:
        with self._lock:
            self._require_session(name)
            if self.get_active_session().name == name:
                raise StoreError(
                    f"session '{name}' is active — switch to another session first"
                )
            self._db.execute("DELETE FROM sessions WHERE name = ?", (name,))
            self._db.commit()

    # -- filters ------------------------------------------------------------

    def add_filter(
        self, session: str, host: str, path: str = "*", comment: str | None = None
    ) -> Filter:
        self._validate_pattern(host, "host")
        self._validate_pattern(path, "path")
        with self._lock:
            self._require_session(session)
            cur = self._db.execute(
                "INSERT INTO filters (session, host, path, comment, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (session, host, path or "*", comment, _now()),
            )
            self._db.commit()
            return self.get_filter(session, int(cur.lastrowid))

    def get_filter(self, session: str, filter_id: int) -> Filter:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM filters WHERE id = ? AND session = ?",
                (filter_id, session),
            ).fetchone()
        if row is None:
            raise StoreError(
                f"filter {filter_id} does not exist in session '{session}'"
            )
        return Filter(
            id=row["id"],
            session=row["session"],
            host=row["host"],
            path=row["path"],
            comment=row["comment"],
            created_at=row["created_at"],
        )

    def list_filters(self, session: str) -> list[Filter]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM filters WHERE session = ? ORDER BY id", (session,)
            ).fetchall()
        return [
            Filter(
                id=r["id"],
                session=r["session"],
                host=r["host"],
                path=r["path"],
                comment=r["comment"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def delete_filter(self, session: str, filter_id: int) -> None:
        with self._lock:
            self.get_filter(session, filter_id)  # raises when missing
            self._db.execute(
                "DELETE FROM filters WHERE id = ? AND session = ?",
                (filter_id, session),
            )
            self._db.commit()

    # -- overrides ----------------------------------------------------------

    def add_override(
        self,
        session: str,
        direction: str,
        action: str,
        header: str,
        value: str | None = None,
        filter_id: int | None = None,
        priority: int = 0,
        comment: str | None = None,
        enabled: bool = True,
    ) -> Override:
        if direction not in ("request", "response"):
            raise StoreError("direction must be 'request' or 'response'")
        if action not in ("set", "remove"):
            raise StoreError("action must be 'set' or 'remove'")
        if action == "set" and value is None:
            raise StoreError("value is required when action is 'set'")
        if action == "remove":
            value = None
        self._validate_header_name(header)
        with self._lock:
            self._require_session(session)
            if filter_id is not None:
                self.get_filter(session, filter_id)
            cur = self._db.execute(
                "INSERT INTO overrides (session, direction, action, header, value,"
                " filter_id, priority, comment, enabled, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    session,
                    direction,
                    action,
                    header,
                    value,
                    filter_id,
                    priority,
                    comment,
                    1 if enabled else 0,
                    _now(),
                ),
            )
            self._db.commit()
            return self.get_override(session, int(cur.lastrowid))

    def get_override(self, session: str, override_id: int) -> Override:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM overrides WHERE id = ? AND session = ?",
                (override_id, session),
            ).fetchone()
        if row is None:
            raise StoreError(
                f"override {override_id} does not exist in session '{session}'"
            )
        return Override(
            id=row["id"],
            session=row["session"],
            direction=row["direction"],
            action=row["action"],
            header=row["header"],
            value=row["value"],
            filter_id=row["filter_id"],
            priority=row["priority"],
            comment=row["comment"],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
        )

    def list_overrides(self, session: str) -> list[Override]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM overrides WHERE session = ?"
                " ORDER BY priority DESC, id",
                (session,),
            ).fetchall()
        return [
            Override(
                id=r["id"],
                session=r["session"],
                direction=r["direction"],
                action=r["action"],
                header=r["header"],
                value=r["value"],
                filter_id=r["filter_id"],
                priority=r["priority"],
                comment=r["comment"],
                enabled=bool(r["enabled"]),
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def delete_override(self, session: str, override_id: int) -> None:
        with self._lock:
            self.get_override(session, override_id)  # raises when missing
            self._db.execute(
                "DELETE FROM overrides WHERE id = ? AND session = ?",
                (override_id, session),
            )
            self._db.commit()

    def clean_overrides(self, session: str) -> int:
        """Remove every override of the session (filters are kept)."""
        with self._lock:
            self._require_session(session)
            cur = self._db.execute(
                "DELETE FROM overrides WHERE session = ?", (session,)
            )
            self._db.commit()
            return int(cur.rowcount)

    # -- engine export ------------------------------------------------------

    def active_session_name(self) -> str:
        return self.get_active_session().name

    # -- internals ----------------------------------------------------------

    def _require_session(self, name: str) -> None:
        exists = self._db.execute(
            "SELECT 1 FROM sessions WHERE name = ?", (name,)
        ).fetchone()
        if not exists:
            raise StoreError(f"session '{name}' does not exist")

    @staticmethod
    def _session_from_row(r: sqlite3.Row) -> Session:
        return Session(
            name=r["name"],
            stealth=bool(r["stealth"]),
            active=bool(r["active"]),
            created_at=r["created_at"],
            updated_at=r["updated_at"],
            override_count=r["override_count"],
            filter_count=r["filter_count"],
        )

    @staticmethod
    def _validate_name(name: str) -> None:
        if not name or len(name) > 64:
            raise StoreError("session name must be 1-64 characters")
        if not all(c.isalnum() or c in "-_." for c in name):
            raise StoreError(
                "session name may only contain letters, digits, '-', '_' and '.'"
            )

    @staticmethod
    def _validate_header_name(header: str) -> None:
        if not header or len(header) > 256:
            raise StoreError("header name must be 1-256 characters")
        forbidden = set(":\r\n \t")
        if any(c in forbidden for c in header):
            raise StoreError(
                "header name must be a valid HTTP token (no spaces, colons or newlines)"
            )

    @staticmethod
    def _validate_pattern(pattern: str, what: str) -> None:
        if pattern is None or len(pattern) > 512:
            raise StoreError(f"{what} pattern must be 1-512 characters")
        if any(c in pattern for c in "\r\n"):
            raise StoreError(f"{what} pattern must not contain newlines")
