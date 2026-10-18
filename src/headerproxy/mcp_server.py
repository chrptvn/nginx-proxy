"""MCP (Model Context Protocol) server.

Exposes every control-plane operation as an MCP *tool*, so MCP clients (n8n,
Claude, ...) can manage header overrides conversationally.  Tools operate on
the **active session** — switch sessions with the ``switch_session`` tool.

Transport: streamable HTTP at ``/mcp`` (stateless JSON mode), mounted into the
same FastAPI app as the REST API.  Tool results are JSON objects with an
``ok`` flag; failures carry an ``error`` message.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

from mcp.server.fastmcp import FastMCP

from .runtime import Runtime
from .store import StoreError

log = logging.getLogger("headerproxy.mcp")


def _ok(payload: dict) -> dict:
    payload["ok"] = True
    return payload


def _err(message: str) -> dict:
    return {"ok": False, "error": message}


def create_mcp(rt: Runtime):
    """Build the FastMCP server bound to ``rt``."""

    mcp: FastMCP = FastMCP(
        name="header-proxy",
        instructions=(
            "Control plane of HeaderProxy, an HTTP header injection proxy. "
            "Rules are grouped into sessions; the proxy applies the rules of "
            "the active session to all traffic. Operates on the active session."
        ),
        stateless_http=True,
        json_response=True,
    )

    async def store_call(
        fn: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> tuple[Any, str | None]:
        """Run a store operation off-loop; map StoreError to an error string."""
        try:
            return await asyncio.to_thread(fn, *args, **kwargs), None
        except StoreError as exc:
            return None, str(exc)

    # -- status & sessions -----------------------------------------------------

    @mcp.tool()
    async def proxy_status() -> dict:
        """Overview: active session, rule counts and version."""

        def collect():
            active = rt.store.get_active_session()
            return {
                "active_session": active.name,
                "stealth": active.stealth,
                "overrides": active.override_count,
                "filters": active.filter_count,
                "sessions": [s.name for s in rt.store.list_sessions()],
            }

        result, error = await store_call(collect)
        return _err(error) if error else _ok(result)

    @mcp.tool()
    async def create_session(name: str, stealth: bool = True) -> dict:
        """Create a new, empty session (does not switch to it)."""
        session, error = await store_call(rt.store.create_session, name, stealth)
        if error:
            return _err(error)
        rt.engine.reload()
        return _ok({"session": session.name, "stealth": session.stealth})

    @mcp.tool()
    async def list_sessions() -> dict:
        """List all sessions with their rule counts and which one is active."""
        sessions, error = await store_call(rt.store.list_sessions)
        if error:
            return _err(error)
        return _ok(
            {
                "sessions": [
                    {
                        "name": s.name,
                        "active": s.active,
                        "stealth": s.stealth,
                        "overrides": s.override_count,
                        "filters": s.filter_count,
                    }
                    for s in sessions
                ]
            }
        )

    @mcp.tool()
    async def save_session(name: str) -> dict:
        """Persist the active session's configuration under `name` (snapshot)."""
        session, error = await store_call(rt.store.save_session, name)
        if error:
            return _err(error)
        rt.engine.reload()
        return _ok({"saved_as": session.name, "overrides": session.override_count})

    @mcp.tool()
    async def switch_session(name: str) -> dict:
        """Make `name` the active session; the proxy applies its rules at once."""
        session, error = await store_call(rt.store.activate_session, name)
        if error:
            return _err(error)
        rt.engine.reload()
        return _ok({"active_session": session.name})

    @mcp.tool()
    async def delete_session(name: str) -> dict:
        """Delete a session together with its overrides and filters."""
        _, error = await store_call(rt.store.delete_session, name)
        if error:
            return _err(error)
        rt.engine.reload()
        return _ok({"deleted": name})

    # -- overrides ----------------------------------------------------------------

    @mcp.tool()
    async def inject_header(
        header: str,
        value: str,
        direction: str = "request",
        filter_id: int | None = None,
        priority: int = 0,
        comment: str | None = None,
    ) -> dict:
        """Add an override that sets `header` to `value` on the request or the
        response. Scope it with `filter_id` (see add_filter)."""
        name, error = await store_call(rt.store.active_session_name)
        if error:
            return _err(error)
        override, error = await store_call(
            rt.store.add_override,
            name,
            direction,
            "set",
            header,
            value,
            filter_id,
            priority,
            comment,
            True,
        )
        if error:
            return _err(error)
        rt.engine.reload()
        return _ok({"override_id": override.id})

    @mcp.tool()
    async def remove_header(
        header: str,
        direction: str = "request",
        filter_id: int | None = None,
        priority: int = 0,
        comment: str | None = None,
    ) -> dict:
        """Add an override that strips `header` from the request or the response."""
        name, error = await store_call(rt.store.active_session_name)
        if error:
            return _err(error)
        override, error = await store_call(
            rt.store.add_override,
            name,
            direction,
            "remove",
            header,
            None,
            filter_id,
            priority,
            comment,
            True,
        )
        if error:
            return _err(error)
        rt.engine.reload()
        return _ok({"override_id": override.id})

    @mcp.tool()
    async def list_overrides() -> dict:
        """List the active session's header overrides."""
        name, error = await store_call(rt.store.active_session_name)
        if error:
            return _err(error)
        overrides, error = await store_call(rt.store.list_overrides, name)
        if error:
            return _err(error)
        return _ok(
            {
                "session": name,
                "overrides": [
                    {
                        "id": o.id,
                        "direction": o.direction,
                        "action": o.action,
                        "header": o.header,
                        "value": o.value,
                        "filter_id": o.filter_id,
                        "enabled": o.enabled,
                        "comment": o.comment,
                    }
                    for o in overrides
                ],
            }
        )

    @mcp.tool()
    async def remove_override(override_id: int) -> dict:
        """Delete a single override by id (active session)."""
        name, error = await store_call(rt.store.active_session_name)
        if error:
            return _err(error)
        _, error = await store_call(rt.store.delete_override, name, override_id)
        if error:
            return _err(error)
        rt.engine.reload()
        return _ok({"removed_override": override_id})

    @mcp.tool()
    async def clean_overrides() -> dict:
        """Delete ALL overrides of the active session (filters are kept)."""
        name, error = await store_call(rt.store.active_session_name)
        if error:
            return _err(error)
        removed, error = await store_call(rt.store.clean_overrides, name)
        if error:
            return _err(error)
        rt.engine.reload()
        return _ok({"removed": removed})

    # -- filters ---------------------------------------------------------------------

    @mcp.tool()
    async def add_filter(host: str, path: str = "*", comment: str | None = None) -> dict:
        """Create a traffic filter (host/path glob) that overrides can reference."""
        name, error = await store_call(rt.store.active_session_name)
        if error:
            return _err(error)
        f, error = await store_call(rt.store.add_filter, name, host, path, comment)
        if error:
            return _err(error)
        rt.engine.reload()
        return _ok({"filter_id": f.id, "host": f.host, "path": f.path})

    @mcp.tool()
    async def list_filters() -> dict:
        """List the active session's filters."""
        name, error = await store_call(rt.store.active_session_name)
        if error:
            return _err(error)
        filters, error = await store_call(rt.store.list_filters, name)
        if error:
            return _err(error)
        return _ok(
            {
                "session": name,
                "filters": [
                    {"id": f.id, "host": f.host, "path": f.path, "comment": f.comment}
                    for f in filters
                ],
            }
        )

    @mcp.tool()
    async def remove_filter(filter_id: int) -> dict:
        """Delete a filter; overrides referencing it become unscoped."""
        name, error = await store_call(rt.store.active_session_name)
        if error:
            return _err(error)
        _, error = await store_call(rt.store.delete_filter, name, filter_id)
        if error:
            return _err(error)
        rt.engine.reload()
        return _ok({"removed_filter": filter_id})

    return mcp
