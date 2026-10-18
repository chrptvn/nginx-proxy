"""MCP server end-to-end: real streamable-HTTP transport + official client."""

import asyncio
import json
import threading
import time

import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from headerproxy.api import create_app
from headerproxy.config import Config
from headerproxy.engine import Engine
from headerproxy.mcp_server import create_mcp
from headerproxy.runtime import Runtime
from headerproxy.store import Store

EXPECTED_TOOLS = {
    "proxy_status",
    "create_session",
    "list_sessions",
    "save_session",
    "switch_session",
    "delete_session",
    "inject_header",
    "remove_header",
    "list_overrides",
    "remove_override",
    "clean_overrides",
    "add_filter",
    "list_filters",
    "remove_filter",
}


@pytest.fixture
async def server(tmp_path):
    cfg = Config(data_dir=tmp_path / "data", log_level="ERROR")
    store = Store(cfg.data_dir / "headerproxy.db")
    store.ensure_default_session(True)
    engine = Engine(store)
    engine.reload()
    rt = Runtime(cfg=cfg, store=store, engine=engine, ca=None, upstream=None, proxy=None)
    mcp = create_mcp(rt)
    app = create_app(rt, mcp_app=mcp.streamable_http_app())

    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    uv = uvicorn.Server(config)
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not uv.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn failed to start")
        await asyncio.sleep(0.05)
    port = uv.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}", rt
    uv.should_exit = True
    thread.join(10)
    store.close()


async def with_session(base_url):
    async with streamablehttp_client(f"{base_url}/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def payload(result) -> dict:
    if getattr(result, "structuredContent", None):
        return result.structuredContent
    for block in result.content:
        text = getattr(block, "text", None)
        if text:
            return json.loads(text)
    return {"ok": False, "raw": []}


async def call(session, tool, args=None) -> dict:
    return payload(await session.call_tool(tool, args or {}))


async def test_lists_all_tools(server):
    base_url, _ = server
    async for s in with_session(base_url):
        tools = await s.list_tools()
        assert EXPECTED_TOOLS <= {t.name for t in tools.tools}


async def test_status_and_inject_flow(server):
    base_url, rt = server
    async for s in with_session(base_url):
        status = await call(s, "proxy_status")
        assert status["active_session"] == "default"

        injected = await call(
            s, "inject_header", {"header": "X-Mcp", "value": "yes", "comment": "via mcp"}
        )
        assert injected["ok"] is True
        overrides = await call(s, "list_overrides")
        assert overrides["overrides"][0]["header"] == "X-Mcp"
        assert rt.store.list_overrides("default")[0].header == "X-Mcp"

        f = await call(s, "add_filter", {"host": "*.example.com"})
        assert f["ok"] is True

        removed = await call(s, "remove_override", {"override_id": injected["override_id"]})
        assert removed["ok"] is True


async def test_session_tools(server):
    base_url, rt = server
    async for s in with_session(base_url):
        assert (await call(s, "create_session", {"name": "mcp-session"}))["ok"] is True
        switched = await call(s, "switch_session", {"name": "mcp-session"})
        assert switched["active_session"] == "mcp-session"
        assert rt.store.active_session_name() == "mcp-session"

        await call(s, "inject_header", {"header": "X-Sess", "value": "1"})
        saved = await call(s, "save_session", {"name": "mcp-snapshot"})
        assert saved["ok"] is True

        sessions = await call(s, "list_sessions")
        names = {x["name"] for x in sessions["sessions"]}
        assert {"default", "mcp-session", "mcp-snapshot"} <= names

        # cannot delete the active session
        deleted = await call(s, "delete_session", {"name": "mcp-session"})
        assert deleted["ok"] is False and "active" in deleted["error"]

        await call(s, "switch_session", {"name": "default"})
        assert (await call(s, "delete_session", {"name": "mcp-session"}))["ok"] is True
        assert (await call(s, "delete_session", {"name": "mcp-snapshot"}))["ok"] is True


async def test_error_reporting(server):
    base_url, _ = server
    async for s in with_session(base_url):
        result = await call(s, "switch_session", {"name": "missing"})
        assert result["ok"] is False


async def test_rest_routes_served_alongside_mcp(server):
    import httpx

    base_url, _ = server
    async with httpx.AsyncClient() as client:
        assert (await client.get(f"{base_url}/api/health")).json() == {"status": "ok"}
        assert (await client.get(f"{base_url}/api/status")).json()["active_session"] == "default"
        assert (await client.get(f"{base_url}/docs")).status_code == 200
        # the MCP transport is still reachable at /mcp
        r = await client.post(f"{base_url}/mcp", json={"jsonrpc": "2.0", "id": 0})
        assert r.status_code != 404
