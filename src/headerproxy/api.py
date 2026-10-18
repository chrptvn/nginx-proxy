"""REST control plane (FastAPI).

All mutating endpoints operate on an explicit session (path parameter) and
refresh the in-memory engine snapshot afterwards, so changes take effect on
the very next request through the proxy.
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from typing import Any, Callable

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .runtime import Runtime
from .store import Filter, Override, Session, StoreError


# -- request/response models ---------------------------------------------------


class SessionIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    stealth: bool = True


class SessionPatch(BaseModel):
    stealth: bool


class OverrideIn(BaseModel):
    direction: str = Field(default="request", description='"request" or "response"')
    action: str = Field(default="set", description='"set" or "remove"')
    header: str = Field(min_length=1, max_length=256)
    value: str | None = Field(default=None, description="required for action=set")
    filter_id: int | None = None
    priority: int = 0
    comment: str | None = Field(default=None, max_length=512)
    enabled: bool = True


class FilterIn(BaseModel):
    host: str = Field(min_length=1, max_length=512, description='glob, e.g. "*.example.com"')
    path: str = Field("*", min_length=1, max_length=512)
    comment: str | None = Field(default=None, max_length=512)


class SessionOut(BaseModel):
    name: str
    stealth: bool
    active: bool
    created_at: str
    updated_at: str
    override_count: int
    filter_count: int

    @classmethod
    def of(cls, s: Session) -> "SessionOut":
        return cls(
            name=s.name,
            stealth=s.stealth,
            active=s.active,
            created_at=s.created_at,
            updated_at=s.updated_at,
            override_count=s.override_count,
            filter_count=s.filter_count,
        )


class OverrideOut(BaseModel):
    id: int
    session: str
    direction: str
    action: str
    header: str
    value: str | None
    filter_id: int | None
    priority: int
    comment: str | None
    enabled: bool
    created_at: str

    @classmethod
    def of(cls, o: Override) -> "OverrideOut":
        return cls(
            id=o.id,
            session=o.session,
            direction=o.direction,
            action=o.action,
            header=o.header,
            value=o.value,
            filter_id=o.filter_id,
            priority=o.priority,
            comment=o.comment,
            enabled=o.enabled,
            created_at=o.created_at,
        )


class FilterOut(BaseModel):
    id: int
    session: str
    host: str
    path: str
    comment: str | None
    created_at: str

    @classmethod
    def of(cls, f: Filter) -> "FilterOut":
        return cls(
            id=f.id,
            session=f.session,
            host=f.host,
            path=f.path,
            comment=f.comment,
            created_at=f.created_at,
        )


# -- helpers -------------------------------------------------------------------


def _status_for(exc: StoreError) -> int:
    message = str(exc)
    if "does not exist" in message:
        return 404
    if "already exists" in message or "is active" in message:
        return 409
    return 400


def _run(rt: Runtime, fn: Callable[[], Any], *, reload_engine: bool = False) -> Any:
    """Run a store operation in the threadpool and map errors to HTTP codes."""
    try:
        result = fn()
    except StoreError as exc:
        raise HTTPException(status_code=_status_for(exc), detail=str(exc)) from exc
    if reload_engine:
        rt.engine.reload()
    return result


# -- app factory ----------------------------------------------------------------


def create_app(rt: Runtime, mcp_app: Any | None = None) -> FastAPI:
    """Build the FastAPI app (REST + optional MCP mount + proxy lifecycle)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if rt.proxy is not None:
            await rt.proxy.serve()
        mcp_ctx = (
            mcp_app.router.lifespan_context(mcp_app) if mcp_app is not None else None
        )

        class _NullCtx:
            async def __aenter__(self):
                return None

            async def __aexit__(self, *exc):
                return False

        async with mcp_ctx if mcp_ctx is not None else _NullCtx():
            try:
                yield
            finally:
                if rt.proxy is not None:
                    await rt.proxy.stop()
                if rt.upstream is not None:
                    await rt.upstream.close()

    app = FastAPI(
        title="HeaderProxy",
        version=__version__,
        description=(
            "Session-scoped HTTP header injection proxy. "
            "Overrides and filters belong to sessions; the proxy applies the "
            "rules of the active session to every request it relays."
        ),
        lifespan=lifespan,
    )
    app.state.runtime = rt
    if mcp_app is not None:
        app.state.mcp_app = mcp_app

    # -- auth ---------------------------------------------------------------

    @app.middleware("http")
    async def require_api_key(request: Request, call_next):
        if rt.cfg.api_key and request.url.path != "/api/health":
            auth = request.headers.get("Authorization", "")
            expected = f"Bearer {rt.cfg.api_key}"
            if not auth or not secrets.compare_digest(auth, expected):
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return await call_next(request)

    # -- meta -----------------------------------------------------------------

    @app.get("/")
    async def root() -> dict:
        return {
            "name": "HeaderProxy",
            "version": __version__,
            "api": "/api",
            "mcp": "/mcp",
            "docs": "/docs",
        }

    @app.get("/api/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.get("/api/status")
    async def status() -> dict:
        active = rt.store.get_active_session()
        return {
            "version": __version__,
            "active_session": active.name,
            "stealth": active.stealth,
            "overrides": active.override_count,
            "filters": active.filter_count,
            "sessions": len(rt.store.list_sessions()),
        }

    # -- sessions ---------------------------------------------------------------

    @app.get("/api/sessions", response_model=list[SessionOut])
    async def list_sessions() -> list[SessionOut]:
        return [SessionOut.of(s) for s in _run(rt, rt.store.list_sessions)]

    @app.post("/api/sessions", response_model=SessionOut, status_code=201)
    async def create_session(body: SessionIn) -> SessionOut:
        session = _run(
            rt,
            lambda: rt.store.create_session(body.name, body.stealth),
            reload_engine=True,
        )
        return SessionOut.of(session)

    @app.post("/api/sessions/{name}/save", response_model=SessionOut)
    async def save_session(name: str) -> SessionOut:
        """Persist the active session's configuration under ``name``."""
        session = _run(
            rt,
            lambda: rt.store.save_session(name),
            reload_engine=True,
        )
        return SessionOut.of(session)

    @app.post("/api/sessions/{name}/activate", response_model=SessionOut)
    async def activate_session(name: str) -> SessionOut:
        session = _run(
            rt,
            lambda: rt.store.activate_session(name),
            reload_engine=True,
        )
        return SessionOut.of(session)

    @app.patch("/api/sessions/{name}", response_model=SessionOut)
    async def patch_session(name: str, body: SessionPatch) -> SessionOut:
        session = _run(
            rt,
            lambda: rt.store.set_session_stealth(name, body.stealth),
            reload_engine=True,
        )
        return SessionOut.of(session)

    @app.delete("/api/sessions/{name}", status_code=204)
    async def delete_session(name: str) -> None:
        _run(rt, lambda: rt.store.delete_session(name), reload_engine=True)

    # -- overrides ----------------------------------------------------------------

    @app.get("/api/sessions/{name}/overrides", response_model=list[OverrideOut])
    async def list_overrides(name: str) -> list[OverrideOut]:
        _run(rt, lambda: rt.store.get_session(name))
        return [
            OverrideOut.of(o) for o in _run(rt, lambda: rt.store.list_overrides(name))
        ]

    @app.post("/api/sessions/{name}/overrides", response_model=OverrideOut, status_code=201)
    async def add_override(name: str, body: OverrideIn) -> OverrideOut:
        override = _run(
            rt,
            lambda: rt.store.add_override(
                session=name,
                direction=body.direction,
                action=body.action,
                header=body.header,
                value=body.value,
                filter_id=body.filter_id,
                priority=body.priority,
                comment=body.comment,
                enabled=body.enabled,
            ),
            reload_engine=True,
        )
        return OverrideOut.of(override)

    @app.delete("/api/sessions/{name}/overrides", response_model=dict)
    async def clean_overrides(name: str) -> dict:
        """Remove every override of the session (filters are preserved)."""
        removed = _run(
            rt,
            lambda: rt.store.clean_overrides(name),
            reload_engine=True,
        )
        return {"removed": removed}

    @app.delete("/api/sessions/{name}/overrides/{override_id}", status_code=204)
    async def delete_override(name: str, override_id: int) -> None:
        _run(
            rt,
            lambda: rt.store.delete_override(name, override_id),
            reload_engine=True,
        )

    # -- filters -------------------------------------------------------------------

    @app.get("/api/sessions/{name}/filters", response_model=list[FilterOut])
    async def list_filters(name: str) -> list[FilterOut]:
        _run(rt, lambda: rt.store.get_session(name))
        return [FilterOut.of(f) for f in _run(rt, lambda: rt.store.list_filters(name))]

    @app.post("/api/sessions/{name}/filters", response_model=FilterOut, status_code=201)
    async def add_filter(name: str, body: FilterIn) -> FilterOut:
        f = _run(
            rt,
            lambda: rt.store.add_filter(name, body.host, body.path, body.comment),
            reload_engine=True,
        )
        return FilterOut.of(f)

    @app.delete("/api/sessions/{name}/filters/{filter_id}", status_code=204)
    async def delete_filter(name: str, filter_id: int) -> None:
        _run(
            rt,
            lambda: rt.store.delete_filter(name, filter_id),
            reload_engine=True,
        )

    # The MCP app (mounted last, so the REST routes above match first) serves
    # its streamable-HTTP transport at /mcp.
    if mcp_app is not None:
        app.mount("/", mcp_app, name="mcp")

    return app
