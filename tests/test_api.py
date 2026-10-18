"""REST API contract tests (no data plane; TestClient drives the app)."""

import pytest
from fastapi.testclient import TestClient

from headerproxy.api import create_app
from headerproxy.config import Config
from headerproxy.engine import Engine
from headerproxy.runtime import Runtime
from headerproxy.store import Store


@pytest.fixture
def runtime(tmp_path):
    cfg = Config(data_dir=tmp_path / "data", log_level="WARNING")
    store = Store(cfg.data_dir / "headerproxy.db")
    store.ensure_default_session(True)
    engine = Engine(store)
    engine.reload()
    return Runtime(cfg=cfg, store=store, engine=engine, ca=None, upstream=None, proxy=None)


def build_client(runtime, api_key=None):
    if api_key:
        cfg = Config(
            data_dir=runtime.cfg.data_dir,
            log_level="WARNING",
            api_key=api_key,
        )
        runtime = Runtime(cfg=cfg, store=runtime.store, engine=runtime.engine, ca=None, upstream=None, proxy=None)
    return TestClient(create_app(runtime, mcp_app=None))


def test_root_and_health(runtime):
    with build_client(runtime) as client:
        info = client.get("/").json()
        assert info["name"] == "HeaderProxy"
        assert client.get("/api/health").json() == {"status": "ok"}


def test_status(runtime):
    with build_client(runtime) as client:
        status = client.get("/api/status").json()
        assert status["active_session"] == "default"
        assert status["stealth"] is True


def test_full_override_flow(runtime):
    with build_client(runtime) as client:
        # filter
        f = client.post(
            "/api/sessions/default/filters",
            json={"host": "*.example.com", "comment": "scoped"},
        )
        assert f.status_code == 201
        filter_id = f.json()["id"]

        # inject request header override scoped by the filter
        o = client.post(
            "/api/sessions/default/overrides",
            json={"action": "set", "header": "X-Injected", "value": "yes", "filter_id": filter_id},
        )
        assert o.status_code == 201
        body = o.json()
        assert body["direction"] == "request"
        assert body["filter_id"] == filter_id

        # list
        rows = client.get("/api/sessions/default/overrides").json()
        assert len(rows) == 1

        # remove single override
        assert client.delete(f"/api/sessions/default/overrides/{body['id']}").status_code == 204
        assert client.get("/api/sessions/default/overrides").json() == []

        # 404 for unknown override
        assert client.delete("/api/sessions/default/overrides/999").status_code == 404


def test_override_validation_errors(runtime):
    with build_client(runtime) as client:
        r = client.post(
            "/api/sessions/default/overrides", json={"action": "set", "header": "X-A"}
        )  # missing value
        assert r.status_code == 400
        r = client.post(
            "/api/sessions/default/overrides",
            json={"direction": "nope", "action": "set", "header": "X-A", "value": "1"},
        )
        assert r.status_code == 400


def test_session_lifecycle(runtime):
    with build_client(runtime) as client:
        assert client.post("/api/sessions", json={"name": "work"}).status_code == 201
        assert client.post("/api/sessions", json={"name": "work"}).status_code == 409

        # active session copy -> save as
        client.post(
            "/api/sessions/default/overrides",
            json={"action": "set", "header": "X-From-Default", "value": "1"},
        )
        saved = client.post("/api/sessions/work/save").json()
        assert saved["override_count"] == 1

        # switch
        assert client.post("/api/sessions/work/activate").status_code == 200
        assert client.get("/api/status").json()["active_session"] == "work"

        # delete active refused
        assert client.delete("/api/sessions/work").status_code == 409
        client.post("/api/sessions/default/activate")
        assert client.delete("/api/sessions/work").status_code == 204

        # clean (X-From-Default from the save step is still there)
        client.post(
            "/api/sessions/default/overrides",
            json={"action": "set", "header": "X-Clean-Me", "value": "1"},
        )
        removed = client.delete("/api/sessions/default/overrides").json()
        assert removed == {"removed": 2}
        assert client.get("/api/sessions/default/overrides").json() == []


def test_session_stealth_toggle(runtime):
    with build_client(runtime) as client:
        r = client.patch("/api/sessions/default", json={"stealth": False})
        assert r.json()["stealth"] is False


def test_api_key_auth(tmp_path):
    cfg = Config(data_dir=tmp_path / "data", log_level="WARNING", api_key="sekret")
    store = Store(cfg.data_dir / "db.sqlite")
    store.ensure_default_session(True)
    rt = Runtime(cfg=cfg, store=store, engine=Engine(store), ca=None, upstream=None, proxy=None)
    with TestClient(create_app(rt, mcp_app=None)) as client:
        assert client.get("/api/status").status_code == 401
        assert client.get("/api/health").status_code == 200
        bad = client.get("/api/status", headers={"Authorization": "Bearer wrong"})
        assert bad.status_code == 401
        good = client.get("/api/status", headers={"Authorization": "Bearer sekret"})
        assert good.status_code == 200
        assert client.get("/mcp", headers={"Authorization": "Bearer sekret"}).status_code != 401
