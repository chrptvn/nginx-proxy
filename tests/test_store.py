"""Store semantics: sessions, overrides, filters, save/activate/delete."""

import pytest

from headerproxy.store import Store, StoreError


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "test.db")
    s.ensure_default_session()
    yield s
    s.close()


def test_default_session_created_and_active(store):
    sessions = store.list_sessions()
    assert [s.name for s in sessions] == ["default"]
    assert sessions[0].active is True
    assert sessions[0].stealth is True


def test_create_and_list_sessions(store):
    store.create_session("scraping")
    store.create_session("testing", stealth=False)
    names = {s.name for s in store.list_sessions()}
    assert names == {"default", "scraping", "testing"}
    assert store.get_session("testing").stealth is False


def test_create_duplicate_session(store):
    store.create_session("dup")
    with pytest.raises(StoreError, match="already exists"):
        store.create_session("dup")


def test_invalid_session_name(store):
    for bad in ("", "a b", "x/y", "n\nl"):
        with pytest.raises(StoreError):
            store.create_session(bad)


def test_activate_switches_exactly_one(store):
    store.create_session("b")
    store.activate_session("b")
    active = [s.name for s in store.list_sessions() if s.active]
    assert active == ["b"]
    store.activate_session("default")
    assert store.get_active_session().name == "default"


def test_activate_missing_session(store):
    with pytest.raises(StoreError, match="does not exist"):
        store.activate_session("ghost")


def test_save_session_copies_active_config(store):
    f = store.add_filter("default", "*.example.com")
    store.add_override("default", "request", "set", "X-Test", "1", filter_id=f.id)
    saved = store.save_session("snapshot-1")

    assert saved.name == "snapshot-1"
    assert saved.override_count == 1
    assert saved.filter_count == 1
    # filters were re-created under the new session with new ids
    assert store.list_filters("snapshot-1")[0].id != f.id
    overrides = store.list_overrides("snapshot-1")
    assert overrides[0].filter_id == store.list_filters("snapshot-1")[0].id


def test_save_session_replaces_existing_target(store):
    store.create_session("old")
    store.add_override("old", "request", "set", "X-Old", "1")
    store.add_override("default", "request", "set", "X-New", "1")
    store.save_session("old")
    names = {o.header for o in store.list_overrides("old")}
    assert names == {"X-New"}


def test_save_onto_active_is_checkpoint(store):
    store.add_override("default", "request", "set", "X-A", "1")
    saved = store.save_session("default")
    assert saved.name == "default"
    assert saved.override_count == 1


def test_delete_session_cascades(store):
    store.create_session("temp")
    store.add_override("temp", "request", "set", "X-A", "1")
    store.add_filter("temp", "*.example.com")
    store.delete_session("temp")
    assert all(s.name != "temp" for s in store.list_sessions())
    assert store.list_overrides("temp") == []
    assert store.list_filters("temp") == []


def test_delete_active_session_refused(store):
    with pytest.raises(StoreError, match="is active"):
        store.delete_session("default")


def test_override_validation(store):
    with pytest.raises(StoreError, match="direction"):
        store.add_override("default", "sideways", "set", "X-A", "1")
    with pytest.raises(StoreError, match="action"):
        store.add_override("default", "request", "merge", "X-A", "1")
    with pytest.raises(StoreError, match="value is required"):
        store.add_override("default", "request", "set", "X-A", None)
    with pytest.raises(StoreError, match="header name"):
        store.add_override("default", "request", "set", "Bad Header", "1")
    # remove overrides ignore value
    o = store.add_override("default", "request", "remove", "X-A", "ignored")
    assert o.value is None


def test_override_requires_existing_filter(store):
    with pytest.raises(StoreError, match="filter"):
        store.add_override("default", "request", "set", "X-A", "1", filter_id=999)


def test_clean_overrides_keeps_filters(store):
    store.add_override("default", "request", "set", "X-A", "1")
    store.add_override("default", "response", "remove", "Server")
    f = store.add_filter("default", "example.com")
    removed = store.clean_overrides("default")
    assert removed == 2
    assert store.list_overrides("default") == []
    assert store.list_filters("default")[0].id == f.id


def test_delete_filter_unscopes_overrides(store):
    f = store.add_filter("default", "example.com")
    o = store.add_override("default", "request", "set", "X-A", "1", filter_id=f.id)
    store.delete_filter("default", f.id)
    assert store.get_override("default", o.id).filter_id is None


def test_delete_missing_rows_raise(store):
    with pytest.raises(StoreError):
        store.delete_override("default", 1234)
    with pytest.raises(StoreError):
        store.delete_filter("default", 1234)
