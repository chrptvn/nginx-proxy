"""Rule matching and application."""

from headerproxy.engine import apply_rules
from headerproxy.headers import Headers
from headerproxy.store import Override


def make_rule(id, direction="request", action="set", header="X-Test", value="1",
              host="*", path="*", priority=0, enabled=True, filter_id=None):
    o = Override(
        id=id,
        session="default",
        direction=direction,
        action=action,
        header=header,
        value=value,
        filter_id=filter_id,
        priority=priority,
        comment=None,
        enabled=enabled,
        created_at="now",
    )
    from headerproxy.engine import Rule

    return Rule.from_override(o, host, path)


def test_match_all_wildcard():
    rule = make_rule(1)
    assert rule.matches("example.com", "example.com", "/any/path")
    assert rule.matches("other.org", "other.org:8443", "/")


def test_match_host_glob():
    rule = make_rule(1, host="*.example.com")
    assert rule.matches("api.example.com", "api.example.com", "/")
    assert not rule.matches("example.com", "example.com", "/")
    assert not rule.matches("evilexample.com", "evilexample.com", "/")


def test_match_host_with_port():
    rule = make_rule(1, host="example.com:8080")
    assert rule.matches("example.com", "example.com:8080", "/")
    assert not rule.matches("example.com", "example.com", "/")


def test_match_path_glob():
    rule = make_rule(1, host="*", path="/api/*")
    assert rule.matches("example.com", "example.com", "/api/v1/users")
    assert not rule.matches("example.com", "example.com", "/web/index.html")


def test_apply_set_and_remove():
    rules = (
        make_rule(1, header="X-Foo", value="bar"),
        make_rule(2, action="remove", header="User-Agent"),
        make_rule(3, header="X-Foo", value="wins"),  # applied last, so it wins
    )
    h = Headers([("User-Agent", "test-agent"), ("Accept", "*/*")])
    applied = apply_rules(rules, h, "example.com", "example.com", "/")

    assert applied == [1, 2, 3]
    assert h.get("X-Foo") == "wins"
    assert not h.has("User-Agent")
    assert h.get("Accept") == "*/*"


def test_priority_ordering_higher_priority_applied_last():
    from headerproxy.engine import Engine, SessionRules

    engine = Engine.__new__(Engine)  # exercise only the sort order
    engine._lock = __import__("threading").Lock()

    low = make_rule(1, header="X-Foo", value="bar", priority=0)
    high = make_rule(3, header="X-Foo", value="wins", priority=10)
    snap = SessionRules(
        name="s", stealth=False, request_rules=tuple(sorted((low, high), key=lambda r: (r.priority, r.id)))
    )
    h = Headers()
    apply_rules(snap.request_rules, h, "example.com", "example.com", "/")
    assert h.get("X-Foo") == "wins"


def test_apply_disabled_skipped():
    rules = (make_rule(1, enabled=False, header="X-Foo", value="bar"),)
    h = Headers()
    assert apply_rules(rules, h, "example.com", "example.com", "/") == []
    assert not h.has("X-Foo")


def test_apply_host_mismatch_skipped():
    rules = (make_rule(1, host="other.com", header="X-Foo", value="bar"),)
    h = Headers()
    assert apply_rules(rules, h, "example.com", "example.com", "/") == []


def test_headers_set_preserves_position_and_removes_duplicates():
    h = Headers([("A", "1"), ("B", "2"), ("A", "3")])
    h.set("A", "only")
    assert h.to_list() == [("A", "only"), ("B", "2")]
    h.add("C", "4")
    assert h.get_all("A") == ["only"]
    h.remove("a")
    assert not h.has("A")
