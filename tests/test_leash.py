import importlib.util
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN = os.path.dirname(_HERE)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_PLUGIN, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


scope = _load("leash_scope")
store = _load("leash_store")


@pytest.fixture()
def scope_file(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(
        '{"target": "lab", "authorization": "mine",'
        ' "allowed_hosts": ["127.0.0.1", "localhost", "*.lab.local"],'
        ' "allowed_cidrs": ["192.168.10.0/24"]}',
        encoding="utf-8",
    )
    return str(p)


def test_extract_targets_urls_ips_domains():
    t = scope.extract_targets(
        'curl -s https://api.evil.com/x && nmap 192.168.10.7 scanme.nmap.org http://LOCALHOST:8000'
    )
    assert "api.evil.com" in t
    assert "192.168.10.7" in t
    assert "scanme.nmap.org" in t
    assert "localhost" in t


def test_extract_targets_ignores_plain_args():
    assert scope.extract_targets("pip install requests") == set()
    assert scope.extract_targets("") == set()


def test_scope_allows_exact_wildcard_cidr(scope_file):
    s = scope.load_scope(scope_file)
    assert s.allows("127.0.0.1")
    assert s.allows("LOCALHOST")
    assert s.allows("api.lab.local")
    assert s.allows("192.168.10.99")
    assert not s.allows("api.evil.com")
    assert not s.allows("192.168.11.1")


def test_scope_load_errors(tmp_path):
    with pytest.raises(scope.ScopeError):
        scope.load_scope("")
    with pytest.raises(scope.ScopeError):
        scope.load_scope(str(tmp_path / "missing.json"))
    bad = tmp_path / "bad.json"
    bad.write_text('{"allowed_hosts": []}', encoding="utf-8")
    with pytest.raises(scope.ScopeError):
        scope.load_scope(str(bad))


def test_verified_finding_requires_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    out = store.add_finding("idor", "high", "verified", "", "")
    assert "error" in out
    out = store.add_finding("idor", "high", "verified", "GET /api/v2/identity → 200 other user", "curl")
    assert out.get("ok")
    st = store.stats()
    assert st["findings"] == 1
