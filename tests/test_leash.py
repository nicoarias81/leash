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
engine = _load("leash_engine")


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


def test_engine_blocks_out_of_scope(scope_file, tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    s = scope.load_scope(scope_file)
    scope.CURRENT["scope"] = s
    out = engine.tcp_scan("api.evil.com")
    assert out["blocked"] and "outside authorized scope" in out["reason"]
    out = engine.http_probe("api.evil.com")
    assert out["blocked"]
    scope.CURRENT["scope"] = None
    out = engine.http_probe("127.0.0.1")
    assert out["blocked"] and "no usable scope" in out["reason"]


def test_engine_scans_and_probes_local_server(scope_file, tmp_path, monkeypatch):
    import http.server
    import threading

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    scope.CURRENT["scope"] = scope.load_scope(scope_file)

    class H(http.server.BaseHTTPRequestHandler):
        def _respond(self, status):
            body = b'{"user": 2, "email": "victim@example.com"}'
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._respond(200 if self.path == "/api/identity/2" else 404)

        def do_POST(self):
            self._respond(404)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        scan = engine.tcp_scan("127.0.0.1", ports=[port])
        assert not scan.get("blocked") and port in scan["open"]
        probe = engine.http_probe("127.0.0.1", port=port, path="/api/identity/2")
        assert probe["status"] == 200 and "victim@example.com" in probe["body"]
        req = engine.http_probe("127.0.0.1", port=port, path="/x",
                                method="POST", headers={"X-A": "1"}, body="y=1")
        assert req["status"] == 404 and "X-A: 1" in req["request"]
    finally:
        srv.shutdown()
    scope.CURRENT["scope"] = None
