import importlib.util
import json
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
        def do_GET(self):
            if self.path == "/api/identity/1":
                body = b'{"id": 1, "email": "alice@example.com"}'
                self.send_response(200)
            elif self.path == "/api/identity/2":
                body = b'{"id": 2, "email": "victim@example.com"}'
                self.send_response(200)
            elif self.path == "/":
                body = b'<html><a href="/page2">p2</a><a href="https://evil.example.com/x">bad</a><form action="/login"><input type="text" name="user"></form></html>'
                self.send_response(200)
            elif self.path == "/page2":
                body = b'<html><a href="/page3">p3</a></html>'
                self.send_response(200)
            elif self.path == "/page3":
                body = b'<html>deep</html>'
                self.send_response(200)
            else:
                body = b'{}'
                self.send_response(404)
            self.send_header("Content-Type", "text/html" if body.startswith(b"<") else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path == "/api/login":
                length = int(self.headers.get("Content-Length", 0))
                creds = self.rfile.read(length).decode()
                user = json.loads(creds).get("user", "")
                body = json.dumps({"token": f"tok-{user}-123", "user": user}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"sid={user}-session; HttpOnly")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

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


def test_stateful_flow_login_replay_bola(scope_file, tmp_path, monkeypatch):
    """The core demo flow: two identities -> replay diff -> BOLA verdict."""
    import http.server
    import threading

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    scope.CURRENT["scope"] = scope.load_scope(scope_file)

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            creds = json.loads(self.rfile.read(length).decode())
            user = creds.get("user", "")
            body = json.dumps({"token": f"tok-{user}-123", "user": user}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"sid={user}-session; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            # BOLA: whoever asks for /api/identity/<id> gets the data, no check
            owner = {"/api/identity/1": "alice@example.com", "/api/identity/2": "victim@example.com"}
            body = json.dumps({"email": owner.get(self.path, "x@x.com")}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        login_a = engine.login("127.0.0.1", port=port, path="/api/login",
                               body='{"user":"alice","password":"pw"}', identity="userA")
        login_b = engine.login("127.0.0.1", port=port, path="/api/login",
                               body='{"user":"bob","password":"pw"}', identity="userB")
        assert login_a.get("ok") and login_b.get("ok"), (login_a, login_b)

        # BOLA: bob's session reads alice's data -> identical responses -> verdict
        r = engine.replay("127.0.0.1", port=port, path="/api/identity/1")
        assert "verdict" in r and "ACCESS-CONTROL FAILURE" in r["verdict"], r
        assert r["results"]["userA"]["body_sha1"] == r["results"]["userB"]["body_sha1"]
        f = store.add_finding("BOLA: any authenticated user reads /api/identity/<id>",
                              "high", "verified", evidence=r["verdict"] +
                              f" | userA sha={r['results']['userA']['body_sha1']}, userB sha={r['results']['userB']['body_sha1']}",
                              source=f"leash_replay GET /api/identity/1 as userA+userB")
        assert f.get("ok")

        # tokens really stayed out of the model's reach: identity store holds them
        idents = json.load(open(engine._identities_path(), encoding="utf-8"))
        assert idents[f"127.0.0.1:{port}"]["userA"]["bearer"] == "tok-alice-123"
    finally:
        srv.shutdown()
    scope.CURRENT["scope"] = None


def test_crawl_inventory(scope_file, tmp_path, monkeypatch):
    import http.server
    import threading

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    scope.CURRENT["scope"] = scope.load_scope(scope_file)

    pages = {
        "/": '<html><a href="/page2">p2</a><a href="https://evil.example.com/x">bad</a>'
             '<form action="/login"><input type="text" name="user"></form></html>',
        "/page2": '<html><a href="/page3">p3</a></html>',
        "/page3": '<html>deep</html>',
    }

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in pages:
                body = pages[self.path].encode()
                self.send_response(200)
            else:
                body = b"{}"
                self.send_response(404)
            self.send_header("Content-Type", "text/html" if self.path in pages else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        out = engine.crawl("127.0.0.1", port=port)
        assert out["pages"] == 3 and out["endpoints"] == ["/", "/page2", "/page3"], out
        assert out["forms"] and out["forms"][0]["inputs"] == ["text:user"]
        assert os.path.isfile(out["inventory"])
    finally:
        srv.shutdown()
    scope.CURRENT["scope"] = None
