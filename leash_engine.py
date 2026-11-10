"""leash — execution engine: TCP recon and raw HTTP probing, scope-gated.

Both primitives re-check the scope on every call (fail-closed) and append to
the evidence ledger. Stdlib only: socket, http.client, concurrent.futures.
"""

import hashlib
import http.client
import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor

try:
    from . import leash_scope as _scope
    from . import leash_store as _store
except ImportError:
    import leash_scope as _scope
    import leash_store as _store

COMMON_PORTS = [80, 443, 8000, 8080, 8443, 3000, 5000, 22, 21, 3306, 5432, 6379, 27017, 9200]
MAX_PORTS = 64
MAX_WORKERS = 16
CONNECT_TIMEOUT = 1.5
HTTP_TIMEOUT = 10
MAX_BODY = 4000


def _gate(host: str):
    """Resolve + authorize a target. Returns (ok, message)."""
    if not host:
        return False, "no target host given"
    h = _scope.normalize_host(host)
    if "://" in h:
        h = h.split("://", 1)[1].split("/", 1)[0]
        h = _scope.normalize_host(h)
    # resolve literals and hostnames so an approved name can't hide a bad IP
    ips = {h}
    try:
        import ipaddress
        ipaddress.ip_address(h)
    except ValueError:
        try:
            ips = {i[4][0] for i in socket.getaddrinfo(h, None)} or {h}
        except OSError:
            ips = {h}
    scope = _state_scope()
    if scope is None:
        return False, f"leash has no usable scope file — refusing to touch {h}"
    bad = sorted(ip for ip in ips if not scope.allows(ip))
    if bad:
        return False, (
            f"{h} resolves to {', '.join(bad)} — outside authorized scope "
            f"({scope.summary()}). Ask the user to extend the scope file or stop."
        )
    return True, h


def _state_scope():
    return _scope.CURRENT["scope"]


def tcp_scan(host, ports=None) -> dict:
    ok, msg = _gate(host)
    if not ok:
        return {"blocked": True, "reason": msg}
    port_list = sorted(set(int(p) for p in (ports or COMMON_PORTS)))[:MAX_PORTS]
    open_ports = []

    def probe(p):
        try:
            with socket.create_connection((msg, p), timeout=CONNECT_TIMEOUT):
                return p
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        open_ports = [p for p in ex.map(probe, port_list) if p]
    _store.log_event("scan", "leash_scan", {msg}, set(), "", "enforce")
    return {"host": msg, "scanned_ports": len(port_list), "open": open_ports}


def http_probe(host, port=80, tls=False, method="GET", path="/",
               headers=None, body="") -> dict:
    ok, msg = _gate(host)
    if not ok:
        return {"blocked": True, "reason": msg}
    hdrs = {str(k)[:200]: str(v)[:400] for k, v in (headers or {}).items()}
    if body and "content-length" not in {k.lower() for k in hdrs}:
        hdrs["Content-Length"] = str(len(body.encode()))
    try:
        conn = (http.client.HTTPSConnection if tls else http.client.HTTPConnection)(
            msg, port=int(port), timeout=HTTP_TIMEOUT)
        conn.request(method.upper()[:10], (path or "/")[:2000],
                     body=body.encode()[:MAX_BODY] if body else None, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read(MAX_BODY)
        conn.close()
    except OSError as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    result = {
        "request": f"{method.upper()} {path} HTTP/1.1\nHost: {msg}:{port}\n" +
                   "\n".join(f"{k}: {v}" for k, v in hdrs.items()) +
                   (f"\n\n{body[:MAX_BODY]}" if body else ""),
        "status": resp.status,
        "headers": dict(resp.getheaders()),
        "body": raw.decode("utf-8", "replace"),
    }
    _store.log_call("leash_request", result["request"], str(resp.status), 0, "")
    return result


# --- fuzzing: payload variants with automatic detection ---------------------

_SQL_ERRORS = [
    "you have an error in your sql syntax", "unclosed quotation mark",
    "sqlite3.", "sqlstate", "ora-", "psql:", "warning: mysql",
    "unterminated string", "syntax error at or near",
]
_MAX_VARIANTS = 20


def fuzz(host, port=80, tls=False, method="GET", path="/search", param="q",
         payloads=None, use_body=False, headers=None, baseline_value=None,
         body_format="form") -> dict:
    """Run payload variants against one parameter; detect reflection, SQL
    errors and error deltas vs a baseline. The model crafts payloads; the
    plugin measures the responses. Pass baseline_value with a known-benign
    input so status/size deltas are meaningful."""
    ok, msg = _gate(host)
    if not ok:
        return {"blocked": True, "reason": msg}
    from urllib.parse import quote
    payloads = [str(p)[:500] for p in (payloads or [])][:_MAX_VARIANTS]
    if not payloads:
        return {"error": "no payloads given — craft 2-10 candidate payloads and pass them in 'payloads'"}
    base_headers = {str(k): str(v) for k, v in (headers or {}).items()}

    def send(value):
        if use_body:
            if body_format == "json":
                body = json.dumps({param: value})
                ct = "application/json"
            else:
                body = f"{param}={quote(value)}"
                ct = "application/x-www-form-urlencoded"
            spec = {"host": msg, "port": port, "tls": tls, "method": "POST", "path": path}
            resp = _do_request(spec, base_headers | {"Content-Type": ct}, body)
        else:
            sep = "&" if "?" in path else "?"
            spec = {"host": msg, "port": port, "tls": tls, "method": method, "path": f"{path}{sep}{param}={quote(value)}"}
            resp = _do_request(spec, base_headers, "")
        return resp

    base = send(str(baseline_value) if baseline_value else "leashbaseline9")
    base_len = len(base["body"])
    variants = []
    for p in payloads:
        resp = send(p)
        low = resp["body"].lower()
        sql_err = any(sig in low for sig in _SQL_ERRORS)
        reflected = p in resp["body"] or quote(p) in resp["body"]
        flags = []
        if sql_err:
            flags.append("SQL-ERROR in response — error-based injection candidate")
        if reflected:
            flags.append("payload REFLECTED unescaped — reflected-XSS candidate")
        if resp["status"] >= 500:
            flags.append(f"server error {resp['status']} on this payload")
        if resp["status"] != base["status"]:
            flags.append(f"status change vs baseline ({base['status']} -> {resp['status']})")
        if abs(len(resp["body"]) - base_len) > 200:
            flags.append(f"body size delta vs baseline ({base_len} -> {len(resp['body'])})")
        variants.append({"payload": p, "status": resp["status"], "len": len(resp["body"]),
                         "flags": flags})
        _store.log_call("leash_fuzz", f"{method} {path} [{param}={p[:80]}]", str(resp["status"]), 0, "")
    hits = sum(1 for v in variants if v["flags"])
    _store.log_event("fuzz", "leash_fuzz", {msg}, set(), "", "enforce")
    out = {"target": f"{msg}:{port}", "endpoint": path, "param": param,
           "baseline": {"status": base["status"], "len": base_len},
           "variants": variants, "flagged": hits}
    if hits:
        out["verdict"] = (f"{hits}/{len(variants)} payloads triggered flags — "
                          "inspect flagged variants and verify manually before recording a finding")
    return out


# --- hardening audit: response security headers + cookie flags --------------

def headers_audit(host, port=80, tls=False, path="/") -> dict:
    """Fetch one in-scope URL and grade its security headers deterministically."""
    ok, msg = _gate(host)
    if not ok:
        return {"blocked": True, "reason": msg}
    resp = _do_request({"host": msg, "port": port, "tls": tls, "method": "GET", "path": path})
    hdrs = {k.lower(): v for k, v in resp["headers"].items()}
    findings = []

    def missing(name, why):
        if name not in hdrs:
            findings.append(f"missing {name}: {why}")

    missing("content-security-policy", "no CSP — injected scripts run unrestricted")
    missing("x-content-type-options", "MIME sniffing allowed")
    if tls:
        missing("strict-transport-security", "no HSTS on TLS site")
    if "x-frame-options" not in hdrs and "frame-ancestors" not in hdrs.get("content-security-policy", ""):
        findings.append("no X-Frame-Options / frame-ancestors — clickjacking possible")
    aco = hdrs.get("access-control-allow-origin", "")
    if aco == "*" and hdrs.get("access-control-allow-credentials", "").lower() == "true":
        findings.append("CORS: wildcard origin WITH credentials — any site can read authenticated responses")
    for raw in (v for k, v in resp["headers"].items() if k.lower() == "set-cookie"):
        low = raw.lower()
        name = raw.split("=")[0]
        gaps = [f for f in ("httponly", "secure", "samesite") if f not in low]
        if gaps:
            findings.append(f"cookie '{name}' without {', '.join(gaps)}")
    _store.log_call("leash_audit", f"GET {path}", str(resp["status"]), 0, "")
    return {"target": f"{msg}:{port}", "path": path, "status": resp["status"],
            "headers": {k.lower(): v for k, v in resp["headers"].items() if k.lower() != "set-cookie"},
            "findings": findings,
            "grade": "pass" if not findings else f"{len(findings)} issue(s)"}


def _identities_path() -> str:
    return os.path.join(_store.data_dir(), "identities.json")


def _load_identities() -> dict:
    p = _identities_path()
    if os.path.isfile(p):
        try:
            with open(p, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
    return {}


def _save_identities(idents: dict) -> None:
    with open(_identities_path(), "w", encoding="utf-8") as fh:
        json.dump(idents, fh, indent=1)


def _session_headers(ident: dict) -> dict:
    hdrs = {}
    for c in ident.get("cookies", []):
        hdrs.setdefault("Cookie", []).append(c)
    if ident.get("bearer"):
        hdrs["Authorization"] = "Bearer " + ident["bearer"]
    return {k: "; ".join(v) if isinstance(v, list) else v for k, v in hdrs.items()}


def _do_request(spec: dict, extra_headers=None, body=None) -> dict:
    """Raw request without gating (gating already done) -> parsed response."""
    hdrs = {str(k): str(v) for k, v in (extra_headers or {}).items()}
    conn = (http.client.HTTPSConnection if spec.get("tls") else http.client.HTTPConnection)(
        spec["host"], port=int(spec.get("port", 80)), timeout=HTTP_TIMEOUT)
    conn.request(spec.get("method", "GET").upper()[:10], (spec.get("path") or "/")[:2000],
                 body=body.encode() if body else None, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read(65536)
    conn.close()
    return {"status": resp.status, "headers": dict(resp.getheaders()),
            "body": raw.decode("utf-8", "replace"), "time_ms": 0}


def login(host, port=80, tls=False, method="POST", path="/login", headers=None,
          body="", identity="user", token_field="token") -> dict:
    """Authenticate as one identity; keep its session inside the plugin."""
    ok, msg = _gate(host)
    if not ok:
        return {"blocked": True, "reason": msg}
    spec = {"host": msg, "port": port, "tls": tls, "method": method, "path": path}
    resp = _do_request(spec, {str(k)[:200]: str(v)[:400] for k, v in (headers or {}).items()}, body)
    cookies = []
    for k, v in resp["headers"].items():
        if k.lower() == "set-cookie":
            cookies.append(v.split(";")[0])
    bearer = ""
    try:
        bearer = str(json.loads(resp["body"]).get(token_field, ""))[:4000]
    except (json.JSONDecodeError, AttributeError):
        pass
    if not cookies and not bearer:
        return {"error": "no session found in response (no Set-Cookie, no JSON token field)",
                "status": resp["status"]}
    idents = _load_identities()
    key = f"{msg}:{port}"
    idents.setdefault(key, {})
    idents[key][identity] = {"cookies": cookies, "bearer": bearer,
                             "login_path": path, "ts": _store._now()}
    _save_identities(idents)
    return {"ok": True, "identity": identity, "target": key,
            "session": f"{len(cookies)} cookie(s)" + (", bearer token" if bearer else ""),
            "note": "credentials stored inside the plugin; they never enter the model context"}


def replay(host, port=80, tls=False, method="GET", path="/", headers=None,
           identities=None, bodies=None, canaries=None) -> dict:
    """Replay one request as each stored identity and diff the responses.

    canaries: {identity: [strings unique to that identity]} — e.g. their
    email, user id or an object id only they own. If identity A's canary
    shows up in identity B's response, data crosses the access-control
    boundary: that is a verified leak, for any API, not just a known lab."""
    ok, msg = _gate(host)
    if not ok:
        return {"blocked": True, "reason": msg}
    idents = _load_identities().get(f"{msg}:{port}", {})
    wanted = identities or list(idents.keys())
    if len(wanted) < 2:
        return {"error": f"need 2+ stored identities for {msg}:{port}; use login() first (have: {list(idents)})"}
    bodies_map = {str(k): str(v) for k, v in (bodies or {}).items()}
    results = {}
    raw_bodies = {}
    for name in wanted[:4]:
        ident = idents.get(name)
        if not ident:
            results[name] = {"error": "unknown identity"}
            continue
        t0 = time.monotonic()
        resp = _do_request({"host": msg, "port": port, "tls": tls, "method": method, "path": path},
                           _session_headers(ident) | {str(k): str(v) for k, v in (headers or {}).items()},
                           bodies_map.get(name, ""))
        resp["time_ms"] = int((time.monotonic() - t0) * 1000)
        raw_bodies[name] = resp["body"]
        results[name] = {
            "status": resp["status"], "body_len": len(resp["body"]),
            "body_sha1": hashlib.sha1(resp["body"].encode()).hexdigest()[:12],
            "time_ms": resp["time_ms"],
        }
        _store.log_call("leash_replay", f"{method} {path} as {name}", str(resp["status"]), 0, "")

    leaks = []
    for owner, markers in (canaries or {}).items():
        for marker in [str(m) for m in markers][:10]:
            for viewer, rb in raw_bodies.items():
                if viewer != owner and marker and marker in rb:
                    leaks.append({"owner": owner, "viewer": viewer,
                                  "marker_seen": marker[:80]})
    ok_names = [n for n, r in results.items() if r.get("status", 500) < 400]
    hashes = {results[n].get("body_sha1") for n in ok_names}
    verdict = None
    if leaks:
        verdict = ("CROSS-IDENTITY LEAK: data owned by one identity appeared in "
                   "another identity's response — broken object-level "
                   "authorization, verified")
    elif len(ok_names) >= 2 and len(hashes) == 1:
        verdict = ("ACCESS-CONTROL FAILURE candidate: different identities received "
                   "byte-identical responses — confirm the data should be shared")
    elif len(ok_names) >= 2:
        verdict = ("responses differ per identity and no canary crossed; "
                   "no leak detected on this endpoint")
    _store.log_event("replay", "leash_replay", {msg}, set(), "", "enforce")
    out = {"target": f"{msg}:{port}", "request": f"{method} {path}", "results": results}
    if leaks:
        out["leaks"] = leaks
    if verdict:
        out["verdict"] = verdict
    return out


def crawl(host, port=80, tls=False, start="/", max_pages=30) -> dict:
    """Same-origin BFS crawl of an in-scope app; persists an endpoint inventory."""
    ok, msg = _gate(host)
    if not ok:
        return {"blocked": True, "reason": msg}
    from html.parser import HTMLParser

    class P(HTMLParser):
        def __init__(self):
            super().__init__()
            self.links, self.forms = set(), []
            self._form = None
        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "a" and a.get("href"):
                self.links.add(a["href"])
            elif tag == "form" and self._form is None:
                self._form = {"action": a.get("action", ""), "inputs": []}
            elif tag == "input" and self._form is not None:
                self._form["inputs"].append(f"{a.get('type', 'text')}:{a.get('name', '')}")
        def handle_endtag(self, tag):
            if tag == "form" and self._form is not None:
                self.forms.append(self._form)
                self._form = None

    base = f"https://{msg}" if tls else f"http://{msg}"
    seen, pages, queue = set(), [], [(start or "/")[:2000]]
    pages = []
    forms_found = []
    while queue and len(seen) < int(max_pages):
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        try:
            resp = _do_request({"host": msg, "port": port, "tls": tls, "method": "GET", "path": path})
        except OSError as exc:
            pages.append({"path": path, "error": str(exc)[:100]})
            continue
        if resp["status"] >= 400 or "html" not in resp["headers"].get("Content-Type", "").lower():
            pages.append({"path": path, "status": resp["status"]})
            continue
        p = P()
        p.feed(resp["body"])
        pages.append({"path": path, "status": resp["status"], "forms": len(p.forms)})
        forms_found += [{"page": path, **f} for f in p.forms]
        for href in p.links:
            if href.startswith(base):
                href = href[len(base):] or "/"
            if href.startswith("/") and "#" not in href and href not in seen:
                queue.append(href[:2000])
    inv_path = os.path.join(_store.data_dir(), "inventory.jsonl")
    with open(inv_path, "a", encoding="utf-8") as fh:
        for pg in pages:
            if "status" in pg:
                fh.write(json.dumps({"ts": _store._now(), "host": msg, **pg}) + "\n")
    crawled = [p for p in pages if "status" in p]
    return {"host": msg, "pages": len(crawled), "ok_2xx": sum(1 for p in crawled if p["status"] < 300),
            "endpoints": sorted(p["path"] for p in crawled), "forms": forms_found,
            "inventory": inv_path}
