"""leash — execution engine: TCP recon and raw HTTP probing, scope-gated.

Both primitives re-check the scope on every call (fail-closed) and append to
the evidence ledger. Stdlib only: socket, http.client, concurrent.futures.
"""

import http.client
import json
import socket
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
