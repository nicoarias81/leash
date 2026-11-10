"""leash — parse and match an authorized pentest scope file.

Scope file format (JSON):
{
  "target": "crAPI lab",
  "authorization": "local lab, owned by me",
  "allowed_hosts": ["127.0.0.1", "localhost", "*.lab.local"],
  "allowed_cidrs": ["192.168.10.0/24"],
  "notes": "..."
}
"""

import ipaddress
import json
import os
import re
from urllib.parse import urlsplit

MAX_TEXT = 200_000

_URL_RE = re.compile(
    r"https?://(\[(?:[0-9a-fA-F:]+)\]|[A-Za-z0-9._\-]+)(?::\d+)?", re.I
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:com|net|org|io|dev|app|xyz|info|co|me|local|test|example|lan|internal)\b",
    re.I,
)


class ScopeError(Exception):
    pass


# the active scope, set by the plugin's register/_reload; engine reads this
CURRENT = {"scope": None}


def normalize_host(host: str) -> str:
    host = (host or "").strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.rstrip(".")


def extract_targets(text: str) -> set:
    """Pull candidate network targets out of arbitrary tool-argument text."""
    if not text or len(text) > MAX_TEXT:
        return set()
    targets = set()
    for m in _URL_RE.finditer(text):
        targets.add(normalize_host(m.group(1)))
    for m in _IPV4_RE.finditer(text):
        targets.add(m.group(0))
    for m in _DOMAIN_RE.finditer(text):
        targets.add(normalize_host(m.group(0)))
    # IPv4s already caught by the domain regex when a TLD-looking octet follows
    return {t for t in targets if t and ("." in t or t == "localhost")}


class Scope:
    def __init__(self, data: dict, path: str):
        self.path = path
        self.target = str(data.get("target") or "unspecified")
        self.authorization = str(data.get("authorization") or "")
        self.hosts = {normalize_host(h) for h in data.get("allowed_hosts", []) if h}
        self.wildcards = set()
        for h in list(self.hosts):
            if h.startswith("*."):
                self.hosts.discard(h)
                self.wildcards.add(h[2:])
        self.networks = []
        for cidr in data.get("allowed_cidrs", []):
            try:
                self.networks.append(ipaddress.ip_network(str(cidr), strict=False))
            except ValueError as exc:
                raise ScopeError(f"invalid CIDR {cidr!r} in {path}: {exc}")

    def allows(self, host: str) -> bool:
        host = normalize_host(host)
        if not host:
            return False
        if host in self.hosts:
            return True
        for suffix in self.wildcards:
            if host == suffix or host.endswith("." + suffix):
                return True
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in self.networks)

    def summary(self) -> str:
        hosts = ", ".join(sorted(self.hosts | {f"*.{w}" for w in self.wildcards})) or "none"
        nets = ", ".join(str(n) for n in self.networks) or "none"
        return f"target={self.target} hosts=[{hosts}] cidrs=[{nets}]"


def load_scope(path: str) -> Scope:
    if not path:
        raise ScopeError("no scope file configured (plugins.entries.leash.scope_file)")
    if not os.path.isfile(path):
        raise ScopeError(f"scope file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ScopeError(f"scope file unreadable: {path}: {exc}")
    if not isinstance(data, dict):
        raise ScopeError(f"scope file must be a JSON object: {path}")
    if not data.get("allowed_hosts") and not data.get("allowed_cidrs"):
        raise ScopeError(f"scope file has no allowed_hosts/allowed_cidrs: {path}")
    return Scope(data, path)
