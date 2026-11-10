"""leash — append-only evidence store: tool-call ledger, findings, report."""

import json
import os
from datetime import datetime, timezone

try:
    from hermes_constants import get_hermes_home
except ImportError:  # standalone test / older runtime
    def get_hermes_home():
        return os.environ.get(
            "HERMES_HOME",
            os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "hermes"),
        )

MAX_EXCERPT = 600


def data_dir() -> str:
    d = os.path.join(get_hermes_home(), "plugin-data", "leash")
    os.makedirs(d, exist_ok=True)
    return d


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(name: str, record: dict) -> None:
    with open(os.path.join(data_dir(), name), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def log_call(tool, args, status, duration_ms, session) -> None:
    _append("ledger.jsonl", {
        "ts": _now(), "kind": "call", "tool": str(tool),
        "args": str(args)[:MAX_EXCERPT], "status": str(status),
        "duration_ms": duration_ms, "session": str(session),
    })


def log_event(kind, tool, targets, bad, session, mode) -> None:
    _append("ledger.jsonl", {
        "ts": _now(), "kind": kind, "tool": str(tool),
        "targets": sorted(targets), "out_of_scope": sorted(bad),
        "mode": mode, "session": str(session),
    })


def add_finding(title, severity, status, evidence, source) -> dict:
    if status == "verified" and not (evidence or "").strip():
        return {"error": "a verified finding requires evidence: paste the command/output that proves it, or record it as hypothesis"}
    rec = {
        "ts": _now(), "title": str(title)[:300],
        "severity": str(severity).lower(), "status": str(status).lower(),
        "evidence": str(evidence or "")[:MAX_EXCERPT], "source": str(source or ""),
    }
    _append("findings.jsonl", rec)
    return {"ok": True, "finding": rec}


def stats() -> dict:
    calls = blocks = violations = 0
    hosts = set()
    ledger = os.path.join(data_dir(), "ledger.jsonl")
    if os.path.isfile(ledger):
        with open(ledger, "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("kind") == "call":
                    calls += 1
                elif rec.get("kind") == "block":
                    blocks += 1
                elif rec.get("kind") == "violation-audit":
                    violations += 1
                for t in rec.get("targets", []) or []:
                    hosts.add(t)
    findings = 0
    fpath = os.path.join(data_dir(), "findings.jsonl")
    if os.path.isfile(fpath):
        with open(fpath, "r", encoding="utf-8") as fh:
            findings = sum(1 for line in fh if line.strip())
    return {"calls": calls, "blocks": blocks, "audit_violations": violations,
            "findings": findings, "hosts_seen": sorted(hosts)}


def write_report(scope_summary: str, scope_error: str) -> str:
    st = stats()
    lines = [
        "# leash — pentest evidence report", "",
        f"Generated: {_now()}", "",
        f"## Scope", "",
        f"- Scope: {scope_summary}" if scope_summary else f"- Scope: UNAVAILABLE ({scope_error})",
        "", "## Activity", "",
        f"- Monitored tool calls: {st['calls']}",
        f"- Blocked (out of scope): {st['blocks']}",
        f"- Out-of-scope attempts (audit mode): {st['audit_violations']}",
        f"- Hosts seen in monitored calls: {', '.join(st['hosts_seen']) or 'none'}",
        "", "## Findings", "",
    ]
    fpath = os.path.join(data_dir(), "findings.jsonl")
    if os.path.isfile(fpath):
        with open(fpath, "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    f = json.loads(line)
                except json.JSONDecodeError:
                    continue
                lines.append(f"### [{f['severity']}] {f['title']} — {f['status']}")
                lines.append(f"- Time: {f['ts']}")
                if f.get("source"):
                    lines.append(f"- Source: {f['source']}")
                if f.get("evidence"):
                    lines.append(f"- Evidence:\n  ```\n  {f['evidence']}\n  ```")
                lines.append("")
    else:
        lines.append("_No findings recorded._")
    out = os.path.join(data_dir(), "report.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return out
