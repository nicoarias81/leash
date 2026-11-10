"""leash — scope enforcement and evidence ledger for agent-driven security testing.

Surfaces (all public Hermes plugin APIs):
- hooks: pre_tool_call (scope gate, block/approve), post_tool_call (evidence ledger)
- tools: leash_scope, leash_finding, leash_report
No core patching, no network calls, stdlib only.
"""

import json

try:
    from . import leash_scope as _scope
    from . import leash_store as _store
except ImportError:  # namespaced/flat load
    import leash_scope as _scope
    import leash_store as _store

DEFAULT_MONITORED = {"terminal", "web_extract"}
MAX_ARG_TEXT = 8000

_state = {
    "mode": "audit",
    "scope_file": "",
    "monitored": set(DEFAULT_MONITORED),
    "scope": None,
    "scope_error": "not loaded yet",
}


def _reload(ctx) -> None:
    try:
        cfg = ctx.get_config() or {}
    except Exception:
        cfg = {}
    mode = str(cfg.get("mode") or "audit").lower()
    if mode not in ("off", "audit", "enforce"):
        mode = "audit"
    _state["mode"] = mode
    _state["scope_file"] = str(cfg.get("scope_file") or "")
    monitored = cfg.get("monitored_tools")
    _state["monitored"] = (
        {str(t) for t in monitored} if isinstance(monitored, list) and monitored
        else set(DEFAULT_MONITORED)
    )
    try:
        _state["scope"] = _scope.load_scope(_state["scope_file"])
        _state["scope_error"] = ""
    except _scope.ScopeError as exc:
        _state["scope"] = None
        _state["scope_error"] = str(exc)


def _is_monitored(tool_name: str) -> bool:
    return tool_name in _state["monitored"] or tool_name.startswith("browser")


def _args_text(args) -> str:
    if isinstance(args, str):
        return args[:MAX_ARG_TEXT]
    try:
        return json.dumps(args, default=str)[:MAX_ARG_TEXT]
    except Exception:
        return str(args)[:MAX_ARG_TEXT]


def _pre_tool_call(tool_name, args, task_id="", **kwargs):
    if _state["mode"] == "off" or not _is_monitored(tool_name):
        return None
    targets = _scope.extract_targets(_args_text(args))
    if not targets:
        return None

    bad, good = [], []
    if _state["scope"] is not None:
        for t in targets:
            (good if _state["scope"].allows(t) else bad).append(t)
    else:
        bad = sorted(targets)

    if not bad:
        return None

    if _state["scope"] is not None:
        reason = (
            f"target(s) outside authorized scope: {', '.join(sorted(bad))}. "
            f"Authorized scope: {_state['scope'].summary()}. "
            "Ask the user to add the host to the scope file (with written authorization) or stop."
        )
        kind = "block" if _state["mode"] == "enforce" else "violation-audit"
    else:
        reason = (
            f"leash has no usable scope file ({_state['scope_error']}) — refusing "
            f"network-capable tool call touching: {', '.join(sorted(bad))}. "
            "Set plugins.entries.leash.scope_file to a scope JSON with allowed_hosts."
        )
        kind = "block-no-scope"

    _store.log_event(kind, tool_name, targets, bad, task_id, _state["mode"])
    if _state["mode"] == "enforce":
        return {"action": "block", "message": f"leash [enforce]: {reason}"}
    return None


def _post_tool_call(tool_name, args, result, status="", duration_ms=0, task_id="", **kwargs):
    if _state["mode"] == "off" or not _is_monitored(tool_name):
        return None
    try:
        _store.log_call(tool_name, _args_text(args), status or "ok", duration_ms, task_id)
    except Exception:
        pass  # ledger must never break the agent
    return None


# --- tools -----------------------------------------------------------------

def _tool_leash_scope(args, **kwargs):
    from datetime import datetime, timezone
    info = {
        "mode": _state["mode"],
        "scope_file": _state["scope_file"],
        "scope": _state["scope"].summary() if _state["scope"] else None,
        "scope_error": _state["scope_error"],
        "monitored_tools": sorted(_state["monitored"]),
        "ledger": _store.stats(),
        "data_dir": _store.data_dir(),
        "loaded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return json.dumps(info, ensure_ascii=False)


def _tool_leash_finding(args, **kwargs):
    out = _store.add_finding(
        title=args.get("title", ""),
        severity=args.get("severity", "medium"),
        status=args.get("status", "hypothesis"),
        evidence=args.get("evidence", ""),
        source=args.get("source", ""),
    )
    return json.dumps(out, ensure_ascii=False)


def _tool_leash_report(args, **kwargs):
    out = _store.write_report(
        _state["scope"].summary() if _state["scope"] else "",
        _state["scope_error"],
    )
    return json.dumps({"ok": True, "report": out}, ensure_ascii=False)


LEASH_SCOPE_SCHEMA = {
    "name": "leash_scope",
    "description": (
        "Show the current leash pentest scope (authorized hosts/CIDRs), enforcement "
        "mode, and evidence-ledger stats. Use at the start of any security test to "
        "confirm what is in scope before touching anything."
    ),
    "parameters": {"type": "object", "properties": {}},
}

LEASH_FINDING_SCHEMA = {
    "name": "leash_finding",
    "description": (
        "Record a security finding with its evidence. status must be 'hypothesis' or "
        "'verified'; 'verified' is refused without an evidence excerpt (the command "
        "and output that prove it). Findings appear in leash_report."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Short finding title"},
            "severity": {"type": "string", "description": "low | medium | high | critical"},
            "status": {"type": "string", "description": "hypothesis | verified"},
            "evidence": {"type": "string", "description": "Command + output excerpt proving the finding (required for verified)"},
            "source": {"type": "string", "description": "Tool/command that produced the evidence"},
        },
        "required": ["title", "severity", "status"],
    },
}

LEASH_REPORT_SCHEMA = {
    "name": "leash_report",
    "description": (
        "Generate the markdown pentest report: scope, monitored activity, blocked "
        "out-of-scope attempts, and every finding with its evidence."
    ),
    "parameters": {"type": "object", "properties": {}},
}


def register(ctx) -> None:
    _reload(ctx)
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    ctx.register_hook("post_tool_call", _post_tool_call)
    ctx.register_tool(name="leash_scope", toolset="leash",
                      schema=LEASH_SCOPE_SCHEMA, handler=_tool_leash_scope)
    ctx.register_tool(name="leash_finding", toolset="leash",
                      schema=LEASH_FINDING_SCHEMA, handler=_tool_leash_finding)
    ctx.register_tool(name="leash_report", toolset="leash",
                      schema=LEASH_REPORT_SCHEMA, handler=_tool_leash_report)
