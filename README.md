# leash

Scope enforcement and evidence ledger for agent-driven security testing in
[Hermes Agent](https://github.com/NousResearch/hermes-agent).

A pentest agent is dangerous precisely because it is good at its job: nothing
stops a `curl` or an `nmap` aimed at a host the user never authorized. leash
constrains that with a hard gate and keeps the evidence that proves each
finding.

## What it does

- **Scope gate** (`pre_tool_call`): monitored tools (`terminal`, `web_extract`,
  `browser_*`) have their arguments scanned for network targets — URLs, host
  names, IPv4s. In `enforce` mode, a call that touches anything outside the
  scope file is **blocked** before it runs, with a message telling the agent
  why. In `audit` mode the attempt is only recorded. With no usable scope
  file, enforce mode fails closed (blocks every network-capable call).
- **Evidence ledger** (`post_tool_call`): every monitored call is appended to a
  local JSONL ledger — what ran, on what, with what status.
- **Findings**: `leash_finding` records a finding; status `verified` is
  refused unless the evidence excerpt is present. Hypotheses stay labelled as
  hypotheses.
- **Report**: `leash_report` writes a markdown report — scope, activity,
  blocked attempts, findings with evidence.

## Scope file

```json
{
  "target": "crAPI lab",
  "authorization": "local lab, owned by me",
  "allowed_hosts": ["127.0.0.1", "localhost"],
  "allowed_cidrs": ["192.168.10.0/24"]
}
```

Wildcards (`*.lab.local`) are supported. DNS is never resolved; matching is
literal.

## Configuration

`plugins.entries.leash.settings` in profile `config.yaml`:

| Key | Default | Meaning |
|---|---|---|
| `mode` | `audit` | `off` / `audit` / `enforce` |
| `scope_file` | *(empty)* | Path to the scope JSON |
| `monitored_tools` | `["terminal", "web_extract"]` | Tool names monitored (`browser_*` always monitored) |

## Tools

- `leash_scope` — show scope, mode and ledger stats
- `leash_finding` — record a finding (`hypothesis` | `verified` + evidence)
- `leash_report` — write the markdown report

## Disclosure

- `pre_tool_call` sees the arguments of monitored tools; arguments may contain
  user content or secrets. Excerpts (first 600 chars) are stored **locally**
  under `$HERMES_HOME/plugin-data/leash/` and are never sent anywhere.
- No network calls, no telemetry, no dependencies beyond the Python stdlib.
- Enforcement is a policy gate, not a sandbox: a tool call to an in-scope host
  runs with the agent's normal permissions.
- `enforce` mode blocks out-of-scope network-capable calls even under cron and
  messaging gateways; nothing waits on a human, so unattended runs fail fast
  instead of hanging.

## Install

```sh
hermes plugins install nicoarias81/leash --enable
```

## Development

```sh
python -m pytest tests/ -q
hermes plugins validate . --install-deps
hermes plugins doctor . --ci
```
