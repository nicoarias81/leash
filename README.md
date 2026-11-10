# leash

Scope enforcement and evidence ledger for agent-driven security testing in
[Hermes Agent](https://github.com/NousResearch/hermes-agent).

A pentest agent is dangerous precisely because it is good at its job: nothing
stops a `curl` or an `nmap` aimed at a host the user never authorized. leash
constrains that with a hard gate and keeps the evidence that proves each
finding.

## What it does

leash is a **pentest toolkit**: it gives the agent the primitives to actually
run an authorized security test — recon, session-aware access-control
testing, findings, report — with a hard scope gate around every network
action. The primitives hold state between calls, which is what a prompt or a
skill cannot do.

- **Engine tools**:
  - `leash_scan` — TCP port scan of an in-scope host (common-services list or
    custom ports).
  - `leash_crawl` — same-origin BFS crawl; maps endpoints and forms into a
    persisted inventory that survives across sessions.
  - `leash_login` — authenticate an *identity* (user/admin/victim) and keep
    its cookies/bearer inside the plugin. The token never enters the model
    context, so it cannot leak into logs, transcripts or other tools' output.
  - `leash_replay` — replay the same request as 2+ stored identities and diff
    status/size/hash/timing. Byte-identical responses for different
    identities are flagged as an access-control failure (BOLA/IDOR) — the
    differential proof, computed by the plugin, not the model.
  - `leash_request` — one raw HTTP(S) request for anything the higher-level
    tools don't cover.
- **Scope gate** (`pre_tool_call` + inside every engine tool): arguments of
  monitored tools (`terminal`, `web_extract`, `browser_*`) are scanned for
  network targets; the engine tools additionally re-check the scope on every
  call, resolving hostnames so an approved name can't hide an out-of-scope IP.
  In `enforce` mode anything outside the scope file is **blocked** before it
  runs. With no usable scope file, the engine fails closed.
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

- `leash_scan` — TCP recon of an in-scope host
- `leash_crawl` — same-origin crawl → persisted endpoint/form inventory
- `leash_login` — store an identity's session inside the plugin (out of context)
- `leash_replay` — multi-identity replay with differential BOLA/IDOR verdict
- `leash_request` — raw HTTP(S) probe of an in-scope host, logged to the ledger
- `leash_scope` — show scope, mode and ledger stats
- `leash_finding` — record a finding (`hypothesis` | `verified` + evidence)
- `leash_report` — write the markdown report

## Disclosure

- The engine's `leash_login` stores session tokens locally at
  `$HERMES_HOME/plugin-data/leash/identities.json` (plaintext, same trust
  boundary as the profile's own config). They never enter the model context.
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
