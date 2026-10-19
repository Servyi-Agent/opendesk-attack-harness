# OpenDesk ⇄ agentbox integration

Wraps the OpenDesk **execution engine inside the agentbox** (JonasOberhauser/agent-scripts
FUSE gatekeeper) while the **UI / permission broker stays outside**:

```
OUTSIDE (trusted)                       INSIDE (agentbox)
┌───────────────────────────┐   HTTP   ┌────────────────────────────────┐
│ broker.mjs                │ ───────► │ opendesk serve (engine)        │
│  rules.json white/black   │  /event  │  tools, LLM calls, sessions    │
│  unknown → ask user (UI)  │ ◄─────── │  LLM key + secrets via /fuse   │
│  audit: decisions.jsonl   │  /reply  │  (one-read, binary-hash gated) │
└───────────────────────────┘          └────────────────────────────────┘
```

## Flow (matches the product spec)

1. Engine starts **inside**; its LLM credential read at startup is gated by the
   agentbox (approved-binary SHA-256 + one-read counter; `fuse-client reset`
   re-arms between sessions).
2. Every tool action that the engine's permission config marks `ask`
   (`bash: ask`, `read: {...}` in `setting.json` + `--use-config-permissions`)
   emits `permission.asked` on the SSE event stream.
3. The **outside broker** matches the request against `rules.json`:
   - **blacklist** hit → auto `reject` (seeds cover the known exfil classes:
     `curl|bash`, `--data-urlencode x@file`, npm-from-URL, `~/.ssh` reads,
     symlink planting, installer artifacts)
   - **whitelist** hit → auto `once` (common safe patterns: ls/cat/grep,
     workspace reads, the LLM API endpoint)
   - **otherwise** → ask the user through the UI seam (`--auto deny|always`
     for headless; interactive prompt otherwise). `always` replies are
   **persisted back into rules.json** — the lists learn.
4. Every decision is appended to `decisions.jsonl` (audit trail).

## Files

| File | Role |
|------|------|
| `start-inside.sh` / `supervise-inside.sh` | run/keep the engine (inside) |
| `broker.mjs` | outside permission broker (lists + ask + learning + audit) |
| `rules.json` | seeded white/blacklists (first match wins: blacklist > whitelist > ask) |
| `ctl.sh` | single control point (`restart` / `triad` / `status`) |
| `deploy-run.sh` | real-deployment orchestration via agentbox `run-agent` (needs docker + kernel FUSE) |

## Verified in-sandbox (engine host-side; policy daemon active)

- whitelist: `ls …/workspace` → `bash ONCE (whitelist: ^ls\b)` → executed
- ask→deny: `whoami` → engine received **"The tool call was rejected by the
  user — permission denied"** → command never ran
- attack class: `curl …/setup.sh | bash` → refused at the model layer;
  the broker blacklist (`curl[^|]*\|\s*(ba)?sh`) is the second net; attack
  server recorded **0 exfil requests**

## Sandbox limitations (honest notes)

- No `CAP_SYS_ADMIN` → kernel FUSE mount impossible here (`fusermount3:
  Operation not permitted`); the gate policy daemon runs, but the real mount
  path is exercised only in deployment mode (`deploy-run.sh`).
- No docker/podman → the inside/outside split is process-level in-sandbox,
  container-level in deployment.
- The ask-flow's interactive UI seam is a CLI prompt; plug the OpenDesk UI
  into `askUser()` in `broker.mjs`.
