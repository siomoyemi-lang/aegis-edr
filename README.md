<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark-bg.png">
    <img src="assets/logo-light-bg.png" alt="Aegis EDR - Endpoint Detection &amp; Response" width="640">
  </picture>
</p>

**Aegis** is an Endpoint Detection and Response (EDR) platform built on a strict split-brain architecture. A lightweight Windows sensor captures native kernel telemetry and ships it to a backend that does all the heavy analysis, so the endpoint stays fast and the detection logic stays out of an attacker's reach.

## System architecture

```
 C++ Agent ──WebSocket──▶ FastAPI Gateway ──XADD──▶ Redis Streams ──XREADGROUP──▶ Detection Engine
 (ETW sensor)  ◀─ KILL_PID ──┘      │                                                   │
                                     └──── channel:alerts (pub/sub) ◀── alerts ─────────┘
                                                   │
                                          Next.js SOC Console (live feed · fleet · lineage · kill)
```

1. **Endpoint Agent** - C++20 daemon using the native Win32 ETW API (`Microsoft-Windows-Kernel-Process`). Three threads: ETW collector (lock-free hand-off, no I/O in the callback), network (RFC 6455 client: per-frame random masking, ping/pong, close handling, reconnect with exponential backoff) and command execution (`KILL_PID` → `TerminateProcess`).
2. **API Gateway** - FastAPI. Ingests telemetry into Redis (`XADD`, capped stream), routes kill commands to the right agent socket, relays alerts / kill results / fleet changes to the console and exposes read-only helpers (`/api/agents`, `/api/alerts`, `/api/agents/{id}/lineage/{pid}`).
3. **Data Broker** - Redis 7 Streams: ingestion is decoupled from analysis, so spikes or engine downtime lose nothing.
4. **Detection Engine** - Python consumer-group worker. Rules are declarative JSON (`detection-engine/rules.json`); it also keeps a 24h process cache used for parent-process rules and lineage graphs, publishes alerts, and can auto-terminate.
5. **SOC Console** - Next.js + Zustand + React Flow: live alert feed, fleet table, process-lineage graph, confirmed Kill Process with real agent acknowledgement.

## Quick start

**Prerequisites:** Windows 10/11 + Administrator rights (ETW kernel tracing), Visual Studio Build Tools (MSVC), CMake, Boost headers, Python 3.12+, Node 20+, Docker Desktop.

```powershell
# 1. Redis + gateway
docker compose up -d --build

# 2. Detection engine
pip install -r detection-engine/requirements.txt
python detection-engine/main.py

# 3. Agent (Administrator PowerShell)
cmake -B build
cmake --build build --config Release
.\build\Release\aegis_agent.exe

# 4. Console
cd frontend-console
npm install
npm run dev          # http://localhost:3000
```

## Configuration

| Component | Setting | Default | Purpose |
| :-- | :-- | :-- | :-- |
| Gateway | `AEGIS_API_KEY` | _(empty = open, dev only)_ | Required in `X-API-Key` for `POST /api/agents/{id}/kill` |
| Gateway | `AEGIS_AGENT_TOKEN` | _(empty = open, dev only)_ | Required in `X-Agent-Token` to open a telemetry socket |
| Gateway | `AEGIS_CORS_ORIGINS` | `http://localhost:3000` | Browser origins allowed (HTTP + `/ws/frontend`) |
| Gateway / Engine | `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| Engine | `AEGIS_AUTO_KILL` | `0` | `1` = terminate flagged processes automatically |
| Engine | `AEGIS_AUTO_KILL_MIN_SEVERITY` | `CRITICAL` | Lowest severity that auto-kills |
| Engine | `AEGIS_GATEWAY_URL` | `http://localhost:8000` | Where the engine sends kill requests |
| Engine | `AEGIS_RULES_FILE` | `detection-engine/rules.json` | Rule set |
| Engine | `AEGIS_LOG_LEVEL` | `INFO` | `DEBUG` logs every process event |
| Agent | `AEGIS_GATEWAY_HOST` / `AEGIS_GATEWAY_PORT` | `127.0.0.1` / `8000` | Gateway address (or `--host`, `--port`) |
| Agent | `AEGIS_AGENT_ID` / `AEGIS_AGENT_TOKEN` | `aegis-<COMPUTERNAME>` / _(none)_ | Identity and shared secret (or `--agent-id`, `--token`) |
| Console | `NEXT_PUBLIC_AEGIS_API_URL` | `http://localhost:8000` | Gateway URL as seen by the browser |
| Console | `NEXT_PUBLIC_AEGIS_API_KEY` | _(none)_ | Sent as `X-API-Key` when killing (visible to the browser - keep the console on a trusted network) |

See `.env.example`. **Auto-kill is off by default** - a rule that matches `cmd.exe` would otherwise terminate your own shells. Turn it on only for high-severity rules, and note the engine refuses to auto-kill events older than 30 s (PIDs get reused).

## Writing rules

Rules are JSON trees of criteria joined by `AND` / `OR` (nestable). Fields: `image_path`, `image_name`, `parent_image_name`, `pid`, `ppid`, `command_line` (once the agent collects it). Operators: `equals`, `not_equals`, `startswith`, `endswith`, `contains`, `contains_any`, `contains_all`, `in`, `regex`, `gt`, `lt` (string compares are case-insensitive; a missing field never matches).

```json
{
  "rule_id": "AEG-WIN-005",
  "name": "Web Shell Reverse Connection",
  "severity": "CRITICAL",
  "condition": "AND",
  "criteria": [
    {"field": "image_name", "operator": "equals", "value": "cmd.exe"},
    {"field": "parent_image_name", "operator": "in", "value": ["nginx.exe", "w3wp.exe", "httpd.exe"]}
  ]
}
```

Rules are validated when the engine starts; a typo fails fast instead of silently never matching. Run the tests with `python -m unittest discover -s detection-engine/tests`.

## Roadmap

- [x] Phase 1 & 2: API gateway and core threading model
- [x] Phase 3: Native Win32 ETW process telemetry
- [x] Phase 4: Redis Streams detection engine (consumer group, declarative rules)
- [x] Phase 5: Active response (`KILL_PID` with acknowledgement)
- [x] Phase 6: SOC dashboard (live feed, fleet table, lineage graph)
- [ ] Phase 7: Command-line extraction and advanced Sigma-style rules
- [ ] TLS (`wss://`) / mTLS between agent and gateway, durable storage (PostgreSQL/TimescaleDB)

## Branding

Logo and icon assets live in [`assets/`](assets) (`icon.png`, `logo-dark-bg.png`, `logo-light-bg.png`, `favicon.ico`, `apple-icon.png`, `social-preview.png`). The console's favicon is cropped edge-to-edge so it fills the browser tab. To use `social-preview.png` on GitHub: *Settings → General → Social preview*.

## Author

Lead Engineer: Shittu Ibraheem Omoyemi · GitHub: [@siomoyemi-lang](https://github.com/siomoyemi-lang)
