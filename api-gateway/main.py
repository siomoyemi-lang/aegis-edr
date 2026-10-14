"""Aegis API Gateway.

Responsibilities (kept deliberately thin):
  * /ws/telemetry/{agent_id}  - ingest agent telemetry -> Redis Stream (XADD, O(1)).
  * /api/agents/{id}/kill     - route a KILL_PID command down the agent's WebSocket.
  * /ws/frontend              - fan out alerts / kill results / fleet changes to the dashboard.
  * Read-only helper endpoints for the dashboard (fleet, recent alerts, process lineage).
"""
import asyncio
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from redis.asyncio import Redis
from starlette.requests import HTTPConnection

log = logging.getLogger("aegis.gateway")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
API_KEY = os.getenv("AEGIS_API_KEY", "")          # protects the kill endpoint; empty => disabled (dev only)
AGENT_TOKEN = os.getenv("AEGIS_AGENT_TOKEN", "")  # shared secret agents present on connect; empty => disabled
CORS_ORIGINS = [o.strip() for o in os.getenv("AEGIS_CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()]

TELEMETRY_STREAM = "stream:aegis_telemetry"
ALERT_CHANNEL = "channel:alerts"
ALERT_STREAM = "stream:aegis_alerts"
ALERT_STATUS_HASH = "alerts:status"
TELEMETRY_MAXLEN = int(os.getenv("AEGIS_TELEMETRY_MAXLEN", "200000"))
MAX_MESSAGE_BYTES = 64 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    # One shared connection pool for the whole process (previously a new client per request).
    app.state.redis = Redis.from_url(REDIS_URL)
    if not API_KEY:
        log.warning("AEGIS_API_KEY is not set: the kill endpoint is UNAUTHENTICATED (dev mode).")
    if not AGENT_TOKEN:
        log.warning("AEGIS_AGENT_TOKEN is not set: any client can open a telemetry socket (dev mode).")
    yield
    await app.state.redis.aclose()


app = FastAPI(title="Aegis API Gateway", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# agent_id -> live WebSocket, and agent_id -> metadata for the fleet view
agent_manager: dict[str, WebSocket] = {}
agent_info: dict[str, dict] = {}


async def get_redis(conn: HTTPConnection) -> Redis:
    # HTTPConnection is the common base of Request and WebSocket, so one dependency serves both.
    return conn.app.state.redis


def _same(a: Optional[str], b: str) -> bool:
    # bytes comparison: compare_digest raises on non-ASCII str, which would turn bad input into a 500
    return a is not None and secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


async def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if API_KEY and not _same(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


class KillCommand(BaseModel):
    pid: int
    alert_id: Optional[str] = None


async def publish_event(redis: Redis, event_type: str, payload: dict) -> None:
    await redis.publish(ALERT_CHANNEL, json.dumps({"type": event_type, "payload": payload}))


def _agent_status(agent_id: str, online: bool) -> dict:
    info = agent_info.setdefault(agent_id, {"agent_id": agent_id, "first_seen": time.time()})
    info["status"] = "online" if online else "offline"
    info["last_seen"] = time.time()
    return dict(info)


@app.websocket("/ws/telemetry/{agent_id}")
async def telemetry_endpoint(websocket: WebSocket, agent_id: str, redis: Redis = Depends(get_redis)):
    if AGENT_TOKEN and not _same(websocket.headers.get("x-agent-token"), AGENT_TOKEN):
        await websocket.close(code=1008)  # rejected before the upgrade completes
        return
    await websocket.accept()
    agent_manager[agent_id] = websocket
    log.info("Agent %s connected", agent_id)
    await publish_event(redis, "AGENT_STATUS", _agent_status(agent_id, True))

    try:
        while True:
            data = await websocket.receive_text()
            if len(data) > MAX_MESSAGE_BYTES:
                continue
            agent_info.get(agent_id, {})["last_seen"] = time.time()

            # Command results from the agent travel on the same socket. Cheap substring check keeps
            # the hot path free of JSON parsing for ordinary telemetry.
            if '"KILL_RESULT"' in data:
                try:
                    result = json.loads(data)
                except json.JSONDecodeError:
                    continue
                result["agent_id"] = agent_id
                alert_id = result.get("alert_id")
                if alert_id and result.get("status") == "SUCCESS":
                    await redis.hset(ALERT_STATUS_HASH, alert_id, "resolved")
                await publish_event(redis, "KILL_RESULT", result)
                continue

            await redis.xadd(
                TELEMETRY_STREAM,
                {"agent_id": agent_id, "raw_data": data},
                maxlen=TELEMETRY_MAXLEN,
                approximate=True,
            )
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("Telemetry socket for %s failed", agent_id)
    finally:
        # Only drop the entry if it still belongs to THIS connection; a reconnecting agent
        # may already have registered a newer socket under the same id.
        if agent_manager.get(agent_id) is websocket:
            del agent_manager[agent_id]
            await publish_event(redis, "AGENT_STATUS", _agent_status(agent_id, False))
        log.info("Agent %s disconnected", agent_id)


@app.post("/api/agents/{agent_id}/kill", dependencies=[Depends(require_api_key)])
async def kill_process(agent_id: str, command: KillCommand):
    ws = agent_manager.get(agent_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="Agent not connected")
    if command.pid <= 4:
        raise HTTPException(status_code=400, detail="Refusing to target system PIDs")
    msg = {"action": "KILL_PID", "target": command.pid}
    if command.alert_id:
        msg["alert_id"] = command.alert_id
    try:
        await ws.send_text(json.dumps(msg))
    except Exception:
        raise HTTPException(status_code=502, detail="Failed to reach agent")
    return {"status": "Kill signal dispatched"}


@app.get("/api/agents")
async def list_agents():
    return sorted(agent_info.values(), key=lambda a: a["agent_id"])


@app.get("/api/alerts")
async def recent_alerts(limit: int = 100, redis: Redis = Depends(get_redis)):
    limit = max(1, min(limit, 500))
    entries = await redis.xrevrange(ALERT_STREAM, count=limit)
    statuses = await redis.hgetall(ALERT_STATUS_HASH)
    alerts = []
    for _id, fields in entries:
        raw = fields.get(b"alert") or fields.get("alert")
        if not raw:
            continue
        alert = json.loads(raw)
        override = statuses.get(alert["alert_id"].encode())
        if override:
            alert["status"] = override.decode()
        alerts.append(alert)
    return alerts


@app.get("/api/agents/{agent_id}/lineage/{pid}")
async def process_lineage(agent_id: str, pid: int, redis: Redis = Depends(get_redis)):
    """Ancestor chain of `pid` plus its direct children, built from the engine's process cache."""

    async def load(p: int):
        raw = await redis.get(f"proc:{agent_id}:{p}")
        return json.loads(raw) if raw else None

    nodes, edges, seen = {}, [], set()
    current = await load(pid)
    if current is None:
        raise HTTPException(status_code=404, detail="Process not found in cache")
    nodes[pid] = current

    cursor = current
    for _ in range(20):  # depth guard also protects against PID-reuse cycles
        ppid = cursor["ppid"]
        if ppid in seen or ppid in nodes:
            break
        seen.add(ppid)
        parent = await load(ppid)
        if parent is None:
            break
        nodes[ppid] = parent
        edges.append({"source": ppid, "target": cursor["pid"]})
        cursor = parent

    kids = await redis.smembers(f"kids:{agent_id}:{pid}")
    for k in sorted(int(x) for x in kids)[:50]:
        child = await load(k)
        if child and k not in nodes:
            nodes[k] = child
            edges.append({"source": pid, "target": k})

    return {"focus": pid, "nodes": list(nodes.values()), "edges": edges}


@app.websocket("/ws/frontend")
async def frontend_endpoint(websocket: WebSocket, redis: Redis = Depends(get_redis)):
    # Browsers always send Origin on WebSocket handshakes; refuse pages we don't serve.
    origin = websocket.headers.get("origin")
    if origin and origin not in CORS_ORIGINS:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    pubsub = redis.pubsub()
    await pubsub.subscribe(ALERT_CHANNEL)

    async def pump():
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                await websocket.send_text(data.decode("utf-8") if isinstance(data, bytes) else data)

    async def drain():
        # Detect client disconnects promptly (receive raises WebSocketDisconnect).
        while True:
            await websocket.receive_text()

    tasks = [asyncio.create_task(pump()), asyncio.create_task(drain())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        await pubsub.unsubscribe(ALERT_CHANNEL)
        await pubsub.aclose()
