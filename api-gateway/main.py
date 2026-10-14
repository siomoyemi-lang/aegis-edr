import asyncio
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from redis.asyncio import Redis
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Agent WebSocket connection manager
agent_manager = {}

async def get_redis():
    return Redis(host="redis", port=6379, db=0)

class KillCommand(BaseModel):
    pid: int

@app.websocket("/ws/telemetry/{agent_id}")
async def telemetry_endpoint(websocket: WebSocket, agent_id: str, redis: Redis = Depends(get_redis)):
    await websocket.accept()
    agent_manager[agent_id] = websocket
    print(f"Agent {agent_id} connected.")
    
    try:
        while True:
            data = await websocket.receive_text()
            await redis.xadd("stream:aegis_telemetry", {"agent_id": agent_id, "raw_data": data})
    except WebSocketDisconnect:
        if agent_id in agent_manager:
            del agent_manager[agent_id]
        print(f"Agent {agent_id} disconnected.")

@app.post("/api/agents/{agent_id}/kill")
async def kill_process(agent_id: str, command: KillCommand):
    if agent_id in agent_manager:
        ws = agent_manager[agent_id]
        await ws.send_text(json.dumps({"action": "KILL_PID", "target": command.pid}))
        return {"status": "Kill signal dispatched"}
    return {"error": "Agent not connected"}

# Frontend Dashboard WebSocket Endpoint
@app.websocket("/ws/frontend")
async def frontend_endpoint(websocket: WebSocket, redis: Redis = Depends(get_redis)):
    await websocket.accept()
    pubsub = redis.pubsub()
    await pubsub.subscribe("channel:alerts")
    
    try:
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message["type"] == "message":
                await websocket.send_text(message["data"].decode("utf-8"))
            await asyncio.sleep(0.1)
    except WebSocketDisconnect:
        await pubsub.unsubscribe("channel:alerts")