import asyncio
import os
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from redis.asyncio import Redis, from_url

app = FastAPI(title="Aegis EDR - API Gateway")

# Active WebSocket connections manager
agent_manager = {}

async def get_redis() -> Redis:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    redis = await from_url(redis_url)
    try:
        yield redis
    finally:
        await redis.close()

async def update_agent_status(agent_id: str):
    # Async status update placeholder for Phase 4
    pass

async def handle_disconnect(agent_id: str):
    if agent_id in agent_manager:
        del agent_manager[agent_id]
        print(f"Agent {agent_id} disconnected.")

@app.websocket("/ws/telemetry/{agent_id}")
async def telemetry_endpoint(websocket: WebSocket, agent_id: str, redis: Redis = Depends(get_redis)):
    await websocket.accept()
    agent_manager[agent_id] = websocket
    print(f"Agent {agent_id} connected.")
    
    asyncio.create_task(update_agent_status(agent_id))
    
    try:
        while True:
            data = await websocket.receive_text()
            # Push raw JSON string directly to Redis Stream (O(1) operation)
            await redis.xadd("stream:aegis_telemetry", {"agent_id": agent_id, "raw_data": data})
            
    except WebSocketDisconnect:
        await handle_disconnect(agent_id)