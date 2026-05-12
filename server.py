"""Minimal local FastAPI server for observing agent API traffic.

This file is a lightweight test harness for the eBPF observatory project. It does
not implement any backend business logic; it only exposes the three agent-facing
endpoints that the Python agent expects:

- POST /api/agent/register
- POST /api/agent/heartbeat
- POST /api/agent/events

Each endpoint prints the received JSON body to stdout so you can verify that the
agent is successfully registering, sending heartbeats, and uploading event
batches during local development.
"""

from __future__ import annotations

from fastapi import FastAPI, Request

app = FastAPI(title="eBPF Observatory Test Server")


@app.post("/api/agent/register")
async def register(request: Request) -> dict[str, bool]:
    body = await request.json()
    print("REGISTER:", body)
    return {"ok": True}


@app.post("/api/agent/heartbeat")
async def heartbeat(request: Request) -> dict[str, bool]:
    body = await request.json()
    print("HEARTBEAT:", body)
    return {"ok": True}


@app.post("/api/agent/events")
async def events(request: Request) -> dict[str, bool]:
    body = await request.json()
    print("EVENTS:", body)
    return {"ok": True}
