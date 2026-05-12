from __future__ import annotations

from dataclasses import asdict
from typing import Any
from urllib.parse import quote

import requests

from .schema import AgentRegistration, AgentHeartbeat, AgentEventBatch


class ServerClient:
    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def register(self, payload: AgentRegistration) -> requests.Response:
        return requests.post(
            f"{self.base_url}/api/agent/register",
            json=asdict(payload),
            timeout=self.timeout,
        )

    def heartbeat(self, payload: AgentHeartbeat) -> requests.Response:
        return requests.post(
            f"{self.base_url}/api/agent/heartbeat",
            json=payload.to_dict(),
            timeout=self.timeout,
        )

    def get_sequence(self, agent_id: str) -> requests.Response:
        escaped_agent_id = quote(agent_id, safe="")
        return requests.get(
            f"{self.base_url}/api/agents/{escaped_agent_id}/sequence",
            timeout=self.timeout,
        )

    def send_events(self, payload: AgentEventBatch) -> requests.Response:
        return requests.post(
            f"{self.base_url}/api/agent/events",
            json=payload.to_dict(),
            timeout=self.timeout,
        )
