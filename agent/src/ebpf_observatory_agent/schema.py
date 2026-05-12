from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Literal
from uuid import uuid4
from time import time_ns

EventType = Literal[
    "NET_CONNECT",
    "NET_ACCEPT",
    "NET_DNS_QUERY",
    "NET_CLOSE",
    "NET_RESET",
    "NET_TIMEOUT",
    "NET_PACKET",
]
Direction = Literal["inbound", "outbound"]
Protocol = Literal["tcp", "udp"]


@dataclass(slots=True)
class AgentMetadata:
    agent_id: str
    hostname: str
    host_ip: str | None = None
    version: str = "0.1.0"


@dataclass(slots=True)
class NetworkEvent:
    event_type: EventType
    timestamp_ns: int
    pid: int
    tid: int
    uid: int
    comm: str
    direction: Direction | None = None
    protocol: Protocol | None = None
    local_ip: str | None = None
    local_port: int | None = None
    remote_ip: str | None = None
    remote_port: int | None = None
    cgroup_id: int | None = None
    container_id: str | None = None
    correlation_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def new(cls, event_type: EventType, **kwargs: Any) -> "NetworkEvent":
        kwargs.setdefault("timestamp_ns", time_ns())
        kwargs.setdefault("correlation_id", str(uuid4()))
        return cls(event_type=event_type, **kwargs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ns": self.timestamp_ns,
            "pid": self.pid,
            "tid": self.tid,
            "uid": self.uid,
            "comm": self.comm,
            "direction": self.direction,
            "protocol": self.protocol,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "cgroup_id": self.cgroup_id,
        }


@dataclass(slots=True)
class AgentRegistration:
    agent_id: str
    hostname: str
    host_ip: str | None
    version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AgentHeartbeat:
    agent_id: str
    timestamp_ns: int
    host_ip: str | None
    healthy: bool = True
    queue_depth: int = 0

    @classmethod
    def now(cls, agent_id: str, host_ip: str | None, healthy: bool = True, queue_depth: int = 0) -> "AgentHeartbeat":
        return cls(agent_id=agent_id, timestamp_ns=time_ns(), host_ip=host_ip, healthy=healthy, queue_depth=queue_depth)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AgentEventBatch:
    agent_id: str
    sequence: int
    events: list[NetworkEvent]
    host_external_ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "sequence": self.sequence,
            "host_external_ip": self.host_external_ip,
            "events": [event.to_dict() for event in self.events],
        }
