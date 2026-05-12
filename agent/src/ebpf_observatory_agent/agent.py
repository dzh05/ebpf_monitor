from __future__ import annotations

from dataclasses import dataclass
from queue import Empty, Queue
from threading import Event, Lock, Thread
from time import sleep
import urllib.request

from .client import ServerClient
from .collector import BaseCollector, CollectorContext, DemoCollector, KernelCollector, CollectorError
from .schema import AgentEventBatch, AgentHeartbeat, AgentRegistration, NetworkEvent


@dataclass(slots=True)
class AgentConfig:
    server_url: str
    agent_id: str
    hostname: str
    version: str = "0.1.0"
    batch_size: int = 50
    flush_interval_seconds: float = 2.0
    heartbeat_interval_seconds: float = 15.0
    use_demo_collector: bool = False
    bpf_object_file: str | None = None
    ringbuf_helper_path: str | None = None
    interface: str | None = None
    fail_open: bool = True


class ObservatoryAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.client = ServerClient(config.server_url)
        self.queue: Queue[NetworkEvent] = Queue(maxsize=10000)
        self.sequence = 0
        self._stop = Event()
        self._lock = Lock()
        self._collector: BaseCollector = self._build_collector()
        self._flush_thread: Thread | None = None
        self._heartbeat_thread: Thread | None = None
        self._host_external_ip: str | None = None

    def _build_collector(self) -> BaseCollector:
        if self.config.use_demo_collector:
            return DemoCollector()
        helper_path = self.config.ringbuf_helper_path or "/tmp/ringbuf_helper"
        return KernelCollector(helper_path, self.config.bpf_object_file, self.config.interface)

    def register(self) -> None:
        self.client.register(
            AgentRegistration(
                agent_id=self.config.agent_id,
                hostname=self.config.hostname,
                host_ip=self._get_host_external_ip(),
                version=self.config.version,
            )
        ).raise_for_status()

    def sync_sequence(self) -> None:
        response = self.client.get_sequence(self.config.agent_id)
        if response.status_code == 404:
            self.register()
            response = self.client.get_sequence(self.config.agent_id)
        response.raise_for_status()
        payload = response.json()
        next_sequence = int(payload.get("next_sequence", 1))
        if next_sequence < 1:
            next_sequence = 1
        with self._lock:
            self.sequence = next_sequence

    def start(self) -> None:
        self.register()
        self.sync_sequence()
        try:
            self._collector.start(CollectorContext(on_event=self.enqueue_event))
        except CollectorError as exc:
            print(f"collector failed to start: {exc}", flush=True)
            if not self.config.fail_open:
                raise
        self._flush_thread = Thread(target=self._flush_loop, daemon=True)
        self._heartbeat_thread = Thread(target=self._heartbeat_loop, daemon=True)
        self._flush_thread.start()
        self._heartbeat_thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._collector.stop()
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=2.0)
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=2.0)

    def enqueue_event(self, event: NetworkEvent) -> None:
        self.queue.put(event)

    def _flush_loop(self) -> None:
        buffer: list[NetworkEvent] = []
        while not self._stop.is_set():
            try:
                event = self.queue.get(timeout=self.config.flush_interval_seconds)
                buffer.append(event)
            except Empty:
                pass

            if len(buffer) >= self.config.batch_size or (buffer and self.queue.empty()):
                self.flush(buffer)
                buffer = []

    def flush(self, events: list[NetworkEvent]) -> None:
        if not events:
            return
        with self._lock:
            current_sequence = self.sequence
            batch = AgentEventBatch(
                agent_id=self.config.agent_id,
                sequence=current_sequence,
                events=events,
                host_external_ip=self._get_host_external_ip(),
            )
        self.client.send_events(batch).raise_for_status()
        with self._lock:
            if self.sequence == current_sequence:
                self.sequence += 1

    def _get_host_external_ip(self) -> str | None:
        if self._host_external_ip:
            return self._host_external_ip

        candidates = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
        ]
        for url in candidates:
            try:
                with urllib.request.urlopen(url, timeout=3) as resp:
                    ip = resp.read().decode().strip()
                    if ip:
                        self._host_external_ip = ip
                        return ip
            except Exception:
                continue
        return None

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            self.client.heartbeat(
                AgentHeartbeat.now(
                    agent_id=self.config.agent_id,
                    host_ip=self._get_host_external_ip(),
                    queue_depth=self.queue.qsize(),
                )
            ).raise_for_status()
            sleep(self.config.heartbeat_interval_seconds)
