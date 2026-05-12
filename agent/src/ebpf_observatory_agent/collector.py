from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from time import sleep
from typing import Callable
import json
import os
import subprocess

from .errors import CollectorError
from .loader import build_placeholder_event, decode_event_payload
from .schema import NetworkEvent


@dataclass(slots=True)
class CollectorContext:
    on_event: Callable[[NetworkEvent], None]


class BaseCollector:
    def start(self, ctx: CollectorContext) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError


class DemoCollector(BaseCollector):
    def __init__(self, interval_seconds: float = 5.0) -> None:
        self.interval_seconds = interval_seconds
        self._stop = Event()
        self._thread: Thread | None = None
        self._ctx: CollectorContext | None = None

    def start(self, ctx: CollectorContext) -> None:
        self._ctx = ctx
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        from time import time_ns
        from uuid import uuid4

        while not self._stop.is_set():
            if self._ctx is not None:
                self._ctx.on_event(
                    NetworkEvent(
                        event_type="NET_CONNECT",
                        timestamp_ns=time_ns(),
                        pid=1,
                        tid=1,
                        uid=0,
                        comm="demo-agent",
                        direction="outbound",
                        protocol="tcp",
                        local_ip="10.0.0.2",
                        local_port=54321,
                        remote_ip="1.1.1.1",
                        remote_port=443,
                        correlation_id=str(uuid4()),
                        extra={"source": "demo"},
                    )
                )
            sleep(self.interval_seconds)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


class KernelCollector(BaseCollector):
    def __init__(self, helper_path: str | Path, object_file: str | Path | None = None, interface: str | None = None) -> None:
        self.helper_path = Path(helper_path)
        self.object_file = Path(object_file) if object_file else None
        self.interface = interface
        self._running = False
        self._thread: Thread | None = None
        self._ctx: CollectorContext | None = None
        self._queue: Queue[NetworkEvent] = Queue()
        self._stop = Event()
        self._proc: subprocess.Popen[str] | None = None
        self._reader_thread: Thread | None = None
        self._dispatch_thread: Thread | None = None
        self._stderr_thread: Thread | None = None

    def start(self, ctx: CollectorContext) -> None:
        self._ctx = ctx
        if self.object_file is None:
            raise CollectorError("kernel collector requires a compiled BPF object file")
        if not self.helper_path.exists():
            raise CollectorError(f"ringbuf helper not found: {self.helper_path}")
        env = os.environ.copy()
        env["EBPF_OBSERVATORY_SKIP_PID"] = str(os.getpid())
        if self.interface:
            env["EBPF_OBSERVATORY_IFACE"] = self.interface
        print(f"EBPF_OBSERVATORY_SKIP_PID: {env['EBPF_OBSERVATORY_SKIP_PID']}")
        self._proc = subprocess.Popen(
            [str(self.helper_path), str(self.object_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        self._running = True
        self._reader_thread = Thread(target=self._read_loop, daemon=True)
        self._dispatch_thread = Thread(target=self._dispatch_loop, daemon=True)
        self._stderr_thread = Thread(target=self._stderr_loop, daemon=True)
        self._reader_thread.start()
        self._dispatch_thread.start()
        self._stderr_thread.start()
        self._queue.put(build_placeholder_event(1))

    def emit(self, event: NetworkEvent) -> None:
        self._queue.put(event)

    def emit_raw(self, payload: dict[str, object]) -> None:
        self._queue.put(decode_event_payload(payload))

    def _read_loop(self) -> None:
        if self._proc is None or self._proc.stdout is None:
            return
        while not self._stop.is_set():
            line = self._proc.stdout.readline()
            if not line:
                if self._proc.poll() is not None:
                    break
                continue
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                event_type = int(payload.get("event_type", 0))
                direction = int(payload.get("direction", 0))
                if not ((event_type == 1 and direction == 2) or (event_type == 2 and direction == 1)):
                    continue
                if int(payload.get("pid", 0)) == 0:
                    continue
                self.emit_raw(payload)

    def _dispatch_loop(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._queue.get(timeout=0.5)
            except Empty:
                continue
            if self._ctx is not None:
                self._ctx.on_event(event)

    def _stderr_loop(self) -> None:
        if self._proc is None or self._proc.stderr is None:
            return
        while not self._stop.is_set():
            line = self._proc.stderr.readline()
            if not line:
                if self._proc.poll() is not None:
                    break
                continue
            print(f"ringbuf helper: {line.rstrip()}", flush=True)

    def stop(self) -> None:
        self._stop.set()
        self._running = False
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2.0)
        if self._dispatch_thread is not None:
            self._dispatch_thread.join(timeout=2.0)
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=2.0)
