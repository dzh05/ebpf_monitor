from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ctypes
import ctypes.util
import json
import shutil
import subprocess
from tempfile import TemporaryDirectory
from typing import Any, Callable

from .errors import CollectorError
from .schema import Direction, NetworkEvent, Protocol


@dataclass(slots=True)
class BPFArtifact:
    object_file: Path

    def validate(self) -> None:
        if not self.object_file.exists():
            raise CollectorError(f"BPF object file not found: {self.object_file}")
        if not self.object_file.is_file():
            raise CollectorError(f"BPF object path is not a file: {self.object_file}")


class BPFLoader:
    """Load and verify a compiled eBPF object with bpftool."""

    def __init__(self, object_file: str | Path) -> None:
        self.artifact = BPFArtifact(Path(object_file))

    def load(self) -> BPFArtifact:
        self.artifact.validate()
        self._require_bpftool()
        self._verify_kernel_load()
        return self.artifact

    def _require_bpftool(self) -> None:
        if shutil.which("bpftool") is None:
            raise CollectorError("bpftool is required to load and verify BPF programs")

    def _verify_kernel_load(self) -> None:
        with TemporaryDirectory(prefix="ebpf-observatory-") as tmpdir:
            obj_pin = Path(tmpdir) / "obj"
            try:
                subprocess.run(
                    ["bpftool", "prog", "loadall", str(self.artifact.object_file), str(obj_pin)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as exc:
                stderr = exc.stderr.strip() if exc.stderr else ""
                stdout = exc.stdout.strip() if exc.stdout else ""
                details = stderr or stdout or "unknown bpftool error"
                raise CollectorError(f"failed to load BPF object: {details}") from exc


def map_event_type(event_type: int) -> str:
    return {
        1: "NET_CONNECT",
        2: "NET_ACCEPT",
        3: "NET_DNS_QUERY",
        4: "NET_CLOSE",
        5: "NET_RESET",
        6: "NET_TIMEOUT",
        7: "NET_PACKET",
    }.get(event_type, "NET_CLOSE")


def map_direction(direction: int) -> Direction | None:
    return {0: None, 1: "inbound", 2: "outbound"}.get(direction)


def map_protocol(protocol: int) -> Protocol | None:
    return {0: None, 1: "tcp", 2: "udp"}.get(protocol)


def build_placeholder_event(event_type: int) -> NetworkEvent:
    from time import time_ns

    return NetworkEvent(
        event_type=map_event_type(event_type),
        timestamp_ns=time_ns(),
        pid=0,
        tid=0,
        uid=0,
        comm="kernel",
        extra={"source": "bpf-placeholder"},
    )


def decode_event_payload(payload: dict[str, Any]) -> NetworkEvent:
    local_ip = str(payload.get("local_ip", "")) or None
    remote_ip = str(payload.get("remote_ip", "")) or None
    if local_ip == "0.0.0.0":
        local_ip = None
    if remote_ip == "0.0.0.0":
        remote_ip = None

    return NetworkEvent(
        event_type=map_event_type(int(payload.get("event_type", 0))),
        timestamp_ns=int(payload.get("timestamp_ns", 0)),
        pid=int(payload.get("pid", 0)),
        tid=int(payload.get("tid", 0)),
        uid=int(payload.get("uid", 0)),
        comm=str(payload.get("comm", "")),
        direction=map_direction(int(payload.get("direction", 0))),
        protocol=map_protocol(int(payload.get("protocol", 0))),
        local_ip=local_ip,
        local_port=int(payload.get("local_port", 0)) or None,
        remote_ip=remote_ip,
        remote_port=int(payload.get("remote_port", 0)) or None,
        cgroup_id=int(payload.get("cgroup_id", 0)) or None,
        extra={"raw": payload},
    )


class BPFKernelBridge:
    def __init__(self, object_file: str | Path) -> None:
        self.object_file = str(object_file)
        self._lib = ctypes.CDLL(ctypes.util.find_library("bpf") or "libbpf.so.0")
        self._obj = ctypes.c_void_p()
        self._ringbuf = ctypes.c_void_p()
        self._events_map_fd = -1
        self._loaded = False
        self._poll_thread: Thread | None = None
        self._stop = Event()
        self._ctx: Callable[[NetworkEvent], None] | None = None
        self._event_struct_size = 200

    def load(self) -> None:
        self._load_object()
        self._attach_programs()
        self._open_ringbuf()
        self._loaded = True

    def start(self, on_event: Callable[[NetworkEvent], None]) -> None:
        if not self._loaded:
            self.load()
        self._ctx = on_event
        self._poll_thread = Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._ringbuf.value:
            self._ringbuf = ctypes.c_void_p()
        if self._obj.value:
            self._obj = ctypes.c_void_p()
        if self._poll_thread is not None:
            self._poll_thread.join(timeout=2.0)

    def _load_object(self) -> None:
        if self._lib.bpf_object__open_file is None:
            raise CollectorError("libbpf is missing bpf_object__open_file")
        opts = None
        self._obj = self._lib.bpf_object__open_file(self.object_file.encode(), opts)
        if not self._obj:
            raise CollectorError(f"failed to open BPF object {self.object_file}")
        if self._lib.bpf_object__load(self._obj) != 0:
            raise CollectorError(f"failed to load BPF object {self.object_file}")

    def _attach_programs(self) -> None:
        pass

    def _open_ringbuf(self) -> None:
        pass

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            sleep(0.5)
