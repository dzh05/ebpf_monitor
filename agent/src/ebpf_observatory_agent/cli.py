from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path

from .agent import AgentConfig, ObservatoryAgent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ebpf-observatory-agent")
    parser.add_argument("--server-url", required=True, help="Central server base URL")
    parser.add_argument("--agent-id", required=True, help="Unique agent identifier")
    parser.add_argument("--hostname", required=True, help="Host name")
    parser.add_argument("--use-demo-collector", action="store_true", help="Use a synthetic demo collector")
    parser.add_argument("--bpf-object-file", default=None, help="Compiled eBPF object file path")
    parser.add_argument("--ringbuf-helper-path", default="/tmp/ringbuf_helper", help="Path to the ringbuf helper executable")
    parser.add_argument("--interface", default=None, help="Network interface to attach TC ingress/egress programs, for example eth0")
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--flush-interval-seconds", type=float, default=2.0)
    parser.add_argument("--heartbeat-interval-seconds", type=float, default=15.0)
    parser.add_argument("--no-fail-open", action="store_true", help="Exit if the kernel collector cannot start")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    bpf_object = Path(args.bpf_object_file) if args.bpf_object_file else None
    agent = ObservatoryAgent(
        AgentConfig(
            server_url=args.server_url,
            agent_id=args.agent_id,
            hostname=args.hostname,
            use_demo_collector=args.use_demo_collector,
            bpf_object_file=str(bpf_object) if bpf_object else None,
            ringbuf_helper_path=args.ringbuf_helper_path,
            interface=args.interface,
            batch_size=args.batch_size,
            flush_interval_seconds=args.flush_interval_seconds,
            heartbeat_interval_seconds=args.heartbeat_interval_seconds,
            fail_open=not args.no_fail_open,
        )
    )

    def _shutdown(*_: object) -> None:
        agent.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    agent.start()
    signal.pause()


if __name__ == "__main__":
    main()
