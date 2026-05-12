# eBPF Observatory Agent

Host-side agent for collecting network lifecycle events with eBPF and reporting them to the central observability server.

## Purpose

This agent runs on monitored hosts and is responsible for:

- collecting kernel network events
- normalizing them into a shared event model
- batching and sending events to the central server
- exposing heartbeat and registration metadata

## Current scope

The first implementation phase focuses on:

- outbound `connect`
- inbound `accept`
- DNS query observations
- connection lifecycle events: `close`, `reset`, `timeout`

## Layout

- `src/ebpf_observatory_agent/` - agent implementation
- `src/ebpf_observatory_agent/schema.py` - event schemas and payload helpers
- `src/ebpf_observatory_agent/client.py` - server API client
- `src/ebpf_observatory_agent/cli.py` - command entry point
- `src/ebpf_observatory_agent/collector.py` - collector abstraction and demo/kernel collectors
- `src/ebpf_observatory_agent/loader.py` - BPF artifact validation and loader helper
- `src/ebpf_observatory_agent/agent.py` - agent runtime and batching logic
- `src/ebpf_observatory_agent/bpf/` - eBPF kernel-side collector sources

## eBPF collector structure

- `src/ebpf_observatory_agent/bpf/common.h` - shared kernel/user event layout
- `src/ebpf_observatory_agent/bpf/collector.bpf.c` - minimal kernel-side skeleton
- `src/ebpf_observatory_agent/bpf/vmlinux.h` - generate from your running kernel with bpftool

## Build requirements for real kernel mode

To compile the BPF object later, you will need:

- `clang`
- `bpftool`
- `libbpf`
- kernel headers or `vmlinux.h`

## Running in demo mode

Use the synthetic collector until the kernel loader is connected:

```bash
ebpf-observatory-agent \
  --agent-id agent-01 \
  --hostname node-a \
  --use-demo-collector
```

## Kernel mode

Provide a compiled BPF object file when ready:

```bash
ebpf-observatory-agent \
  --agent-id agent-01 \
  --hostname node-a \
  --bpf-object-file ./build/collector.bpf.o
```

## Local verification

If you only want to verify kernel loading, use:

```bash
python - <<'PY'
from ebpf_observatory_agent.loader import BPFLoader
print(BPFLoader("./build/collector.bpf.o").load())
PY
```

## Next step

The next implementation milestone is a real libbpf-based loader and ring buffer event reader.
