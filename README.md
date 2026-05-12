# eBPF Monitor

这是一个基于 eBPF 的网络行为监控项目，目标是在 Linux 主机上采集网络连接相关事件，并通过 Python agent 将事件批量上报给后端服务。

目前项目已基本完成核心链路：

1. eBPF 程序挂载到内核 tracepoint
2. 内核事件通过 ringbuf 进入用户态 helper
3. helper 过滤噪声并输出 JSON
4. Python agent 读取 helper 输出并批量上传
5. 本地 FastAPI 服务可用于观察请求内容

---

## 项目结构

- `agent/`
  - Python agent 源码
  - eBPF C 程序
  - ringbuf 用户态 helper
- `server.py`
  - 本地调试用 FastAPI 服务
- `README.md`
  - 项目说明与部署运行指南
- `API.md`
  - 对接后端的接口说明

---

## 核心工作方式

当前采集链路如下：

```text
tracepoint/sock/inet_sock_set_state
        ↓
      eBPF ringbuf
        ↓
   ringbuf_helper.c
        ↓ stdout JSON
Python agent collector
        ↓
  events batch JSON
        ↓
     后端 API
```

当前主采集点已经收敛为：

- `tracepoint/sock/inet_sock_set_state`

这样可以优先保证抓到真实的 IP 和端口信息。

---

## 依赖环境

### 系统依赖

建议运行在 Linux 内核环境下，并准备以下工具：

- `clang`
- `gcc`
- `bpftool`
- `libbpf`
- `python3`
- `python3-venv`
- `pip`

### Python 依赖

agent 侧需要：

- `requests`
- `fastapi`
- `uvicorn`

---

## 部署与运行

### 1. 准备 Python 虚拟环境

进入项目根目录后：

```bash
cd /root/ebpf-monitor
python3 -m venv agent/.venv
source agent/.venv/bin/activate
pip install -U pip
pip install -r agent/requirements.txt
```

如果你还没有单独的 `requirements.txt`，至少需要安装：

```bash
pip install requests fastapi uvicorn
```

---

### 2. 编译 eBPF 程序

进入 eBPF 目录并编译：

```bash
cd /root/ebpf-monitor/agent/src/ebpf_observatory_agent/bpf
clang -O2 -g -target bpf -I. -I/usr/include/x86_64-linux-gnu -c collector.bpf.c -o collector.bpf.o
```

编译成功后会生成 `collector.bpf.o`，这是 agent 和 helper 都会使用的 BPF 对象文件。

---

### 3. 编译用户态 ringbuf helper

helper 负责加载 BPF 对象、挂载 tracepoint、读取 ringbuf，并输出 JSON。

```bash
cd /root/ebpf-monitor/agent/src/ebpf_observatory_agent
gcc -O2 -g ringbuf_helper.c -o /tmp/ringbuf_helper -I. -I/usr/include/x86_64-linux-gnu -lbpf -lelf -lz -pthread
```

建议把可执行文件放在 `/tmp/ringbuf_helper`，agent 默认也可以直接使用这个路径。

---

### 4. 启动本地调试服务

如果你只是想观察 agent 是否真的在发请求，可以先启动本地 FastAPI 服务：

```bash
cd /root/ebpf-monitor
source agent/.venv/bin/activate
python -m uvicorn server:app --host 0.0.0.0 --port 8000
```

这个服务会打印三类请求：

- `POST /api/agent/register`
- `POST /api/agent/heartbeat`
- `POST /api/agent/events`

---

### 5. 启动 agent

agent 会：

- 注册到后端
- 启动 ringbuf helper
- 读取 helper 输出
- 聚合事件
- 批量上传到后端 API

示例：

```bash
cd /root/ebpf-monitor
source agent/.venv/bin/activate
python -m ebpf_observatory_agent.cli \
  --server-url http://127.0.0.1:8000 \
  --agent-id test \
  --hostname test \
  --bpf-object-file /root/ebpf-monitor/agent/src/ebpf_observatory_agent/bpf/collector.bpf.o \
  --ringbuf-helper-path /tmp/ringbuf_helper
```

python -m ebpf_observatory_agent.cli   --server-url http://38.207.189.106:8082 --agent-id test   --hostname test   --bpf-object-file /root/ebpf-monitor/agent/src/ebpf_observatory_agent/bpf/collector.bpf.o   --ringbuf-helper-path /tmp/ringbuf_helper   



38.207.189.106 美国CMIN2

---

## agent 上报逻辑

当前 agent 的上报方式是批量发送：

- 事件先进入内部队列
- flush 线程聚合事件
- 达到批量阈值或队列空闲时发送

默认行为：

- `batch_size = 50`
- `flush_interval_seconds = 2.0`
- `heartbeat_interval_seconds = 15.0`

---

## 当前发送 JSON 的格式

agent 发给后端的 payload 结构为：

```json
{
  "agent_id": "test",
  "sequence": 14,
  "host_external_ip": "117.72.171.43",
  "events": [
    {
      "event_type": "NET_TIMEOUT",
      "timestamp_ns": 165780858082234,
      "pid": 1962,
      "tid": 1970,
      "uid": 0,
      "comm": "jdog-kunlunmirr",
      "direction": "outbound",
      "protocol": "tcp",
      "local_ip": "172.16.0.6",
      "local_port": 80,
      "remote_ip": "210.116.111.29",
      "remote_port": 20665,
      "cgroup_id": 2604
    }
  ]
}
```

说明：

- `host_external_ip` 是本机外网 IP
- `events` 里只保留对接后端所需的核心字段

---

## helper 的过滤规则

为了避免噪声和自我循环，helper 目前会过滤：

1. 全 0 的空事件
2. 本监控程序自身触发的回环事件

这样可以避免：

- agent 监控自己上传服务端请求
- 事件无限循环触发
- 输出刷屏

---

## 验证方式

你可以通过下面几步确认链路是否通了：

1. 启动 FastAPI server
2. 启动 agent
3. 观察 server 终端是否打印 `REGISTER`
4. 观察 server 终端是否打印 `HEARTBEAT`
5. 触发一个网络动作，例如 `curl`、`ping`、`python socket connect`
6. 观察 `EVENTS` 是否持续打印

---

## 常见问题

### 1. `fastapi` 找不到
请确认你启动的是虚拟环境里的 Python：

```bash
source agent/.venv/bin/activate
python -m uvicorn server:app --host 0.0.0.0 --port 8000
```

不要直接使用系统自带的 `uvicorn`。

---

### 2. `collector.bpf.o` 找不到
先重新编译 BPF 程序，确认生成了 `.o` 文件。

---

### 3. helper 没有输出事件
检查：

- BPF 是否成功编译
- helper 是否成功启动
- 是否有足够的权限加载 BPF
- 事件是否被过滤掉了

---

### 4. 只看到 `127.0.0.1` 或大量本机流量
这是因为 agent 和本地 server 在同一台机器上运行，会产生本地回环流量。当前 helper 已经做了部分过滤，但仍要注意：

- 本地调试环境下会出现少量 loopback 事件
- 真实业务接入时会更容易看到外部连接

---
