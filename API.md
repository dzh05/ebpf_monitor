# API 文档

本文档用于描述 eBPF Monitor 项目里，Python agent 与后端服务之间的接口约定。后端开发人员可以直接按这里的格式实现服务端接收逻辑。

当前接口分为三类：

- Agent 注册
- Agent 心跳
- Agent 事件批量上报

---

## 1. 基础约定

### Base URL

示例：

```text
http://127.0.0.1:8000
```

实际部署时可以替换为你的后端服务地址。

### Content-Type

所有接口都使用：

```http
Content-Type: application/json
```

### 通用返回

接口成功时返回：

```json
{
  "ok": true
}
```

后端可以扩展为自己的业务响应格式，但 agent 侧当前主要关注 HTTP 200。

---

## 2. Agent 注册接口

### `POST /api/agent/register`

#### 说明

agent 启动后会先向后端注册自身信息。

#### 请求体

```json
{
  "agent_id": "test",
  "hostname": "test",
  "host_ip": "117.72.171.43",
  "version": "0.1.0"
}
```

#### 字段说明

- `agent_id`：agent 的唯一标识
- `hostname`：主机名
- `host_ip`：当前机器的外网 IP
- `version`：agent 版本号

#### 响应示例

```json
{
  "ok": true
}
```

---

## 3. Agent 心跳接口

### `POST /api/agent/heartbeat`

#### 说明

agent 会按固定时间间隔向后端发送心跳，用于表明 agent 仍然存活，并汇报当前队列深度。

#### 请求体

```json
{
  "agent_id": "test",
  "timestamp_ns": 1777196941520478779,
  "host_ip": "117.72.171.43",
  "healthy": true,
  "queue_depth": 0
}
```

#### 字段说明

- `agent_id`：agent 标识
- `timestamp_ns`：心跳发出时间，纳秒
- `host_ip`：当前机器的外网 IP
- `healthy`：当前是否健康
- `queue_depth`：当前待发送事件队列深度

#### 响应示例

```json
{
  "ok": true
}
```

---

## 4. Agent 事件批量上报接口

### `POST /api/agent/events`

#### 说明

agent 会将采集到的网络事件按批次上报。一个请求里可以包含 1 条或多条事件。

#### 请求体

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

#### 顶层字段说明

- `agent_id`：agent 标识
- `sequence`：批次序号，单调递增
- `host_external_ip`：本机外网 IP
- `events`：事件数组

#### `events` 中的字段说明

每个事件只包含以下字段：

- `event_type`：事件类型
- `timestamp_ns`：事件时间，纳秒
- `pid`：进程 ID
- `tid`：线程 ID
- `uid`：用户 ID
- `comm`：进程名
- `direction`：方向，`inbound` / `outbound`
- `protocol`：协议，`tcp` / `udp`
- `local_ip`：本地 IP
- `local_port`：本地端口
- `remote_ip`：远端 IP
- `remote_port`：远端端口
- `cgroup_id`：cgroup ID

#### 事件类型枚举

- `NET_CONNECT`
- `NET_ACCEPT`
- `NET_DNS_QUERY`
- `NET_CLOSE`
- `NET_RESET`
- `NET_TIMEOUT`

#### 响应示例

```json
{
  "ok": true
}
```

---

## 5. 后端实现建议

后端可以按以下方式处理：

1. `/api/agent/register`
   - 创建或更新 agent 记录
2. `/api/agent/heartbeat`
   - 更新 agent 在线状态和队列深度
3. `/api/agent/events`
   - 批量写入事件表或消息队列
   - 支持后续查询、告警、聚合分析

---

## 6. 示例接收逻辑

如果后端开发需要一个快速参考，可以按以下逻辑实现：

- 接收 JSON body
- 校验 `agent_id` / `sequence` / `events`
- 持久化请求内容
- 返回 `200 OK`

---

## 7. 本地调试服务

项目根目录下的 `server.py` 是一个最小 FastAPI 测试服务，它只负责打印请求内容，便于本地观察 agent 是否正常上报。

接口完全匹配本 API 文档中的约定。
