#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define ETH_P_IP 0x0800
#define AF_INET 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct tcphdr_min {
    __be16 source;
    __be16 dest;
};

struct udphdr_min {
    __be16 source;
    __be16 dest;
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void fill_common_fields(struct net_event *event, __u32 event_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = event_type;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

static __always_inline int emit_event(struct net_event *event)
{
    struct net_event *slot;

    slot = bpf_ringbuf_reserve(&events, sizeof(*slot), 0);
    if (!slot)
        return 0;

    __builtin_memcpy(slot, event, sizeof(*slot));
    bpf_ringbuf_submit(slot, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct net_event event;

    if (ctx->ret != 0)
        return 0;

    fill_common_fields(&event, NET_EVENT_CONNECT);
    event.direction = NET_DIR_OUTBOUND;
    event.protocol = NET_PROTO_TCP;
    return emit_event(&event);
}

SEC("kretprobe/inet_csk_accept")
int trace_inet_csk_accept_ret(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    struct net_event event;
    __u16 family;

    if (!newsk)
        return 0;

    family = BPF_CORE_READ(newsk, __sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    fill_common_fields(&event, NET_EVENT_ACCEPT);
    event.direction = NET_DIR_INBOUND;
    event.protocol = NET_PROTO_TCP;
    event.local_ip_v4 = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
    event.remote_ip_v4 = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
    event.local_port = BPF_CORE_READ(newsk, __sk_common.skc_num);
    event.remote_port = bpf_ntohs(BPF_CORE_READ(newsk, __sk_common.skc_dport));

    return emit_event(&event);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_accept4(struct trace_event_raw_sys_enter *ctx)
{
    struct net_event event;

    fill_common_fields(&event, NET_EVENT_ACCEPT);
    event.direction = NET_DIR_INBOUND;
    event.protocol = NET_PROTO_TCP;
    return emit_event(&event);
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_sock_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    __u32 state = BPF_CORE_READ(ctx, newstate);
    struct net_event event;

    if (state != TCP_SYN_SENT)
        return 0;
    if (BPF_CORE_READ(ctx, family) != AF_INET || BPF_CORE_READ(ctx, protocol) != IPPROTO_TCP)
        return 0;

    fill_common_fields(&event, NET_EVENT_CONNECT);
    event.direction = NET_DIR_OUTBOUND;

    __builtin_memcpy(&event.local_ip_v4, ctx->saddr, sizeof(event.local_ip_v4));
    __builtin_memcpy(&event.remote_ip_v4, ctx->daddr, sizeof(event.remote_ip_v4));
    event.local_port = BPF_CORE_READ(ctx, sport);
    event.remote_port = BPF_CORE_READ(ctx, dport);

    event.protocol = NET_PROTO_TCP;
    return emit_event(&event);
}
