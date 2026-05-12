#ifndef EBPF_OBSERVATORY_COMMON_H
#define EBPF_OBSERVATORY_COMMON_H

#define TASK_COMM_LEN 16
#define MAX_EVENT_EXTRA_BYTES 128

#define NET_EVENT_CONNECT 1
#define NET_EVENT_ACCEPT 2
#define NET_EVENT_DNS_QUERY 3
#define NET_EVENT_CLOSE 4
#define NET_EVENT_RESET 5
#define NET_EVENT_TIMEOUT 6
#define NET_EVENT_PACKET 7

#define NET_DIR_UNKNOWN 0
#define NET_DIR_INBOUND 1
#define NET_DIR_OUTBOUND 2

#define NET_PROTO_UNKNOWN 0
#define NET_PROTO_TCP 1
#define NET_PROTO_UDP 2

struct net_event {
    __u32 event_type;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u8 direction;
    __u8 protocol;
    __u16 reserved0;
    __u32 local_ip_v4;
    __u32 remote_ip_v4;
    __u16 local_port;
    __u16 remote_port;
    __u64 cgroup_id;
    char extra[MAX_EVENT_EXTRA_BYTES];
};

#endif
