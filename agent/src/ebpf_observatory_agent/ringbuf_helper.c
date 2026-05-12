#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "bpf/common.h"

static volatile sig_atomic_t stop = 0;
static __u32 skipped_pid = 0;
static struct bpf_link *links[32];
static size_t link_count = 0;
static struct bpf_tc_hook tc_hooks[2];
static struct bpf_tc_opts tc_opts[2];
static size_t tc_count = 0;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void ipv4_to_str(__u32 addr, char *buf, size_t buf_len)
{
    struct in_addr in = {
        .s_addr = addr,
    };
    if (!inet_ntop(AF_INET, &in, buf, buf_len)) {
        snprintf(buf, buf_len, "0.0.0.0");
    }
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    (void)size;

    const struct net_event *event = data;
    char local_ip[INET_ADDRSTRLEN];
    char remote_ip[INET_ADDRSTRLEN];

    if (event->pid != 0 && skipped_pid != 0 && event->pid == skipped_pid) {
        return 0;
    }

    if (event->local_ip_v4 == 0 && event->remote_ip_v4 == 0 && event->local_port == 0 && event->remote_port == 0) {
        return 0;
    }

    if ((strcmp(event->comm, "python") == 0 || strcmp(event->comm, "uvicorn") == 0) &&
        (event->local_port == 8000 || event->remote_port == 8000 ||
         (event->local_ip_v4 != 0 && event->remote_ip_v4 != 0 && event->local_ip_v4 == event->remote_ip_v4))) {
        return 0;
    }

    ipv4_to_str(event->local_ip_v4, local_ip, sizeof(local_ip));
    ipv4_to_str(event->remote_ip_v4, remote_ip, sizeof(remote_ip));

    printf(
        "{\"event_type\":%u,\"timestamp_ns\":%llu,\"pid\":%u,\"tid\":%u,\"uid\":%u,\"comm\":\"%s\",\"direction\":%u,\"protocol\":%u,\"local_ip\":\"%s\",\"remote_ip\":\"%s\",\"local_port\":%u,\"remote_port\":%u,\"cgroup_id\":%llu,\"extra\":\"%s\"}\n",
        event->event_type,
        (unsigned long long)event->timestamp_ns,
        event->pid,
        event->tid,
        event->uid,
        event->comm,
        event->direction,
        event->protocol,
        local_ip,
        remote_ip,
        event->local_port,
        event->remote_port,
        (unsigned long long)event->cgroup_id,
        event->extra
    );
    fflush(stdout);
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level > LIBBPF_WARN) {
        return 0;
    }
    vfprintf(stderr, format, args);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <bpf-object-file>\n", argv[0]);
        return 1;
    }

    const char *obj_file = argv[1];
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;
    struct ring_buffer *rb = NULL;
    int ringbuf_fd = -1;
    int err = 0;

    const char *skip_pid_env = getenv("EBPF_OBSERVATORY_SKIP_PID");
    const char *iface_env = getenv("EBPF_OBSERVATORY_IFACE");
    unsigned int ifindex = 0;

    if (skip_pid_env != NULL && skip_pid_env[0] != '\0') {
        skipped_pid = (__u32)strtoul(skip_pid_env, NULL, 10);
    }
    if (iface_env != NULL && iface_env[0] != '\0') {
        ifindex = if_nametoindex(iface_env);
        if (ifindex == 0) {
            fprintf(stderr, "failed to resolve interface: %s\n", iface_env);
            return 1;
        }
    }

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    obj = bpf_object__open_file(obj_file, NULL);
    if (!obj) {
        fprintf(stderr, "failed to open BPF object: %s\n", obj_file);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    bpf_object__for_each_program(prog, obj) {
        const char *section = bpf_program__section_name(prog);
        struct bpf_link *link = NULL;

        if (section && strcmp(section, "tracepoint/syscalls/sys_exit_connect") == 0) {
            link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_exit_connect");
        } else if (section && strcmp(section, "tracepoint/syscalls/sys_enter_accept4") == 0) {
            continue;
        } else if (section && strcmp(section, "tracepoint/syscalls/sys_enter_sendto") == 0) {
            continue;
        } else if (section && strcmp(section, "tracepoint/sock/inet_sock_set_state") == 0) {
            link = bpf_program__attach_tracepoint(prog, "sock", "inet_sock_set_state");
        } else if (section && strcmp(section, "kretprobe/inet_csk_accept") == 0) {
            link = bpf_program__attach_kprobe(prog, true, "inet_csk_accept");
        } else if (section && strcmp(section, "classifier") == 0 && strcmp(bpf_program__name(prog), "trace_tc_ingress") == 0 && ifindex != 0) {
            struct bpf_tc_hook hook = {
                .sz = sizeof(hook),
                .ifindex = (int)ifindex,
                .attach_point = BPF_TC_INGRESS,
            };
            struct bpf_tc_opts opts = {
                .sz = sizeof(opts),
                .prog_fd = bpf_program__fd(prog),
                .flags = BPF_TC_F_REPLACE,
                .handle = 1,
                .priority = 1,
            };
            err = bpf_tc_hook_create(&hook);
            if (err && err != -EEXIST) {
                fprintf(stderr, "failed to create TC ingress hook on %s: %d\n", iface_env, err);
                bpf_object__close(obj);
                return 1;
            }
            err = bpf_tc_attach(&hook, &opts);
            if (err) {
                fprintf(stderr, "failed to attach TC ingress program on %s: %d\n", iface_env, err);
                bpf_object__close(obj);
                return 1;
            }
            if (tc_count < sizeof(tc_hooks) / sizeof(tc_hooks[0])) {
                tc_hooks[tc_count] = hook;
                tc_opts[tc_count] = opts;
                tc_count++;
            }
            continue;
        } else if (section && strcmp(section, "classifier") == 0 && strcmp(bpf_program__name(prog), "trace_tc_egress") == 0 && ifindex != 0) {
            struct bpf_tc_hook hook = {
                .sz = sizeof(hook),
                .ifindex = (int)ifindex,
                .attach_point = BPF_TC_EGRESS,
            };
            struct bpf_tc_opts opts = {
                .sz = sizeof(opts),
                .prog_fd = bpf_program__fd(prog),
                .flags = BPF_TC_F_REPLACE,
                .handle = 2,
                .priority = 1,
            };
            err = bpf_tc_hook_create(&hook);
            if (err && err != -EEXIST) {
                fprintf(stderr, "failed to create TC egress hook on %s: %d\n", iface_env, err);
                bpf_object__close(obj);
                return 1;
            }
            err = bpf_tc_attach(&hook, &opts);
            if (err) {
                fprintf(stderr, "failed to attach TC egress program on %s: %d\n", iface_env, err);
                bpf_object__close(obj);
                return 1;
            }
            if (tc_count < sizeof(tc_hooks) / sizeof(tc_hooks[0])) {
                tc_hooks[tc_count] = hook;
                tc_opts[tc_count] = opts;
                tc_count++;
            }
            continue;
        } else {
            continue;
        }

        if (!link) {
            fprintf(stderr, "failed to attach program %s (%s)\n", bpf_program__name(prog), section);
            bpf_object__close(obj);
            return 1;
        }
        if (link_count < sizeof(links) / sizeof(links[0])) {
            links[link_count++] = link;
        }
    }

    map = bpf_object__find_map_by_name(obj, "events");
    if (!map) {
        fprintf(stderr, "ringbuf map 'events' not found\n");
        bpf_object__close(obj);
        return 1;
    }

    ringbuf_fd = bpf_map__fd(map);
    if (ringbuf_fd < 0) {
        fprintf(stderr, "invalid ringbuf fd\n");
        bpf_object__close(obj);
        return 1;
    }

    rb = ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        bpf_object__close(obj);
        return 1;
    }

    while (!stop) {
        err = ring_buffer__poll(rb, 1000);
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring buffer poll failed: %d\n", err);
            break;
        }
    }

    for (size_t i = 0; i < tc_count; i++) {
        bpf_tc_detach(&tc_hooks[i], &tc_opts[i]);
    }
    for (size_t i = 0; i < link_count; i++) {
        bpf_link__destroy(links[i]);
    }
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
