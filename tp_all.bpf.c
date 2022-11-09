#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../monitor.h"
#include "utils/bits.bpf.h"
#include "utils/maps.bpf.h"
#include "utils/core_fixes.bpf.h"
// Agents
#include "agent_schedule.bpf.h"
// #include "agent_memory.bpf.h"
// #include "agent_disk.bpf.h"
#include "agent_network.bpf.h"

extern int LINUX_KERNEL_VERSION __kconfig;

/*
BPF map that contains metadata associated with each monitored PID. Contents
are set and updated in userspace upon requests from the nodelet C++ application.
*/
BPF_MAP(control, BPF_MAP_TYPE_HASH, MAX_CONTAINERS, u32, bpf_hist_metadata_t);

// ------------------ schedule ------------------

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    u32 pid_ns = bpf_get_pid_ns(p);
    bpf_hist_metadata_t *p_metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_runqlat.handle_sched_wakeup(p, p_metadata);
    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
    u32 pid_ns = bpf_get_pid_ns(p);
    bpf_hist_metadata_t *p_metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_runqlat.handle_sched_wakeup_new(p, p_metadata);
    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    u32 prev_tgid = prev->tgid;
    u32 next_tgid = next->tgid;

    unsigned int pid_ns_prev = bpf_get_pid_ns(prev);
    unsigned int pid_ns_next = bpf_get_pid_ns(next);

    bpf_hist_metadata_t *prev_metadata, *next_metadata;

    prev_metadata = bpf_map_lookup_elem(&control, &pid_ns_prev);
    next_metadata = bpf_map_lookup_elem(&control, &pid_ns_next);

    // Metric handlers.
    // agent_oncpu.handle_sched_switch(preempt, prev, next, prev_metadata, next_metadata);
    agent_runqlat.handle_sched_switch(preempt, prev, next, prev_metadata, next_metadata);
    return 0;
}

/*
// ------------------ memory ------------------

SEC("tracepoint/exceptions/page_fault_user")
int handle_page_fault_user(struct pt_regs *ctx)
{
    u32 pid_ns = bpf_get_current_pid_ns();
    if (pid_ns == 0)
    {
        return 0;
    }
    bpf_hist_metadata_t *metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_user_fault.handle_memory_event(metadata);
    return 0;
}

SEC("tracepoint/exceptions/page_fault_kernel")
int handle_page_fault_kernel(struct pt_regs *ctx)
{
    u32 pid_ns = bpf_get_current_pid_ns();
    if (pid_ns == 0)
    {
        return 0;
    }
    bpf_hist_metadata_t *metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_kernel_fault.handle_memory_event(metadata);
    return 0;
}

SEC("tracepoint/tlb/tlb_flush")
int handle_tlb_flush(struct pt_regs *ctx)
{
    u32 pid_ns = bpf_get_current_pid_ns();
    if (pid_ns == 0)
    {
        return 0;
    }
    bpf_hist_metadata_t *metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_tlb_flush.handle_memory_event(metadata);
    return 0;
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(mark_page_accessed)
{
    u32 pid_ns = bpf_get_current_pid_ns();
    if (pid_ns == 0)
    {
        return 0;
    }
    bpf_hist_metadata_t *metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_cache_total.handle_memory_event(metadata);
    return 0;
}

// ------------------ disk ------------------

SEC("tp_btf/block_rq_insert")
int block_rq_insert(u64 *ctx)
{
    u32 pid_ns = bpf_get_current_pid_ns();
    if (pid_ns == 0)
    {
        return 0;
    }
    bpf_hist_metadata_t *metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_disk_latency.handle_block_rq_insert(metadata, (void *)ctx[1]);
    return 0;
}

SEC("tp_btf/block_rq_issue")
int block_rq_issue(u64 *ctx)
{
    u32 pid_ns = bpf_get_current_pid_ns();
    if (pid_ns == 0)
    {
        return 0;
    }
    bpf_hist_metadata_t *metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_disk_latency.handle_block_rq_insert(metadata, (void *)ctx[1]);
    return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, int error,
             unsigned int nr_bytes)
{
    u32 pid_ns = bpf_get_current_pid_ns();
    if (pid_ns == 0)
    {
        return 0;
    }
    bpf_hist_metadata_t *metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_disk_latency.handle_block_rq_complete(metadata, rq);
    agent_disk_io_size.handle_block_rq_complete(metadata, rq);
    return 0;
}
*/
// ------------------ network ------------------

SEC("fentry/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    if (sk == 0)
    {
        return 0;
    }
    u32 pid_ns = bpf_get_current_pid_ns();
    if (pid_ns == 0)
    {
        return 0;
    }
    bpf_hist_metadata_t *metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_tcp_send_flow.handle_tcp_sendmsg(metadata, sk, size);
    return 0;
}
/*
SEC("tracepoint/skb/kfree_skb")
int trace_tcp_drop(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    u32 pid_ns = bpf_get_current_pid_ns();
    if (pid_ns == 0)
    {
        return 0;
    }
    bpf_hist_metadata_t *metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_tcp_drop.handle_tcp_drop(metadata);
    return 0;
}
*/
SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv, struct sock *sk)
{
    u32 pid_ns = bpf_get_current_pid_ns();
    if (pid_ns == 0)
    {
        return 0;
    }
    bpf_hist_metadata_t *metadata = bpf_map_lookup_elem(&control, &pid_ns);

    // Metric handlers.
    agent_tcp_rtt.handle_tcp_rcv_established(metadata, sk);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
