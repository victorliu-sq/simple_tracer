#ifndef __AGENT_SCHEDULE_BPF_H
#define __AGENT_SCHEDULE_BPF_H

#include "agent.h"

// Forward declarations.
static agent_t agent_oncpu;
static agent_t agent_runqlat;

// Data BPF Maps.
static struct metric initial_hist;
// BPF_MAP(start_oncpu, BPF_MAP_TYPE_HASH, MAX_SAMPLES, u32, u64);
// BPF_MAP(hists_oncpu, BPF_MAP_TYPE_HASH, MAX_SAMPLES, u32, struct metric);

BPF_MAP(start_runqlat, BPF_MAP_TYPE_HASH, MAX_SAMPLES, u32, u64);
BPF_MAP(hists_runqlat, BPF_MAP_TYPE_HASH, MAX_SAMPLES, u32, struct metric);

/*
static __always_inline void update_hist(struct task_struct *task, u32 pid, u64 ts)
{
    u64 delta, *tsp, slot;
    struct metric *histp;

    u32 pid_ns = bpf_get_pid_ns(task);

    tsp = bpf_map_lookup_elem(&start_oncpu, &pid);
    if (!tsp || ts < *tsp)
    {
        return;
    }

    histp = bpf_map_lookup_or_try_init(&hists_oncpu, &pid_ns, &initial_hist);
    if (!histp)
    {
        return;
    }

    delta = ts - *tsp;
    // delta /= 1000;
    slot = get_bin_id(delta);
    __sync_fetch_and_add(&histp->slots[slot], 1);
}
*/
/*
Handler for sched_switch tracepoint.
*/
/*
static __always_inline int handle_sched_switch_oncpu(
    bool preempt,
    struct task_struct *prev,
    struct task_struct *next,
    bpf_hist_metadata_t *prev_metadata,
    bpf_hist_metadata_t *next_metadata)
{
    u32 prev_pid = prev->pid;
    u32 pid = next->pid;
    u64 ts = bpf_ktime_get_ns();

    if (prev_metadata && prev_metadata->config[agent_oncpu.metric_id].active)
    {
        update_hist(prev, prev_pid, ts);
        // bpf_map_update_elem(&start_oncpu, &prev_pid, &ts, 0);
    }
    if (next_metadata && next_metadata->config[agent_oncpu.metric_id].active)
    {
        bpf_map_update_elem(&start_oncpu, &pid, &ts, 0);
        // update_hist(next, pid, ts);
    }
    return 0;
}
*/
static __always_inline int trace_enqueue(u32 tgid, u32 pid)
{
    if (!pid)
    {
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_runqlat, &pid, &ts, 0);
    return 0;
}

/*
Handler for sched_wakeup tracepoint.
*/
static __always_inline int handle_sched_wakeup_runqlat(
    struct task_struct *p,
    bpf_hist_metadata_t *p_metadata)
{
    if (p_metadata && p_metadata->config[agent_runqlat.metric_id].active)
    {
        return trace_enqueue(p->tgid, p->pid);
    }
    return 0;
}

/*
Handler for sched_wakeup_new tracepoint.
*/
static __always_inline int handle_sched_wakeup_new_runqlat(
    struct task_struct *p,
    bpf_hist_metadata_t *p_metadata)
{
    if (p_metadata && p_metadata->config[agent_runqlat.metric_id].active)
    {
        return trace_enqueue(p->tgid, p->pid);
    }
    return 0;
}

/*
Handler for sched_switch tracepoint.
*/
static __always_inline int handle_sched_switch_runqlat(
    bool preempt,
    struct task_struct *prev,
    struct task_struct *next,
    bpf_hist_metadata_t *prev_metadata,
    bpf_hist_metadata_t *next_metadata)
{
    struct metric *histp;
    u64 *tsp, slot;
    u32 tgid, pid;
    s64 delta;

    if (prev_metadata)
    {
        bpf_config_t runq_prev_conf = prev_metadata->config[agent_runqlat.metric_id];
        if (runq_prev_conf.active && get_task_state(prev) == TASK_RUNNING && sample(runq_prev_conf.freq))
        {
            trace_enqueue(prev->tgid, prev->pid);
        }
    }

    if (next_metadata && next_metadata->config[agent_runqlat.metric_id].active)
    {
        pid = next->pid;
        tgid = next->tgid;

        tsp = bpf_map_lookup_elem(&start_runqlat, &pid);
        if (!tsp)
        {
            return 0;
        }
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 0)
        {
            goto cleanup;
        }

        // TODO: if this errors
        u32 pid_ns = bpf_get_pid_ns(next);

        histp = bpf_map_lookup_or_try_init(&hists_runqlat, &pid_ns, &initial_hist);
        if (!histp)
        {
            goto cleanup;
        }

        // delta /= 1000U;
        slot = get_bin_id(delta);
        __sync_fetch_and_add(&histp->slots[slot], 1);

    cleanup:
        bpf_map_delete_elem(&start_runqlat, &pid);
    }

    return 0;
}

// ---------- BPF Agent definitions ----------
/*
static agent_t agent_oncpu = {
    .metric_id = 0,
    .handle_sched_switch = handle_sched_switch_oncpu,
};
*/
static agent_t agent_runqlat = {
    .metric_id = 1,
    .handle_sched_switch = handle_sched_switch_runqlat,
    .handle_sched_wakeup = handle_sched_wakeup_runqlat,
    .handle_sched_wakeup_new = handle_sched_wakeup_new_runqlat,
};

#endif /* __AGENT_SCHEDULE_BPF_H  */
