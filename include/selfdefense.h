#ifndef SELFDEFENSE_H
#define SELFDEFENSE_H

#include <linux/sched.h>

notrace int  sd_bootstrap_kprobe_hook(void);
notrace void sd_protect_symbol(const char *symname);
notrace int  selfdefense_init(void);
notrace void selfdefense_exit(void);

notrace void sd_register_phys_range(const void *va, size_t size);
notrace void sd_register_hidden_task(struct task_struct *task);

#endif