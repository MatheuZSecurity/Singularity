#ifndef ANTI_LKRG_KPROBE_H
#define ANTI_LKRG_KPROBE_H

notrace int lkrg_bypass_init(void);
notrace void lkrg_bypass_exit(void);
notrace bool lkrg_hooked(void);
notrace void enable_umh_bypass(void);
notrace void disable_umh_bypass(void);

#endif
