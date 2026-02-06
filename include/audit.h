#ifndef HOOKING_AUDIT_H
#define HOOKING_AUDIT_H

notrace int hooking_audit_init(void);
notrace void hooking_audit_exit(void);
notrace int get_blocked_audit_count(void);
notrace int get_total_audit_count(void);

#endif
