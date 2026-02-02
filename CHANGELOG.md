# Changelog

## [Released] - 2026-02-02

### Changed

**LKRG Bypass Module - Complete Rewrite**
- Removed all LKRG internal function hooks (p_cmp_creds, p_cmp_tasks, p_check_integrity, etc.)
- New approach: hook kernel functions that LKRG uses instead of LKRG's own functions
- Direct manipulation of LKRG's global control structure (p_lkrg_global_ctrl)
- Memory offset-based control disable/restore (UMH validation, enforcement, PINT validation/enforcement)
- Hooks now target: vprintk_emit, signal functions (do_send_sig_info, send_sig_info, __send_signal_locked, force_sig), usermodehelper functions (call_usermodehelper_exec_async, call_usermodehelper_exec)
- Log filtering system intercepts and suppresses LKRG kernel messages
- SIGKILL interception prevents LKRG from killing hidden processes
- UMH protection bypass during usermode helper execution
- Automatic LKRG detection via symbol presence check
- Module notifier waits for LKRG load then locates control structure

**Technical Changes:**
- Removed 12 LKRG-internal hooks
- Added 7 kernel function hooks
- Added LKRG control structure offsets (UMH_VALIDATE: 0x30, UMH_ENFORCE: 0x34, PINT_VALIDATE: 0x08, PINT_ENFORCE: 0x0c)
- Added log buffer (512 bytes) with spinlock protection
- Added saved state variables for control restoration
- PID extraction from log messages for filtering
- Enhanced lineage checking (up to 64 levels)

### Impact

This version shifts from hooking LKRG's detection functions to disabling LKRG's protections at the source:
- More reliable bypass via direct control structure manipulation
- Prevents LKRG from detecting integrity violations instead of hiding from checks
- Suppresses all LKRG kernel log output for hidden processes
- Blocks LKRG from terminating hidden processes via signal interception
- Cleaner UMH bypass with automatic enable/disable during execution
- Better compatibility across LKRG versions (fewer internal function dependencies)

## [Released] - 2026-01-20

### Added

**LKRG Bypass Module** (`lkrg_bypass.c`) Bypass working on the date it was committed.
- Complete evasion of Linux Kernel Runtime Guard integrity checks
- Hooks: p_check_integrity, p_cmp_creds, p_cmp_tasks, p_ed_pcfi_validate_sp, p_ed_enforce_pcfi
- Task enumeration hiding: p_dump_task_f, ed_task_add
- UMH tracking bypass: p_call_usermodehelper_entry, p_call_usermodehelper_exec_entry, p_call_usermodehelper_ret
- Kprobe interception: kprobe_ftrace_handler
- Exploit detection bypass: p_exploit_detection_init
- Automatic LKRG detection and hook installation on module load
- Process lineage verification (hides entire process trees up to 64 levels deep)
- Module notification system for detecting LKRG loading

**Falco/eBPF Security Bypass** (Bypass working on the date it was committed)
- BPF iterator filtering (bpf_iter_run_prog) - hides processes/sockets from enumeration
- Ringbuffer interception (bpf_ringbuf_output/reserve/submit) - blocks Falco events
- BPF map filtering (bpf_map_lookup_elem/update_elem) - prevents PID tracking
- Perf event suppression (perf_event_output, perf_trace_run_bpf_submit)
- Seq file filtering (bpf_seq_write/printf) - prevents /proc leakage
- Program execution control (__bpf_prog_run) - blocks monitoring in hidden context
- Socket inode tracking for comprehensive network connection hiding
- Bypasses: Falco, Tracee, bpftool, ss with BPF backend

**Enhanced Audit Evasion**
- Socket inode tracking system (MAX_HIDDEN_INODES: 256)
- audit_log_start hook (prevents log creation for hidden processes)
- recvfrom hook (additional netlink SOCK_DIAG/NETFILTER filtering)
- Socket inode extraction from audit messages (socket:[inode] and ino= patterns)
- /proc/[pid] path detection in audit data
- Automatic socket scanning for hidden processes

**Process Hiding Improvements**
- Automatic process tree hiding on kill -59 (hide_process_tree function)
- Thread group hiding for multi-threaded processes (while_each_thread)
- Enhanced child process tracking via process sibling lists
- Immediate hiding with timing delays (msleep(50))

### Changed

**BPF Module Strategy**
- Removed blocking of BPF syscalls (was detection fingerprint)
- New approach: selective data filtering instead of syscall blocking
- Removed: BPF command enumerations, program type checks, link creation filters
- Added: hidden IP caching (cached_ipv4), socket port filtering (HIDDEN_PORT), lineage checking (is_child_of_hidden_process with 10-level depth)

**Privilege Escalation Simplification**
- Removed MAGIC environment variable method
- Removed __x64_sys_getuid hook and rootmagic() function
- Now signal-based only (kill -59) with SpawnRoot()

**ICMP Reverse Shell**
- Integrated with LKRG bypass (enable/disable_umh_bypass calls)
- Automatic process hiding (no manual PID tracking required)
- Cleaner spawning with timing delays (msleep(50))
- SELinux bypass integration maintained

### Removed

**Module Loading Prevention**
- Completely removed hooking_insmod.c and hooking_insmod.h
- Removed init_module/finit_module hooks (x64 + ia32) - 4 hooks total
- Removed to avoid detection fingerprinting and allow legitimate module operations

### Technical Summary

**Hook Changes:**
- +12 LKRG bypass hooks
- +11 eBPF security bypass hooks (bpf syscall hooks already existed)
- +2 audit hooks (audit_log_start, recvfrom)
- -1 privilege escalation hook (getuid)
- -4 module loading hooks

**Files Added:**
- modules/lkrg_bypass.c
- include/lkrg_bypass.h

**Files Removed:**
- modules/hooking_insmod.c
- include/hooking_insmod.h

**Files Modified:**
- main.c (module initialization order)
- Makefile (build targets)
- modules/audit.c (socket inode tracking)
- modules/become_root.c (removed getuid/rootmagic)
- modules/bpf_hook.c (complete rewrite - 600+ lines)
- modules/icmp.c (LKRG bypass integration)

### Impact

This release focuses on evading modern kernel security and eBPF-based monitoring:
- **LKRG**: Completely bypassed (all integrity checks, task enumeration, CFI validation)
- **eBPF Security Tools**: Defeated via data filtering (Falco, Tracee, bpftool)
- **Process Hiding**: More comprehensive with automatic lineage tracking (64 levels)
- **Reverse Shell**: Cleaner with LKRG UMH bypass integration
- **Stealth**: Removed detection fingerprints (no more blanket BPF/module blocking)
- **Audit Evasion**: Enhanced with socket inode correlation
