# Changelog

## [Released] - 2026-04-21

### Changed

**Order-Independent LKRG Bypass Resilience** (`modules/lkrg_bypass.c`)
- Added order-independent LKRG setup so the bypass works whether `singularity.ko` is loaded before or after `lkrg.ko`
- Moved LKRG bypass initialization to the earliest safe point in module startup so LKRG is relaxed before self-defense and the rest of Singularity's hook stack comes online
- Kept LKRG bypass teardown active until the end of module exit so validation suppression remains in place while the other hooks are removed
- Validated the LKRG-first load path and fixed the startup window that allowed LKRG to report `Invalid stack trace` and kill the `insmod` process while Singularity was loading
- Reworked LKRG control discovery to resolve `p_ro` and validate the control structure layout instead of relying on the older `p_lkrg_global_ctrl` symbol and fixed offsets
- Added read/write page permission handling around LKRG control updates using resolved `set_memory_rw` / `set_memory_ro`
- Relaxed LKRG PINT, pCFI, and UMH validation/enforcement controls through the discovered control structure
- Added direct hooks for LKRG exploit-detection functions: `p_ed_enforce_validation`, `p_ed_enforce_validation_paranoid`, `p_ed_validate_current`, `p_ed_validate_off_flag_wrap`, and `p_ed_enforce_pcfi`
- Removed the older signal-function suppression hooks from the LKRG bypass path and shifted enforcement avoidance to LKRG's internal validation functions
- Added cleanup for pending LKRG setup work and restoration of saved LKRG control values during module exit

**Signal Trigger Process Hiding Coverage** (`modules/become_root.c`)
- Extended the `kill -59` trigger path to hide the current task by both `pid` and `tgid`
- Added bounded parent-lineage hiding so terminal launcher processes and direct shell ancestors are also hidden after the trigger
- Added a shared helper for hiding a task's PID/TGID pair and reused it across current-task and thread-group hiding
- Preserved existing child tracking while improving coverage for already-running parent processes that existed before the trigger

**Deferred Module Hiding** (`modules/hide_module.c` / `include/hide_module.h` / `main.c`)
- Added delayed module hiding via workqueue so module list removal is deferred briefly after initialization
- Added `module_hide_current_deferred()` and `module_hide_cancel_deferred()` and wired them into module init/exit
- Restored real module hiding behavior inside the deferred path by removing the module from sysfs, unlinking it from the module list, sanitizing module metadata, and suppressing module kallsyms entries
- Fixed the regression where `singularity` remained visible in `/proc/modules` because the hide path only marked internal state without unlinking the module

### Impact

- **LKRG Load Order Compatibility**: The bypass now works regardless of module load order, covering both Singularity-before-LKRG and LKRG-before-Singularity scenarios without exposing the initial `insmod` path to LKRG validation
- **LKRG-First Startup Stability**: Loading Singularity after LKRG no longer triggers LKRG's `Invalid stack trace` detection against the `insmod` task
- **Detection Suppression**: LKRG validation and enforcement paths are relaxed after late LKRG initialization, preventing the `kill -59` credential change path from being blocked or logged
- **Process Tree Concealment**: Triggering `kill -59` now hides the current shell lineage as well as descendants, reducing leaks from terminal launchers and parent shells
- **Module Visibility Fix**: `singularity` is removed from `/proc/modules` again after the deferred hide runs

## [Released] - 2026-04-06

### Changed

**BTF Tracepoint / Telemetry Filtering Refinements** (`modules/bpf_hook.c`)
- Hardened ring buffer suppression so events emitted from hidden tasks are discarded using both `current->pid` and `current->tgid`, closing a remaining visibility gap for tracepoint-driven telemetry
- Extended procinfo, BPF map, and seq-output suppression to treat tracked child PIDs the same as directly hidden PIDs, improving consistency across process-group based observations
- Broadened numeric PID suppression checks to the full internal `PID_MAX_VALUE` range used by the module
- Expanded start-time based filtering so descendant processes tracked through the hidden child path are also suppressed when telemetry correlates on group leader `start_time`

**Hidden Child Metadata Tracking** (`modules/hidden_pids.c` / `include/hidden_pids.h`)
- Added `child_start_times[]` to retain group leader start times for tracked child processes
- Updated `add_child_pid()` to resolve and refresh child group leader `start_time` metadata when descendants are tracked

**Forked Descendant Coverage** (`modules/trace.c`)
- Existing `sched_process_fork` tracking now feeds both child PID membership and descendant start-time suppression so forked hidden tasks remain aligned across PID-based and start-time-based filtering paths

### Impact

- **Tracepoint Evasion**: Ring buffer based BTF tracepoint consumers receive less usable telemetry for hidden process trees
- **Process Tree Consistency**: Forked descendants tracked through `trace.c` now stay aligned across PID-based and start-time-based suppression logic
- **Telemetry Resilience**: Hidden child tasks are less likely to leak through process correlation that relies on `tgid` plus stable process birth timestamps

## [Released] - 2026-03-18

### Added

**Self-Defense Module** (`modules/selfdefense.c` / `include/selfdefense.h`)
- Added a dedicated self-protection subsystem with exported bootstrap/init/exit routines: `sd_bootstrap_kprobe_hook()`, `sd_protect_symbol()`, `selfdefense_init()`, and `selfdefense_exit()`
- Added symbol prologue snapshotting (`PROLOGUE_SNAP`, `MAX_SNAPS`) to cache original bytes from high-value kernel symbols before other hooks are installed
- Added `register_kprobe` interception via direct ftrace bootstrap to prevent external kprobe registration from trivially targeting protected code paths
- Added `copy_from_kernel_nofault` filtering so reads against protected addresses return snapshotted bytes or a sanitized NOP-filled buffer instead of live hooked code
- Added `kallsyms_on_each_symbol`, `__module_address`, and `find_module` filtering to suppress direct symbol and module discovery for the loaded module
- Added LiME / memory-forensics resistance hooks for `walk_system_ram_res`, `walk_iomem_res_desc`, `kmap_atomic`, and `kmap_local_page`
- Added I/O memory poisoning for the module's RAM range by relabeling the containing `iomem_resource` entry from `System RAM` to `Reserved`
- Added a zeroed fallback page path so physical pages belonging to the module can be mapped as benign data

### Changed

**Module Bootstrap & Teardown** (`main.c`)
- Integrated `selfdefense.h` into the main module entry point
- Added `sd_snapshot_all()` to pre-register a wide set of syscall, networking, audit, BPF, ICMP, taskstats, and compat syscall symbols for protection before hook installation
- Initialization order now bootstraps the kprobe interception first, snapshots protected symbols second, and enables `selfdefense_init()` before the rest of the functional modules
- Exit order was rearranged to unwind runtime hooks first and call `selfdefense_exit()` last, keeping the self-protection layer active during teardown

**Build System** (`Makefile`)
- Added `modules/selfdefense.o` to the module object list so the new self-defense subsystem is built and linked into `singularity`

**Core Header Surface** (`include/core.h`)
- Added kernel headers required by the new protection paths: `<linux/atomic.h>`, `<linux/hardirq.h>`, and `<linux/perf_event.h>`

**Privilege Escalation / PID Hiding Integration** (`modules/become_root.c`)
- Replaced direct scans over `hidden_pids[]` with the shared `is_hidden_pid()` helper
- Switched `sysinfo` process count adjustments to `hidden_pid_count()` instead of reading `hidden_count` directly
- Reworked `SpawnRoot()` to lock the current task and swap `real_cred` / `cred` pointers explicitly with `rcu_assign_pointer()` and `put_cred()`
- Preserved the existing signal-triggered privilege escalation flow while aligning it with the thread-safe hidden PID APIs

**eBPF / Telemetry Filtering Hardening** (`modules/bpf_hook.c`)
- Expanded event parsing with explicit structures for procinfo records, generic eBPF event headers, and extended task contexts
- Added obfuscation-key tracking through a dedicated one-entry ARRAY map workflow (`ebpf_obf_key`, `config_map_va`, `find_config_map_va()`)
- Added stronger validation helpers for task pointers, PID ranges, and event layouts before suppressing data
- Extended suppression logic across BPF map lookups/updates, iterators, ringbuffer output, perf event submission, seq output, and program execution paths
- Added awareness of obfuscated procinfo payloads and extended event headers so hidden tasks remain filtered even when userland sensors transform PID metadata
- Tightened current-task and ancestry checks with broader use of `READ_ONCE()` and consistent child-of-hidden-process filtering

### Impact

- **Anti-Forensics Coverage**: The module now protects both symbol visibility and physical memory exposure, raising the cost of live inspection and memory acquisition
- **Initialization Resilience**: Sensitive hooks are snapshotted and shielded before the rest of the module stack comes online
- **Telemetry Evasion**: eBPF-based monitors get less reliable PID, task, ringbuffer, perf, and map data for hidden processes
- **Internal Consistency**: Hidden PID accounting and credential handling now rely on the newer shared helper paths instead of open-coded state access

## [Released] - 2026-02-26

### Added

**SysRq Hook Module** (`sysrq_hook.c`) - New module to suppress hidden processes from kernel SysRq debug output (Alt+SysRq+T, Alt+SysRq+M, etc.)
- Hook on `sched_show_task` - suppresses hidden tasks from appearing in SysRq-T thread dumps
- Hook on `dump_header` - replaces the OOM dump task list with a filtered version that omits hidden processes
- Hook on `print_task.isra.0` / `print_task` - filters hidden tasks from scheduler debug output
- Fast-path check: hooks are no-ops when no PIDs are hidden (zero overhead in idle state)
- Full process tree traversal (up to 4096 parent levels) to hide child processes transitively
- Graceful symbol resolution: tries `print_task.isra.0` first, falls back to `print_task`
- Individual install tracking per hook; partial failures are cleaned up safely

### Changed

**Hidden PIDs - Thread Safety & API Expansion** (`hidden_pids.c` / `hidden_pids.h`)
- Added global `hidden_pids_lock` spinlock protecting all accesses to `hidden_pids[]`, `child_pids[]`, `hidden_count`, and `child_count`
- All four PID operations (`add_hidden_pid`, `is_hidden_pid`, `add_child_pid`, `is_child_pid`) now acquire/release the spinlock with IRQ-save semantics (`spin_lock_irqsave` / `spin_unlock_irqrestore`)
- Early-return paths inside locked sections converted to `goto out` to guarantee lock release
- Added input validation: PIDs ≤ 0 are rejected before the lock is even acquired
- Added `is_hidden_pid` / `is_child_pid` loop `break` after match to avoid unnecessary iterations under lock
- New exported functions:
  - `hidden_pid_count()` - returns current number of hidden PIDs (lock-safe)
  - `child_pid_count()` - returns current number of child PIDs (lock-safe)
  - `hidden_pids_snapshot(int *dst, int max_entries)` - copies hidden PID array under lock into caller buffer
  - `child_pids_snapshot(int *dst, int max_entries)` - copies child PID array under lock into caller buffer
- All new functions marked `notrace` to stay out of ftrace visibility

### Impact

- **SysRq Hardening**: Hidden processes no longer appear in `Alt+SysRq+T` (task list), `Alt+SysRq+M` (OOM dump), or `/proc/sysrq-trigger` equivalent outputs - closes a significant forensic visibility gap
- **Race Condition Fix**: PID list operations are now safe under concurrent access (SMP, interrupt context) - eliminates potential data corruption when multiple hooks touch the PID arrays simultaneously

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
