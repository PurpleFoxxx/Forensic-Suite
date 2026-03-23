#!/bin/bash
# Linux Forensic Collector — Bash fallback
# Runs when Python is not available on target system
# All output written to OUTPUT_DIR (USB) only
# No files written to target filesystem
# Volatile data collected first

set -u

OUTPUT_DIR="${1:?usage: bash_collector.sh <output_dir>}"
INVESTIGATOR="${2:-unknown}"
CASE_ID="CASE-$(date +%Y%m%d-%H%M%S)"
CASE_DIR="${OUTPUT_DIR}/${CASE_ID}"
HASH_LOG="${CASE_DIR}/hashes.txt"

mkdir -p "${CASE_DIR}/disk" \
         "${CASE_DIR}/memory" \
         "${CASE_DIR}/network" \
         "${CASE_DIR}/logs"

log() {
    printf '{"ts":"%s","event":"%s"}\n' "$(date -Iseconds)" "$1" \
        >> "${CASE_DIR}/logs/session.log"
}

# Write artifact to USB, append sha256 to hashes.txt
# Usage: artifact <subdir> <filename> <command>
artifact() {
    local subdir="$1" fname="$2"
    shift 2
    local path="${CASE_DIR}/${subdir}/${fname}"
    eval "$@" > "${path}" 2>/dev/null
    if [ -s "${path}" ]; then
        local h
        h=$(sha256sum "${path}" | awk '{print $1}')
        printf '%s  %s/%s\n' "${h}" "${subdir}" "${fname}" >> "${HASH_LOG}"
    fi
}

log "session_start"
log "case_id=${CASE_ID}"
log "investigator=${INVESTIGATOR}"

# ── VOLATILE MEMORY — collect first ──────────────────────

# Running processes
artifact memory ps_full.txt           "ps auxwwef"
artifact memory pstree.txt            "pstree -p -a -l 2>/dev/null || ps --forest aux 2>/dev/null"

# Process details from /proc — kernel read-only interface
{
    for pid in /proc/[0-9]*/; do
        pid="${pid%/}"; pid="${pid##*/}"
        [ -f "/proc/${pid}/status" ] || continue
        name=$(awk '/^Name:/{print $2}' "/proc/${pid}/status" 2>/dev/null)
        state=$(awk '/^State:/{print $2}' "/proc/${pid}/status" 2>/dev/null)
        ppid=$(awk '/^PPid:/{print $2}' "/proc/${pid}/status" 2>/dev/null)
        vmrss=$(awk '/^VmRSS:/{print $2,$3}' "/proc/${pid}/status" 2>/dev/null)
        exe=$(readlink "/proc/${pid}/exe" 2>/dev/null || printf 'n/a')
        cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | head -c 256)
        printf 'pid=%s name=%s state=%s ppid=%s vmrss=%s exe=%s cmd=%s\n' \
            "${pid}" "${name}" "${state}" "${ppid}" "${vmrss}" "${exe}" "${cmdline}"
    done
} > "${CASE_DIR}/memory/proc_list.txt"
if [ -s "${CASE_DIR}/memory/proc_list.txt" ]; then
    h=$(sha256sum "${CASE_DIR}/memory/proc_list.txt" | awk '{print $1}')
    printf '%s  memory/proc_list.txt\n' "${h}" >> "${HASH_LOG}"
fi

# Open file descriptors — /proc read-only
{
    for pid in /proc/[0-9]*/; do
        pid="${pid%/}"; pid="${pid##*/}"
        comm=$(cat "/proc/${pid}/comm" 2>/dev/null)
        for fd in /proc/${pid}/fd/*; do
            [ -e "${fd}" ] || continue
            target=$(readlink "${fd}" 2>/dev/null)
            printf 'pid=%s comm=%s fd=%s -> %s\n' \
                "${pid}" "${comm}" "${fd##*/}" "${target}"
        done
    done
} > "${CASE_DIR}/memory/open_fds.txt"
if [ -s "${CASE_DIR}/memory/open_fds.txt" ]; then
    h=$(sha256sum "${CASE_DIR}/memory/open_fds.txt" | awk '{print $1}')
    printf '%s  memory/open_fds.txt\n' "${h}" >> "${HASH_LOG}"
fi

# Memory maps — /proc read-only
{
    for pid in /proc/[0-9]*/; do
        pid="${pid%/}"; pid="${pid##*/}"
        [ -f "/proc/${pid}/maps" ] || continue
        printf '=== %s ===\n' "${pid}"
        cat "/proc/${pid}/maps" 2>/dev/null
    done
} > "${CASE_DIR}/memory/proc_maps.txt"
if [ -s "${CASE_DIR}/memory/proc_maps.txt" ]; then
    h=$(sha256sum "${CASE_DIR}/memory/proc_maps.txt" | awk '{print $1}')
    printf '%s  memory/proc_maps.txt\n' "${h}" >> "${HASH_LOG}"
fi

# Environment variables — /proc read-only
{
    for pid in /proc/[0-9]*/; do
        pid="${pid%/}"; pid="${pid##*/}"
        [ -f "/proc/${pid}/environ" ] || continue
        printf '=== pid=%s ===\n' "${pid}"
        tr '\0' '\n' < "/proc/${pid}/environ" 2>/dev/null | head -50
    done
} > "${CASE_DIR}/memory/proc_environ.txt"
if [ -s "${CASE_DIR}/memory/proc_environ.txt" ]; then
    h=$(sha256sum "${CASE_DIR}/memory/proc_environ.txt" | awk '{print $1}')
    printf '%s  memory/proc_environ.txt\n' "${h}" >> "${HASH_LOG}"
fi

artifact memory meminfo.txt           "cat /proc/meminfo"
artifact memory vmstat.txt            "vmstat -s"
artifact memory who.txt               "who"
artifact memory w.txt                 "w"
artifact memory lsmod.txt             "lsmod"
artifact memory sysctl.txt            "sysctl -a 2>/dev/null"
artifact memory interrupts.txt        "cat /proc/interrupts"
artifact memory dmesg.txt             "dmesg 2>/dev/null"
artifact memory uptime.txt            "uptime"
artifact memory uname.txt             "uname -a"

# ── NETWORK VOLATILE — collect before anything changes ───

artifact network connections.txt      "ss -tupwan"
artifact network listening.txt        "ss -tlpn; ss -ulpn"
artifact network arp.txt              "ip neigh show"
artifact network interfaces.txt       "ip addr show"
artifact network routes.txt           "ip route show; ip -6 route show"

# /proc/net — raw kernel network state, read-only
for table in tcp tcp6 udp udp6 arp dev if_inet6 sockstat; do
    [ -f "/proc/net/${table}" ] && \
        artifact network "proc_net_${table}.txt" "cat /proc/net/${table}"
done

artifact network resolv.conf          "cat /etc/resolv.conf"
artifact network hosts.txt            "cat /etc/hosts"
artifact network iptables.txt         "iptables -L -n -v --line-numbers 2>/dev/null"
artifact network iptables_nat.txt     "iptables -t nat -L -n -v 2>/dev/null"
artifact network ip6tables.txt        "ip6tables -L -n -v 2>/dev/null"
artifact network nftables.txt         "nft list ruleset 2>/dev/null"
artifact network ufw.txt              "ufw status verbose 2>/dev/null"
artifact network wireless.txt         "iw dev 2>/dev/null"
artifact network syslog.txt           "tail -500 /var/log/syslog 2>/dev/null || tail -500 /var/log/messages 2>/dev/null"

# Packet capture — passive only, no packets sent
PCAP_PATH="${CASE_DIR}/network/capture.pcap"
PCAP_DUR="${PCAP_DURATION:-60}"
if command -v tcpdump > /dev/null 2>&1; then
    tcpdump -i any -w "${PCAP_PATH}" -s 0 --immediate-mode \
        > /dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep "${PCAP_DUR}"
    kill "${TCPDUMP_PID}" 2>/dev/null
    wait "${TCPDUMP_PID}" 2>/dev/null
    if [ -s "${PCAP_PATH}" ]; then
        h=$(sha256sum "${PCAP_PATH}" | awk '{print $1}')
        printf '%s  network/capture.pcap\n' "${h}" >> "${HASH_LOG}"
    fi
elif command -v tshark > /dev/null 2>&1; then
    tshark -i any -w "${PCAP_PATH}" -a "duration:${PCAP_DUR}" \
        > /dev/null 2>&1
    if [ -s "${PCAP_PATH}" ]; then
        h=$(sha256sum "${PCAP_PATH}" | awk '{print $1}')
        printf '%s  network/capture.pcap\n' "${h}" >> "${HASH_LOG}"
    fi
fi

# ── DISK — less volatile, collect after memory/network ───

artifact disk block_devices.txt       "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,LABEL,MODEL"
artifact disk partition_tables.txt    "fdisk -l"
artifact disk mounts.txt              "mount"
artifact disk fstab.txt               "cat /etc/fstab"
artifact disk df.txt                  "df -hT"
artifact disk dev_listing.txt         "ls -la /dev/"
artifact disk swap.txt                "cat /proc/swaps"
artifact disk recently_modified.txt   "find / -xdev -mtime -7 -type f 2>/dev/null | head -1000"
artifact disk suid.txt                "find / -xdev -perm -4000 -type f 2>/dev/null"
artifact disk sgid.txt                "find / -xdev -perm -2000 -type f 2>/dev/null"
artifact disk hidden_files.txt        "find /home /root -name '.*' -maxdepth 4 2>/dev/null"

# MBR — raw 512 byte read, written to USB
for disk in $(lsblk -d -o NAME,TYPE --noheadings 2>/dev/null | awk '$2=="disk"{print $1}'); do
    dd if="/dev/${disk}" bs=512 count=1 iflag=direct \
        of="${CASE_DIR}/disk/mbr_${disk}.raw" 2>/dev/null
    if [ -f "${CASE_DIR}/disk/mbr_${disk}.raw" ]; then
        h=$(sha256sum "${CASE_DIR}/disk/mbr_${disk}.raw" | awk '{print $1}')
        printf '%s  disk/mbr_%s.raw\n' "${h}" "${disk}" >> "${HASH_LOG}"
    fi
done

# ── PERSISTENCE ARTIFACTS ────────────────────────────────

artifact memory passwd.txt            "cat /etc/passwd"
artifact memory shadow.txt            "cat /etc/shadow 2>/dev/null"
artifact memory group.txt             "cat /etc/group"
artifact memory sudoers.txt           "cat /etc/sudoers 2>/dev/null"
artifact memory last.txt              "last -50"
artifact memory lastlog.txt           "lastlog"
artifact memory os_release.txt        "cat /etc/os-release"
artifact memory systemd_services.txt  "systemctl list-units --type=service --all 2>/dev/null"
artifact memory systemd_timers.txt    "systemctl list-timers --all 2>/dev/null"
artifact memory auth_log.txt          "tail -500 /var/log/auth.log 2>/dev/null || tail -500 /var/log/secure 2>/dev/null"
artifact network authorized_keys.txt  "find / -name authorized_keys 2>/dev/null | xargs cat 2>/dev/null"

# Shell histories
{
    for hfile in /root/.bash_history /root/.zsh_history \
        $(find /home -maxdepth 3 -name '.bash_history' -o -name '.zsh_history' 2>/dev/null); do
        [ -f "${hfile}" ] || continue
        printf '=== %s ===\n' "${hfile}"
        cat "${hfile}" 2>/dev/null
        printf '\n'
    done
} > "${CASE_DIR}/memory/shell_histories.txt"
if [ -s "${CASE_DIR}/memory/shell_histories.txt" ]; then
    h=$(sha256sum "${CASE_DIR}/memory/shell_histories.txt" | awk '{print $1}')
    printf '%s  memory/shell_histories.txt\n' "${h}" >> "${HASH_LOG}"
fi

# Cron jobs
{
    for p in /etc/crontab /etc/cron.d /var/spool/cron; do
        [ -e "${p}" ] || continue
        if [ -f "${p}" ]; then
            printf '=== %s ===\n' "${p}"
            cat "${p}" 2>/dev/null
        elif [ -d "${p}" ]; then
            for f in "${p}"/*; do
                [ -f "${f}" ] || continue
                printf '=== %s ===\n' "${f}"
                cat "${f}" 2>/dev/null
            done
        fi
    done
} > "${CASE_DIR}/memory/cron.txt"
if [ -s "${CASE_DIR}/memory/cron.txt" ]; then
    h=$(sha256sum "${CASE_DIR}/memory/cron.txt" | awk '{print $1}')
    printf '%s  memory/cron.txt\n' "${h}" >> "${HASH_LOG}"
fi

# ── REPORT ───────────────────────────────────────────────

{
    printf 'case_id:      %s\n' "${CASE_ID}"
    printf 'investigator: %s\n' "${INVESTIGATOR}"
    printf 'hostname:     %s\n' "$(hostname -f 2>/dev/null || hostname)"
    printf 'kernel:       %s\n' "$(uname -r)"
    printf 'start:        %s\n' "$(date -Iseconds)"
    printf 'mode:         bash_fallback\n'
    printf 'artifacts:    %d\n' "$(find "${CASE_DIR}" -type f | wc -l)"
} > "${CASE_DIR}/logs/report.txt"

log "session_end"
