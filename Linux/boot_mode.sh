#!/bin/bash
# boot mode — runs from bootable USB
# Target OS is not running — no password required
# Write-block applied to target disk before any access
# Target mounted read-only with noatime — no timestamps modified

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/evidence"
MOUNT_POINT="/mnt/forensic_target"

if [ "$(id -u)" -ne 0 ]; then
    printf 'error: must run as root\n' >&2
    exit 1
fi

CASE_ID="BOOT-$(date +%Y%m%d-%H%M%S)"
CASE_DIR="${OUTPUT_DIR}/${CASE_ID}"
HASH_LOG="${CASE_DIR}/hashes.txt"

mkdir -p "${CASE_DIR}/disk_image" \
         "${CASE_DIR}/fs" \
         "${CASE_DIR}/logs"

log() {
    printf '{"ts":"%s","event":"%s"}\n' "$(date -Iseconds)" "$1" \
        >> "${CASE_DIR}/logs/session.log"
}

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

log "boot_mode_start"

# Show available disks
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,MODEL

printf 'target disk (e.g. sda, nvme0n1): '
read -r TARGET_DISK

if [ ! -b "/dev/${TARGET_DISK}" ]; then
    printf 'error: /dev/%s not found\n' "${TARGET_DISK}" >&2
    exit 1
fi

log "target=/dev/${TARGET_DISK}"

# Software write-block — applied immediately, never removed by this script
blockdev --setro "/dev/${TARGET_DISK}" 2>/dev/null
for part in /dev/${TARGET_DISK}[0-9]*; do
    [ -b "${part}" ] && blockdev --setro "${part}" 2>/dev/null
done
log "write_block_set=/dev/${TARGET_DISK}"

# Disk image
printf 'create full disk image? [y/N]: '
read -r DO_IMAGE
if [ "${DO_IMAGE}" = "y" ] || [ "${DO_IMAGE}" = "Y" ]; then
    IMG="${CASE_DIR}/disk_image/${TARGET_DISK}.img"
    if command -v dcfldd > /dev/null 2>&1; then
        dcfldd if="/dev/${TARGET_DISK}" of="${IMG}" \
            bs=512 conv=noerror,sync \
            hashwindow=256M hash=sha256 \
            hashlog="${CASE_DIR}/disk_image/dcfldd_hash.txt" \
            statusinterval=1024
    else
        dd if="/dev/${TARGET_DISK}" of="${IMG}" \
            bs=4M conv=noerror,sync \
            status=progress 2>> "${CASE_DIR}/logs/dd.log"
    fi
    if [ -f "${IMG}" ]; then
        h=$(sha256sum "${IMG}" | awk '{print $1}')
        printf '%s  disk_image/%s.img\n' "${h}" "${TARGET_DISK}" >> "${HASH_LOG}"
        printf '%s\n' "${h}" > "${IMG}.sha256"
        log "disk_image_complete=${IMG}"
    fi
fi

# Mount each partition read-only — noatime prevents atime writes on target
mkdir -p "${MOUNT_POINT}"
declare -a MOUNTED_PARTS=()

for part in $(lsblk "/dev/${TARGET_DISK}" -o NAME,FSTYPE --noheadings \
              | awk '$2 ~ /ext4|ext3|ext2|xfs|btrfs/ {print $1}'); do
    mp="${MOUNT_POINT}/${part}"
    mkdir -p "${mp}"
    if mount -o ro,noexec,nosuid,nodev,noatime "/dev/${part}" "${mp}" 2>/dev/null; then
        MOUNTED_PARTS+=("${part}")
        log "mounted_ro=/dev/${part}"

        # Collect from mounted filesystem — all writes go to CASE_DIR on USB
        ROOT="${mp}"

        for f in etc/passwd etc/shadow etc/group etc/sudoers etc/fstab \
                 etc/resolv.conf etc/hosts etc/ssh/sshd_config; do
            src="${ROOT}/${f}"
            [ -f "${src}" ] || continue
            dest="${CASE_DIR}/fs/$(printf '%s' "${f}" | tr '/' '_').txt"
            cp "${src}" "${dest}" 2>/dev/null
            h=$(sha256sum "${dest}" | awk '{print $1}')
            printf '%s  fs/%s\n' "${h}" "$(basename "${dest}")" >> "${HASH_LOG}"
        done

        artifact fs recently_modified.txt \
            "find '${ROOT}' -xdev -mtime -7 -type f 2>/dev/null | sed 's|${ROOT}||' | head -1000"

        artifact fs suid.txt \
            "find '${ROOT}' -xdev -perm -4000 -type f 2>/dev/null | sed 's|${ROOT}||'"

        artifact fs hidden_files.txt \
            "find '${ROOT}/home' '${ROOT}/root' -name '.*' -maxdepth 4 2>/dev/null | sed 's|${ROOT}||'"

        # Shell histories
        {
            find "${ROOT}/home" "${ROOT}/root" \
                -name '.bash_history' -o -name '.zsh_history' 2>/dev/null | \
            while IFS= read -r hf; do
                printf '=== %s ===\n' "${hf#"${ROOT}"}"
                cat "${hf}" 2>/dev/null
                printf '\n'
            done
        } > "${CASE_DIR}/fs/shell_histories.txt"
        h=$(sha256sum "${CASE_DIR}/fs/shell_histories.txt" | awk '{print $1}')
        printf '%s  fs/shell_histories.txt\n' "${h}" >> "${HASH_LOG}"

        # Logs
        for lf in var/log/syslog var/log/messages var/log/auth.log var/log/secure var/log/kern.log; do
            src="${ROOT}/${lf}"
            [ -f "${src}" ] || continue
            dest="${CASE_DIR}/fs/log_$(basename "${lf}").txt"
            cp "${src}" "${dest}" 2>/dev/null
            h=$(sha256sum "${dest}" | awk '{print $1}')
            printf '%s  fs/log_%s\n' "${h}" "$(basename "${lf}")" >> "${HASH_LOG}"
        done

        artifact fs installed_packages.txt \
            "grep '^Package:' '${ROOT}/var/lib/dpkg/status' 2>/dev/null | sort"

        umount "${mp}" 2>/dev/null
        log "unmounted=/dev/${part}"
    fi
done

# Write-block remains — never removed
log "boot_mode_end"

{
    printf 'case_id:      %s\n' "${CASE_ID}"
    printf 'target:       /dev/%s\n' "${TARGET_DISK}"
    printf 'write_block:  set (not removed)\n'
    printf 'artifacts:    %d\n' "$(find "${CASE_DIR}" -type f | wc -l)"
    printf 'end:          %s\n' "$(date -Iseconds)"
} > "${CASE_DIR}/logs/report.txt"
