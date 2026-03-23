#!/usr/bin/env python3

import os
import json
from modules.utils import run, save, save_json, tool_exists


def collect_disk(case_dir):
    results = {}

    # Block devices
    out, _ = run("lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,LABEL,MODEL --json")
    try:
        data = json.loads(out)
    except Exception:
        data = {"raw": out.decode("utf-8", errors="replace")}
    save_json(case_dir, "disk", "block_devices.json", data)

    # Partition tables
    out1, _ = run("fdisk -l")
    out2, _ = run("parted -l")
    save(case_dir, "disk", "partition_tables.txt",
         out1.decode("utf-8", errors="replace") + "\n" + out2.decode("utf-8", errors="replace"))

    # MBR hex dump — read-only, 512 bytes from each disk
    mbr_out = {}
    devs, _ = run("lsblk -d -o NAME,TYPE --noheadings")
    for line in devs.decode("utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == "disk":
            disk = parts[0]
            raw, rc = run(["dd", "if=/dev/{}".format(disk), "bs=512", "count=1", "iflag=direct"], timeout=10)
            if rc == 0:
                save(case_dir, "disk", "mbr_{}.raw".format(disk), raw)
                xxd, _ = run("xxd /dev/{}".format(disk) + " -l 512", shell=True, timeout=10)
                save(case_dir, "disk", "mbr_{}.hex".format(disk),
                     xxd.decode("utf-8", errors="replace"))
            mbr_out[disk] = rc
    results["mbr_disks"] = mbr_out

    # Mounts / fstab
    out, _ = run("mount")
    save(case_dir, "disk", "mounts.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("cat /etc/fstab", shell=True)
    save(case_dir, "disk", "fstab.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("findmnt --json")
    try:
        save_json(case_dir, "disk", "findmnt.json", json.loads(out))
    except Exception:
        save(case_dir, "disk", "findmnt.txt", out.decode("utf-8", errors="replace"))

    # Disk usage
    out, _ = run("df -hT")
    save(case_dir, "disk", "df.txt", out.decode("utf-8", errors="replace"))

    # SMART
    if tool_exists("smartctl"):
        devs, _ = run("lsblk -d -o NAME,TYPE --noheadings")
        smart = b""
        for line in devs.decode("utf-8", errors="replace").splitlines():
            p = line.split()
            if len(p) == 2 and p[1] == "disk":
                o, _ = run(["smartctl", "-a", "/dev/{}".format(p[0])], timeout=30)
                smart += o + b"\n"
        if smart:
            save(case_dir, "disk", "smart.txt", smart.decode("utf-8", errors="replace"))

    # Recently modified files — read-only find, output to USB only
    out, _ = run("find / -xdev -mtime -7 -type f 2>/dev/null", shell=True, timeout=120)
    save(case_dir, "disk", "recently_modified.txt", out.decode("utf-8", errors="replace"))

    # SUID / SGID
    out1, _ = run("find / -xdev -perm -4000 -type f 2>/dev/null", shell=True, timeout=120)
    out2, _ = run("find / -xdev -perm -2000 -type f 2>/dev/null", shell=True, timeout=120)
    save(case_dir, "disk", "suid.txt", out1.decode("utf-8", errors="replace"))
    save(case_dir, "disk", "sgid.txt", out2.decode("utf-8", errors="replace"))

    # Hidden files in home dirs
    out, _ = run("find /home /root -name '.*' -maxdepth 4 2>/dev/null", shell=True, timeout=60)
    save(case_dir, "disk", "hidden_files.txt", out.decode("utf-8", errors="replace"))

    # Swap
    out, _ = run("cat /proc/swaps")
    save(case_dir, "disk", "swap.txt", out.decode("utf-8", errors="replace"))

    # /dev listing
    out, _ = run("ls -la /dev/")
    save(case_dir, "disk", "dev_listing.txt", out.decode("utf-8", errors="replace"))

    return results
