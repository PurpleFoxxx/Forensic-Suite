#!/usr/bin/env python3
"""
Memory collection order: volatile data first, then persistent.
All output written to case_dir (USB) only.
No files created on target filesystem.
"""

import os
import json
from modules.utils import run, save, save_json, sha256, log_event, tool_exists


def collect_memory(case_dir, skip_dump=False):
    results = {}

    # ── VOLATILE FIRST ────────────────────────────────────────

    # Running processes — most volatile, collect immediately
    out, _ = run("ps auxwwef")
    save(case_dir, "memory", "ps_full.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("pstree -p -a -l 2>/dev/null || ps --forest aux", shell=True)
    save(case_dir, "memory", "pstree.txt", out.decode("utf-8", errors="replace"))

    # Process details from /proc — read-only kernel interface
    procs = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        p = {"pid": pid}
        try:
            with open("/proc/{}/cmdline".format(pid), "rb") as f:
                p["cmdline"] = f.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except Exception:
            p["cmdline"] = ""
        try:
            with open("/proc/{}/status".format(pid)) as f:
                for line in f:
                    if line.startswith(("Name:", "State:", "PPid:", "Uid:", "Gid:", "VmRSS:")):
                        k, v = line.split(":", 1)
                        p[k.strip()] = v.strip()
        except Exception:
            pass
        try:
            p["exe"] = os.readlink("/proc/{}/exe".format(pid))
        except Exception:
            p["exe"] = ""
        procs.append(p)

    save_json(case_dir, "memory", "process_list.json", procs)
    results["process_count"] = len(procs)

    # Open file descriptors per process — /proc, read-only
    fd_data = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = "/proc/{}/fd".format(pid)
        fds = {}
        try:
            for fd in os.listdir(fd_dir):
                try:
                    fds[fd] = os.readlink(os.path.join(fd_dir, fd))
                except Exception:
                    pass
        except Exception:
            pass
        if fds:
            fd_data[pid] = fds
    save_json(case_dir, "memory", "open_fds.json", fd_data)

    # lsof if available
    if tool_exists("lsof"):
        out, _ = run("lsof -n -P", timeout=60)
        save(case_dir, "memory", "lsof.txt", out.decode("utf-8", errors="replace"))

    # Memory maps per process
    maps = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/{}/maps".format(pid)) as f:
                maps[pid] = f.read()
        except Exception:
            pass
    # Write combined maps to single file — do not create per-process files on target
    combined = ""
    for pid, content in maps.items():
        combined += "=== PID {} ===\n{}\n".format(pid, content)
    save(case_dir, "memory", "proc_maps.txt", combined)

    # Environment variables from /proc — read-only
    env_data = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/{}/environ".format(pid), "rb") as f:
                env_data[pid] = f.read().replace(b"\x00", b"\n").decode("utf-8", errors="replace")[:2000]
        except Exception:
            pass
    save_json(case_dir, "memory", "proc_environ.json", env_data)

    # /proc/meminfo
    out, _ = run("cat /proc/meminfo")
    save(case_dir, "memory", "meminfo.txt", out.decode("utf-8", errors="replace"))

    # vmstat
    out, _ = run("vmstat -s")
    save(case_dir, "memory", "vmstat.txt", out.decode("utf-8", errors="replace"))

    # Kernel modules — loaded into memory
    out, _ = run("lsmod")
    save(case_dir, "memory", "lsmod.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("sysctl -a 2>/dev/null", shell=True, timeout=30)
    save(case_dir, "memory", "sysctl.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("cat /proc/interrupts")
    save(case_dir, "memory", "interrupts.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("cat /proc/kallsyms", timeout=30)
    save(case_dir, "memory", "kallsyms.txt", out.decode("utf-8", errors="replace"))

    # ── SEMI-VOLATILE ─────────────────────────────────────────

    # Active user sessions
    out, _ = run("who")
    save(case_dir, "memory", "who.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("w")
    save(case_dir, "memory", "w.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("last -50")
    save(case_dir, "memory", "last.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("lastlog")
    save(case_dir, "memory", "lastlog.txt", out.decode("utf-8", errors="replace"))

    # System info
    out, _ = run("uname -a")
    save(case_dir, "memory", "uname.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("uptime")
    save(case_dir, "memory", "uptime.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("cat /etc/os-release")
    save(case_dir, "memory", "os_release.txt", out.decode("utf-8", errors="replace"))

    # ── PERSISTENCE / LESS VOLATILE ───────────────────────────

    out, _ = run("cat /etc/passwd")
    save(case_dir, "memory", "passwd.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("cat /etc/shadow 2>/dev/null", shell=True)
    save(case_dir, "memory", "shadow.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("cat /etc/group")
    save(case_dir, "memory", "group.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("cat /etc/sudoers 2>/dev/null", shell=True)
    save(case_dir, "memory", "sudoers.txt", out.decode("utf-8", errors="replace"))

    # Cron jobs
    cron = b""
    for p in ("/etc/crontab", "/etc/cron.d", "/var/spool/cron"):
        if os.path.isfile(p):
            with open(p, "rb") as f:
                cron += b"\n=== {} ===\n".format(p.encode()) + f.read()
        elif os.path.isdir(p):
            for fn in os.listdir(p):
                fp = os.path.join(p, fn)
                try:
                    with open(fp, "rb") as f:
                        cron += b"\n=== {} ===\n".format(fp.encode()) + f.read()
                except Exception:
                    pass
    save(case_dir, "memory", "cron.txt", cron.decode("utf-8", errors="replace"))

    out, _ = run("systemctl list-timers --all 2>/dev/null", shell=True)
    save(case_dir, "memory", "systemd_timers.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("systemctl list-units --type=service --all 2>/dev/null", shell=True)
    save(case_dir, "memory", "systemd_services.txt", out.decode("utf-8", errors="replace"))

    # Shell histories — read-only
    histories = []
    combined = ""
    for root, _, files in os.walk("/home"):
        for fn in files:
            if fn in (".bash_history", ".zsh_history", ".ash_history"):
                histories.append(os.path.join(root, fn))
    for p in ("/root/.bash_history", "/root/.zsh_history"):
        if os.path.exists(p):
            histories.append(p)
    for hp in histories:
        try:
            with open(hp, errors="replace") as f:
                combined += "\n=== {} ===\n{}".format(hp, f.read())
        except Exception:
            pass
    save(case_dir, "memory", "shell_histories.txt", combined)
    results["history_files"] = histories

    # Auth log
    out, _ = run(
        "tail -500 /var/log/auth.log 2>/dev/null || tail -500 /var/log/secure 2>/dev/null",
        shell=True
    )
    save(case_dir, "memory", "auth_log.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("dmesg 2>/dev/null", shell=True, timeout=30)
    save(case_dir, "memory", "dmesg.txt", out.decode("utf-8", errors="replace"))

    # ── RAM DUMP ──────────────────────────────────────────────
    if not skip_dump:
        dump_path = os.path.join(case_dir, "memory", "ram.raw")
        acquired = False

        if tool_exists("avml"):
            _, rc = run(["avml", dump_path], timeout=900)
            if rc == 0:
                acquired = True

        if not acquired and os.path.exists("/tmp/lime.ko"):
            _, rc = run(
                "insmod /tmp/lime.ko 'path={} format=raw'".format(dump_path),
                shell=True, timeout=900
            )
            if rc == 0:
                acquired = True

        if not acquired:
            # Partial kcore — read-only kernel memory interface
            raw, rc = run(
                ["dd", "if=/proc/kcore", "of={}".format(dump_path),
                 "bs=1M", "count=128", "iflag=direct"],
                timeout=120
            )
            if rc == 0:
                acquired = True

        if acquired and os.path.exists(dump_path):
            digest = sha256(dump_path)
            with open(os.path.join(case_dir, "hashes.txt"), "a") as f:
                f.write("{}  memory/ram.raw\n".format(digest))
            results["ram_dump"] = dump_path
        else:
            results["ram_dump"] = "failed"

    return results
