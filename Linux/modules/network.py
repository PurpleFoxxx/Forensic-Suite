#!/usr/bin/env python3
"""
Network collection — passive read only.
tcpdump runs in capture-only mode, no packets injected.
All output written to case_dir (USB) only.
"""

import os
import time
import json
import subprocess
from modules.utils import run, save, save_json, sha256, tool_exists


def collect_network(case_dir, pcap_duration=60):
    results = {}

    # ── VOLATILE FIRST ────────────────────────────────────────

    # Active connections — most volatile
    out, _ = run("ss -tupwan")
    save(case_dir, "network", "connections.txt", out.decode("utf-8", errors="replace"))

    # Parse to JSON
    conns = []
    for line in out.decode("utf-8", errors="replace").splitlines():
        if line.startswith(("tcp", "udp")):
            parts = line.split()
            if len(parts) >= 5:
                conns.append({
                    "proto":   parts[0],
                    "state":   parts[1] if len(parts) > 3 else "",
                    "local":   parts[4] if len(parts) > 4 else "",
                    "peer":    parts[5] if len(parts) > 5 else "",
                    "process": " ".join(parts[6:]) if len(parts) > 6 else "",
                })
    save_json(case_dir, "network", "connections.json", conns)
    results["established"] = sum(1 for c in conns if c.get("state") == "ESTAB")

    # Listening ports
    out1, _ = run("ss -tlpn")
    out2, _ = run("ss -ulpn")
    save(case_dir, "network", "listening.txt",
         out1.decode("utf-8", errors="replace") + "\n" + out2.decode("utf-8", errors="replace"))

    # ARP / neighbor table — volatile
    out, _ = run("ip neigh show")
    save(case_dir, "network", "arp.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("ip -j neigh show")
    try:
        save_json(case_dir, "network", "arp.json", json.loads(out))
    except Exception:
        pass

    # Interfaces
    out, _ = run("ip addr show")
    save(case_dir, "network", "interfaces.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("ip -j addr show")
    try:
        save_json(case_dir, "network", "interfaces.json", json.loads(out))
    except Exception:
        pass

    # Routing
    out1, _ = run("ip route show")
    out2, _ = run("ip -6 route show")
    save(case_dir, "network", "routes.txt",
         out1.decode("utf-8", errors="replace") + "\n" + out2.decode("utf-8", errors="replace"))

    out, _ = run("ip -j route show")
    try:
        save_json(case_dir, "network", "routes.json", json.loads(out))
    except Exception:
        pass

    # /proc/net — raw kernel network tables, read-only
    for table in ("tcp", "tcp6", "udp", "udp6", "arp", "dev", "if_inet6", "sockstat"):
        path = "/proc/net/{}".format(table)
        if os.path.exists(path):
            with open(path, errors="replace") as f:
                save(case_dir, "network", "proc_net_{}.txt".format(table), f.read())

    # ── SEMI-VOLATILE ─────────────────────────────────────────

    # DNS config
    out, _ = run("cat /etc/resolv.conf")
    save(case_dir, "network", "resolv.conf", out.decode("utf-8", errors="replace"))

    out, _ = run("resolvectl status 2>/dev/null || systemd-resolve --status 2>/dev/null", shell=True)
    save(case_dir, "network", "resolved_status.txt", out.decode("utf-8", errors="replace"))

    # Hosts file
    out, _ = run("cat /etc/hosts")
    save(case_dir, "network", "hosts.txt", out.decode("utf-8", errors="replace"))

    # Firewall rules — read-only
    out, _ = run("iptables -L -n -v --line-numbers 2>/dev/null", shell=True)
    save(case_dir, "network", "iptables.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("iptables -t nat -L -n -v 2>/dev/null", shell=True)
    save(case_dir, "network", "iptables_nat.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("ip6tables -L -n -v 2>/dev/null", shell=True)
    save(case_dir, "network", "ip6tables.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("nft list ruleset 2>/dev/null", shell=True)
    save(case_dir, "network", "nftables.txt", out.decode("utf-8", errors="replace"))

    out, _ = run("ufw status verbose 2>/dev/null", shell=True)
    save(case_dir, "network", "ufw.txt", out.decode("utf-8", errors="replace"))

    # Wireless
    out, _ = run("iw dev 2>/dev/null", shell=True)
    save(case_dir, "network", "wireless.txt", out.decode("utf-8", errors="replace"))

    # SSH config
    for p in ("/etc/ssh/sshd_config", "/etc/ssh/ssh_config"):
        if os.path.exists(p):
            with open(p, errors="replace") as f:
                save(case_dir, "network", os.path.basename(p), f.read())

    out, _ = run("find / -name authorized_keys 2>/dev/null", shell=True, timeout=30)
    save(case_dir, "network", "authorized_keys_paths.txt", out.decode("utf-8", errors="replace"))

    # Network logs
    out, _ = run(
        "tail -500 /var/log/syslog 2>/dev/null || tail -500 /var/log/messages 2>/dev/null",
        shell=True, timeout=30
    )
    save(case_dir, "network", "syslog.txt", out.decode("utf-8", errors="replace"))

    # ── PACKET CAPTURE ────────────────────────────────────────
    # Passive sniff only — no packets sent, no NIC config change persists after process exits
    pcap_path = os.path.join(case_dir, "network", "capture.pcap")

    if tool_exists("tcpdump"):
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-i", "any", "-w", pcap_path, "-s", "0",
                 "--immediate-mode"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
            time.sleep(pcap_duration)
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            pass

        if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0:
            digest = sha256(pcap_path)
            with open(os.path.join(case_dir, "hashes.txt"), "a") as f:
                f.write("{}  network/capture.pcap\n".format(digest))
            results["pcap"] = pcap_path
            results["pcap_bytes"] = os.path.getsize(pcap_path)
        else:
            results["pcap"] = "empty"

    elif tool_exists("tshark"):
        try:
            subprocess.run(
                ["tshark", "-i", "any", "-w", pcap_path,
                 "-a", "duration:{}".format(pcap_duration)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                timeout=pcap_duration + 30,
            )
        except Exception:
            pass
        if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0:
            digest = sha256(pcap_path)
            with open(os.path.join(case_dir, "hashes.txt"), "a") as f:
                f.write("{}  network/capture.pcap\n".format(digest))
            results["pcap"] = pcap_path
        else:
            results["pcap"] = "empty"
    else:
        results["pcap"] = "no_tool"

    return results
