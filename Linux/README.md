# 🐧 Forensic Suite — Linux

> Live and offline forensic acquisition for Linux systems — RAM, Disk, Network, and System metadata. No external dependencies. Runs from USB. Writes nothing to the target filesystem.

---

## What It Does

The Linux suite handles two distinct acquisition scenarios:

**Live Mode** — target system is running. Run `autorun.sh` from a USB drive. It collects volatile data (RAM, processes, connections) before anything less volatile, ensuring maximum evidence preservation.

**Boot Mode** — target system is off or you need an offline acquisition. Boot from your forensic USB, run `boot_mode.sh`. It applies a software write-block to the target disk before any access, mounts partitions read-only with `noatime`, and images the disk — never modifying a single byte on the target.

All output is written exclusively to the USB/evidence directory. Nothing is ever created on the target filesystem.

---

## Acquisition Modes

### Live Mode — `autorun.sh`

The primary entry point. Automatically detects Python 3 (embedded runtime first, then system), and runs the full Python collector (`main.py`). Falls back to the pure-Bash collector (`bash_collector.sh`) if no Python is available — so it works on any Linux system, no matter how minimal.

Collects in strict volatility order:

1. **Memory** — running processes, open file descriptors, memory maps, environment variables, kernel modules, RAM dump (via AVML, LiME, or partial kcore)
2. **Network** — active connections, ARP table, interfaces, routes, firewall rules, packet capture (passive sniff via tcpdump or tshark)
3. **Disk** — block devices, partition tables, MBR dumps, mounts, SUID/SGID files, recently modified files, hidden files
4. **Persistence** — cron jobs, shell histories, auth logs, systemd services/timers, SSH authorized keys, `/etc/passwd`, `/etc/shadow`

### Boot Mode — `boot_mode.sh`

Offline acquisition from a bootable USB. Prompts for target disk, applies write-block immediately, optionally creates a full disk image (via `dcfldd` with SHA-256, or `dd`), then mounts each partition read-only to collect filesystem artifacts.

---

## Requirements

- Linux (any distribution)
- Root / `sudo` access
- No installation required — everything runs from the USB

Optional tools (used automatically if present on the target system):

| Tool                 | Purpose                                      |
| -------------------- | -------------------------------------------- |
| `avml`               | RAM acquisition (preferred)                  |
| `LiME`               | RAM acquisition (kernel module)              |
| `tcpdump` / `tshark` | Passive packet capture                       |
| `dcfldd`             | Disk imaging with inline hashing (boot mode) |
| `smartctl`           | SMART disk health data                       |
| `lsof`               | Extended open file descriptor listing        |

If none of the RAM tools are present, a partial kcore read is attempted as a fallback.

---

## Getting Started

```bash
git clone https://github.com/PurpleFoxxx/Forensic-Suite
cd Forensic-Suite/Linux
```

**Live acquisition:**

```bash
sudo bash autorun.sh
```

With optional parameters:

```bash
sudo INVESTIGATOR="Jane Doe" CASE_ID="IR-2026-001" PCAP_DURATION=120 bash autorun.sh
```

**Boot mode (offline):**

```bash
sudo bash boot_mode.sh
```

The script will prompt you to select the target disk and whether to create a full disk image.

**Python collector directly (if preferred):**

```bash
sudo python3 forensic_suite/main.py \
    --output /path/to/usb/evidence \
    --investigator "Jane Doe" \
    --case IR-2026-001 \
    --pcap-duration 120
```

Run specific modules only with `--module disk`, `--module memory`, or `--module network`. Skip RAM dump with `--no-ram-dump`.

---

## Output Structure

```
evidence/
└── CASE-20260210-151935_20260210_151935/
    ├── memory/
    │   ├── process_list.json
    │   ├── open_fds.json
    │   ├── proc_maps.txt
    │   ├── proc_environ.json
    │   ├── shell_histories.txt
    │   ├── lsmod.txt
    │   ├── dmesg.txt
    │   ├── auth_log.txt
    │   ├── cron.txt
    │   └── ram.raw
    ├── network/
    │   ├── connections.json
    │   ├── arp.json
    │   ├── interfaces.json
    │   ├── routes.json
    │   ├── iptables.txt
    │   ├── nftables.txt
    │   └── capture.pcap
    ├── disk/
    │   ├── block_devices.json
    │   ├── partition_tables.txt
    │   ├── mbr_sda.raw
    │   ├── mbr_sda.hex
    │   ├── recently_modified.txt
    │   ├── suid.txt
    │   └── hidden_files.txt
    ├── logs/
    │   ├── session.log
    │   ├── report.txt
    │   └── results.json
    └── hashes.txt
```

Every artifact has its SHA-256 hash recorded in `hashes.txt` at the moment of creation for chain-of-custody integrity.

---

## Tools Used

All tools referenced are open source and either bundled on the USB or optionally present on the target system. The suite is designed to function fully without any of them — the Bash fallback collector uses only standard POSIX utilities and `/proc`.

| Tool                                          | Purpose                            |
| --------------------------------------------- | ---------------------------------- |
| [AVML](https://github.com/microsoft/avml)     | Userspace RAM acquisition          |
| [LiME](https://github.com/504ensicsLabs/LiME) | Kernel module RAM acquisition      |
| [tcpdump](https://www.tcpdump.org/)           | Passive packet capture             |
| [dcfldd](https://dcfldd.sourceforge.net/)     | Forensic disk imaging with hashing |

---

## Disclaimer & Notice

This tool was developed in good faith for **lawful forensic investigation, incident response, and educational purposes** using open source, publicly available utilities.

The creators of Forensic Suite **accept no responsibility or liability** for any misuse, unlawful application, or damage arising from the use of this tool by any individual or organization.

**You are solely responsible for ensuring you have proper legal authorization before acquiring data from any system.** Unauthorized access to computer systems and data is illegal in most jurisdictions.

Use responsibly. Use lawfully.

---

_Part of [Forensic Suite](https://github.com/PurpleFoxxx/Forensic-Suite) — cross-platform live forensic acquisition._
