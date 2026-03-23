# 🔬 Forensic Suite

> Cross-platform live forensic acquisition — pick your OS, plug in your drive, run one script. No installs. No dependencies. No traces left behind.

Forensic Suite is an open source, self-contained toolkit for acquiring digital evidence from live and offline systems across multiple operating environments. Designed for incident responders, digital forensic investigators, and security researchers who need a reliable, portable acquisition pipeline that works anywhere — even on the most minimal of systems.

**Current Status: Work in Progress 🚧**
The suite is under active development. Windows and Linux environments are functional. Additional platforms and features are being added.

---

## How It Works

Clone or copy the suite onto a USB drive. Connect it to the target machine, run the script for the appropriate OS as root/administrator, and walk away. Everything lands in a timestamped case folder on the USB — SHA-256 hashed, never touching the target filesystem beyond what the OS kernel itself exposes.

```
Forensic-Suite/
├── Windows/          ← PowerShell acquisition suite
├── Linux/            ← Bash + Python acquisition suite
└── README.md         ← you are here
```

---

## Supported Environments

### 🪟 Windows — `Windows/acquire.ps1`

**Status: Stable**

Interactive PowerShell script for live acquisition on running Windows systems.

| Capability | Details                                                          |
| ---------- | ---------------------------------------------------------------- |
| RAM        | Full physical memory image via WinPmem                           |
| Disk       | Logical (drive letters) or Physical (raw disk) imaging via dc3dd |
| Hashing    | SHA-256 per artifact, written alongside each image               |
| Network    | ipconfig, ARP, netstat, routing table                            |
| System     | Running processes, systeminfo                                    |

Quick start:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Windows\acquire.ps1
```

→ [Full Windows documentation](Windows/README.md)

---

### 🐧 Linux — `Linux/autorun.sh` / `Linux/boot_mode.sh`

**Status: Stable**

Dual-mode acquisition suite for live and offline Linux systems. Runs Python if available, falls back to pure Bash — works on any Linux system, no matter how stripped down.

| Capability | Details                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------- |
| RAM        | AVML → LiME → kcore fallback chain                                                          |
| Disk       | Block devices, MBR dumps, partition tables, SUID/SGID, recent/hidden files                  |
| Hashing    | SHA-256 per artifact, appended to `hashes.txt` at write time                                |
| Network    | Connections, ARP, interfaces, routes, firewall rules, passive packet capture                |
| System     | Processes, open FDs, memory maps, env vars, kernel modules, shell histories, cron, services |
| Boot Mode  | Software write-block + read-only mount + offline disk imaging — target never modified       |

Quick start (live):

```bash
sudo bash Linux/autorun.sh
```

Quick start (offline/boot):

```bash
sudo bash Linux/boot_mode.sh
```

→ [Full Linux documentation](Linux/README.md)

---

## Planned / In Progress

- [ ] macOS acquisition module
- [ ] Unified HTML evidence report across all platforms
- [ ] Timeline generation from collected artifacts
- [ ] Volatile memory analysis integration (Volatility 3)
- [ ] Bootable ISO with all tools pre-bundled

---

## Getting Started

```bash
git clone https://github.com/PurpleFoxxx/Forensic-Suite.git
```

Copy the cloned folder to a USB drive (preferably formatted exFAT for cross-platform compatibility), connect to the target machine, and run the appropriate script for the OS.

No pip installs. No npm. No NuGet. The suite carries everything it needs.

---

## Design Principles

**Volatility order** — RAM and network state are collected before disk artifacts everywhere. Evidence that disappears first is captured first.

**Write-nothing** — the suite never creates files on the target filesystem. All output is directed to the USB evidence directory only. In boot mode, a software write-block is applied to the target disk before any access.

**Integrity by default** — every artifact is SHA-256 hashed at the moment it is written. Chain of custody begins at acquisition, not after.

**Graceful degradation** — if a preferred tool isn't available, the suite falls back. AVML → LiME → kcore for RAM. Python → Bash for the full collection pipeline. dcfldd → dd for disk imaging. Something always runs.

**No external network** — the suite makes no outbound connections. Packet capture is passive receive only. Nothing is sent anywhere.

---

## Disclaimer & Responsible Use Notice

This toolkit was built in good faith by security researchers and developers using open source, publicly available tools, with the sole intent of supporting **lawful digital forensic investigation, incident response, and security research**.

**The creators of Forensic Suite hold no responsibility or liability for any misuse, unauthorized use, illegal activity, or damage caused by any individual or organization using this tool.**

This is a cybersecurity tool. With that comes responsibility:

- **Always obtain explicit written authorization** before acquiring data from any system you do not personally own
- **Unauthorized access to computer systems is a criminal offence** in virtually every jurisdiction worldwide
- Do not use this tool to surveil, harm, coerce, or violate the privacy of any individual
- Do not use this tool against systems, networks, or infrastructure you are not explicitly permitted to access

If you are unsure whether you have authorization — you do not have authorization.

The creators developed this with good intent. Use it with the same.

---

## Contributing

The project is a work in progress and contributions are welcome. If you find a bug, have a feature idea, or want to add support for a new platform or acquisition method, open an issue or pull request at [github.com/PurpleFoxxx/Forensic-Suite](https://github.com/PurpleFoxxx/Forensic-Suite).

---

_Built with open source tools. Shared in good faith._
