# 🪟 Forensic Suite — Windows

> Live forensic acquisition for Windows systems — RAM, Disk, Network, and System metadata. No external dependencies. Just run and go.

---

## What It Does

`acquire.ps1` is an interactive PowerShell script that walks you through a full live forensic acquisition on a running Windows machine. It collects:

- **RAM** — Full physical memory image via WinPmem
- **Disk** — Logical (drive letters) or Physical (raw disk) imaging with SHA-256 hashing via dc3dd
- **Network** — IP config, ARP table, active connections, routing table
- **System** — Running processes, system information

Everything lands in a timestamped case folder (`Forensic_Case_YYYYMMDD_HHMMSS`) on the evidence drive you choose. Logs and hash values are written alongside each artifact automatically.

---

## Requirements

- Windows (x64)
- PowerShell (run as **Administrator**)
- The bundled tools in `Windows-Tools\` — already included in the repo, no installs needed

---

## Getting Started

```powershell
git clone https://github.com/PurpleFoxxx/Forensic-Suite
cd "Forensic-Suite\Windows"
```

Bypass execution policy for the session, then run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\acquire.ps1
```

The script will prompt you for:

1. **Evidence drive** — where to store acquired data (e.g. `E:`, `F:`)
2. **Disk mode** — Logical (drive letters like `C:`, `D:`) or Physical (raw disks like `PhysicalDrive0`)
3. **Drive/disk selection** — which drives or disks to image

Everything else is automated.

---

## Output Structure

```
Forensic_Case_20260210_151935\
├── memory\
│   └── memory.raw
├── disks\
│   └── drive_D.img
├── network\
│   ├── ipconfig.txt
│   ├── arp.txt
│   ├── netstat.txt
│   └── routes.txt
└── logs\
    ├── winpmem.log
    ├── drive_D.log
    ├── systeminfo.txt
    └── tasks.txt
```

---

## Tools Used

| Tool                                             | Purpose                            |
| ------------------------------------------------ | ---------------------------------- |
| [WinPmem](https://github.com/Velocidex/WinPmem)  | Physical memory acquisition        |
| [dc3dd](https://sourceforge.net/projects/dc3dd/) | Forensic disk imaging with hashing |

Both tools are open source and bundled under `Windows-Tools\`. No internet connection required during acquisition.

---

## Disclaimer & Notice

This tool was developed in good faith for **lawful forensic investigation, incident response, and educational purposes** using open source, publicly available utilities.

The creators of Forensic Suite **accept no responsibility or liability** for any misuse, unlawful application, or damage arising from the use of this tool by any individual or organization.

**You are solely responsible for ensuring you have proper legal authorization before acquiring data from any system.** Unauthorized access to computer systems and data is illegal in most jurisdictions.

Use responsibly. Use lawfully.

---

_Part of [Forensic Suite](https://github.com/PurpleFoxxx/Forensic-Suite) — cross-platform live forensic acquisition._
