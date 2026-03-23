#!/usr/bin/env python3

import os
import json
from datetime import datetime
from modules.utils import save, save_json


def generate_report(case_dir, results):
    save_json(case_dir, "logs", "results.json", results)

    meta    = results.get("meta", {})
    modules = results.get("modules", {})
    disk    = modules.get("disk", {})
    memory  = modules.get("memory", {})
    network = modules.get("network", {})

    lines = [
        "Linux Forensic Report",
        "=" * 50,
        "case_id:      {}".format(meta.get("case_id", "")),
        "investigator: {}".format(meta.get("investigator", "")),
        "hostname:     {}".format(meta.get("hostname", "")),
        "kernel:       {}".format(meta.get("kernel", "")),
        "start:        {}".format(meta.get("start", "")),
        "end:          {}".format(meta.get("end", "")),
        "",
        "[disk]",
        "  mbr_disks:          {}".format(list(disk.get("mbr_disks", {}).keys())),
        "",
        "[memory]",
        "  process_count:      {}".format(memory.get("process_count", "")),
        "  history_files:      {}".format(memory.get("history_files", [])),
        "  ram_dump:           {}".format(memory.get("ram_dump", "not_attempted")),
        "",
        "[network]",
        "  established:        {}".format(network.get("established", "")),
        "  pcap:               {}".format(network.get("pcap", "")),
        "  pcap_bytes:         {}".format(network.get("pcap_bytes", "")),
        "",
        "[chain_of_custody]",
        "  hashes: {}".format(os.path.join(case_dir, "hashes.txt")),
        "=" * 50,
    ]

    save(case_dir, "logs", "report.txt", "\n".join(lines))
