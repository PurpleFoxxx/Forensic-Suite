#!/usr/bin/env python3

import os
import sys
import argparse
import platform
from datetime import datetime

from modules.utils import check_root, create_case_dir, log_event
from modules.disk import collect_disk
from modules.memory import collect_memory
from modules.network import collect_network
from modules.report import generate_report

def parse_args():
    p = argparse.ArgumentParser(description="Linux Forensic Collector")
    p.add_argument("--output",       required=True, help="Output directory on USB")
    p.add_argument("--case",         default=None)
    p.add_argument("--investigator", default="unknown")
    p.add_argument("--module",       choices=["all","disk","memory","network"], default="all")
    p.add_argument("--pcap-duration", type=int, default=60)
    p.add_argument("--no-ram-dump",  action="store_true")
    return p.parse_args()

def main():
    args = parse_args()

    if not check_root():
        sys.stderr.write("ERROR: must run as root\n")
        sys.exit(1)

    if platform.system() != "Linux":
        sys.stderr.write("ERROR: Linux only\n")
        sys.exit(1)

    case_id  = args.case or "CASE-{}".format(datetime.now().strftime("%Y%m%d-%H%M%S"))
    case_dir = create_case_dir(args.output, case_id)

    meta = {
        "case_id":      case_id,
        "investigator": args.investigator,
        "hostname":     platform.node(),
        "kernel":       platform.release(),
        "start":        datetime.now().isoformat(),
    }

    log_event(case_dir, "session_start", meta)

    results = {"meta": meta, "modules": {}}

    if args.module in ("all", "disk"):
        results["modules"]["disk"] = collect_disk(case_dir)
        log_event(case_dir, "module_complete", {"module": "disk"})

    if args.module in ("all", "memory"):
        results["modules"]["memory"] = collect_memory(case_dir, skip_dump=args.no_ram_dump)
        log_event(case_dir, "module_complete", {"module": "memory"})

    if args.module in ("all", "network"):
        results["modules"]["network"] = collect_network(case_dir, pcap_duration=args.pcap_duration)
        log_event(case_dir, "module_complete", {"module": "network"})

    meta["end"] = datetime.now().isoformat()
    generate_report(case_dir, results)
    log_event(case_dir, "session_end", {"case_dir": case_dir})

if __name__ == "__main__":
    main()
