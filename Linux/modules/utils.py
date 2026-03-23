#!/usr/bin/env python3

import os
import json
import hashlib
import subprocess
from datetime import datetime


def check_root():
    return os.geteuid() == 0


def create_case_dir(base, case_id):
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    d   = os.path.join(base, "{}_{}".format(case_id, ts))
    for sub in ("disk", "memory", "network", "logs"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    return d


def run(cmd, timeout=60, shell=False):
    """Execute command. Returns (stdout_bytes, returncode). Never raises."""
    try:
        r = subprocess.run(
            cmd if shell else (cmd.split() if isinstance(cmd, str) else cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            shell=shell,
        )
        return r.stdout, r.returncode
    except Exception:
        return b"", -1


def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "error"


def save(case_dir, subdir, filename, data):
    """
    Write data to <case_dir>/<subdir>/<filename>.
    data can be bytes or str.
    Appends sha256 + path to hashes.txt.
    All writes go to USB (case_dir) only — never to target filesystem.
    """
    path = os.path.join(case_dir, subdir, filename)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode, errors="replace" if mode == "w" else None) as f:
        f.write(data)
    digest = sha256(path)
    hash_line = "{}  {}/{}\n".format(digest, subdir, filename)
    with open(os.path.join(case_dir, "hashes.txt"), "a") as f:
        f.write(hash_line)
    return path


def save_json(case_dir, subdir, filename, obj):
    return save(case_dir, subdir, filename, json.dumps(obj, indent=2, default=str))


def log_event(case_dir, event, data=None):
    entry = {
        "ts":    datetime.now().isoformat(),
        "event": event,
    }
    if data:
        entry.update(data)
    line = json.dumps(entry) + "\n"
    with open(os.path.join(case_dir, "logs", "session.log"), "a") as f:
        f.write(line)


def tool_exists(name):
    out, rc = run("which {}".format(name))
    return rc == 0
