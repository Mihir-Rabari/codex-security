#!/usr/bin/env python3
"""Print selected Linux process metadata for a diagnostic test run."""

import json
import os
import sys
import time
from pathlib import Path

TOOLS = {
    "bun": "bun",
    "node": "node",
    "git": "git",
    "python": "python",
    "python3": "python",
    "bash": "shell",
    "sh": "shell",
}


def read(path):
    try:
        return path.read_text()
    except OSError:
        return None


def stat(path):
    raw = read(path / "stat")
    if raw is None:
        return None
    name, fields = raw.rsplit(")", 1)
    fields = fields.split()
    result = {
        "pid": int(name.split("(", 1)[0]),
        "tool": TOOLS.get(name.split("(", 1)[1], "other"),
        "state": fields[0],
        "ppid": int(fields[1]),
        "user_ticks": int(fields[11]),
        "system_ticks": int(fields[12]),
        "start_ticks": int(fields[19]),
    }
    if result["state"] == "Z":
        result["wait_status"] = int(fields[49])
    return result


def snapshot(root, known):
    pending = [(root["pid"], root["start_ticks"]), *known.items()]
    found = {}
    while pending:
        pid, expected_start = pending.pop()
        if pid == os.getpid() or pid in found:
            continue
        path = Path("/proc") / str(pid)
        process = stat(path)
        if process is None or (
            expected_start is not None and process["start_ticks"] != expected_start
        ):
            continue
        found[pid] = process
        process["threads"] = []
        for task in path.joinpath("task").glob("[0-9]*"):
            thread = stat(task)
            if thread is None:
                continue
            thread.pop("tool")
            thread.pop("ppid")
            thread["tid"] = thread.pop("pid")
            thread["wchan"] = (read(task / "wchan") or "unavailable").strip()
            for line in (read(task / "status") or "").splitlines():
                key, _, value = line.partition(":")
                if key in {"voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"}:
                    thread[key] = int(value)
            process["threads"].append(thread)
            pending.extend((int(child), None) for child in (read(task / "children") or "").split())
    return found


def main():
    root = stat(Path("/proc") / sys.argv[1])
    if root is None:
        return
    known = {}
    started = time.monotonic()
    # Successful controls finish before ten minutes. Delay sampling until then.
    time.sleep(600)
    while True:
        current_root = stat(Path("/proc") / str(root["pid"]))
        if current_root is None or current_root["start_ticks"] != root["start_ticks"]:
            return
        processes = snapshot(root, known)
        current = {pid: p["start_ticks"] for pid, p in processes.items()}
        print(
            json.dumps(
                {
                    "diagnostic": "process-state",
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "processes": list(processes.values()),
                    "no_longer_observed": [
                        {"pid": pid, "start_ticks": start}
                        for pid, start in known.items()
                        if current.get(pid) != start
                    ],
                }
            ),
            flush=True,
        )
        known = current
        time.sleep(10)


if __name__ == "__main__":
    # Diagnostics must neither expose exception details nor affect the test command.
    try:
        main()
    except Exception:
        pass
