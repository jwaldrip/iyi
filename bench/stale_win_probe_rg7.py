#!/usr/bin/env python3
"""Probe for RG7 on Windows: where two builds of one program differ.

A probe, not a gate (see .github/workflows/stale-win-probe.yml). bench/stale_reproducible.sh
builds each samples/iyi program with --threads 1 and --threads 8 and compares the
executables; on Windows every one differed. This builds one program four ways
(threads 1 twice, threads 8 twice, each from an emptied cache), compares each pair,
and names the PE section and the bytes of every difference.

Usage: stale_win_probe_rg7.py REPO IYI WORK [program]
"""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

repo = Path(sys.argv[1])
iyi = sys.argv[2]
work = Path(sys.argv[3])
program = sys.argv[4] if len(sys.argv) > 4 else "hello.iyi"
work.mkdir(parents=True, exist_ok=True)
source = repo / "samples" / "iyi" / program

env = os.environ.copy()
sep = ";" if os.name == "nt" else ":"
env["ZERO_AR_DATE"] = "1"
env.setdefault("SOURCE_DATE_EPOCH", "0")
env["IYI_PATH"] = f"{repo / 'src'}{sep}{repo / 'samples' / 'iyi'}"
env["IYI_LIBRARY_PATH"] = str(repo / "lib")
cache = work / "cache"
env["IYI_CACHE_DIR"] = str(cache)


def build(label, *flags):
    if cache.exists():
        shutil.rmtree(cache)
    cache.mkdir()
    out = work / f"{label}.exe"
    result = subprocess.run([iyi, "build", *flags, "-o", str(out), str(source)], env=env, capture_output=True,
                            text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        print(f"{label}: build failed\n{result.stdout}\n{result.stderr}")
        return None
    return out.read_bytes()


def sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count, = struct.unpack_from("<H", data, pe + 6)
    optional_size, = struct.unpack_from("<H", data, pe + 20)
    table = pe + 24 + optional_size
    found = [("headers", 0, struct.unpack_from("<I", data, pe + 24 + 60)[0])]
    for index in range(count):
        name, vsize, vaddr, rawsize, rawptr = struct.unpack_from("<8sIIII", data, table + index * 40)
        found.append((name.rstrip(b"\0").decode("ascii", "replace"), rawptr, rawptr + rawsize))
    return found


def where(offsets, table):
    for name, start, end in table:
        if start <= offsets < end:
            return name
    return "?"


def compare(label, left, right):
    if left is None or right is None:
        return
    if left == right:
        print(f"{label}: identical ({len(left)} bytes)")
        return
    table = sections(left)
    size = min(len(left), len(right))
    ranges = []
    start = None
    for index in range(size):
        if left[index] != right[index]:
            if start is None:
                start = index
        elif start is not None:
            ranges.append((start, index))
            start = None
    if start is not None:
        ranges.append((start, size))
    total = sum(end - begin for begin, end in ranges)
    per_section = {}
    for begin, end in ranges:
        name = where(begin, table)
        per_section[name] = per_section.get(name, 0) + (end - begin)
    print(f"{label}: DIFFER, sizes {len(left)} vs {len(right)}, {len(ranges)} ranges, {total} bytes, by section {per_section}")
    for begin, end in ranges[:12]:
        print(f"   {begin:#x}-{end:#x} ({where(begin, table)}): {left[begin:min(end, begin + 24)].hex()} vs {right[begin:min(end, begin + 24)].hex()}")


a1 = build("t1a", "--threads", "1")
a2 = build("t1b", "--threads", "1")
b1 = build("t8a", "--threads", "8")
b2 = build("t8b", "--threads", "8")
compare("threads 1 against threads 1", a1, a2)
compare("threads 8 against threads 8", b1, b2)
compare("threads 1 against threads 8", a1, b1)
n1 = build("nd1", "--threads", "1", "--no-debug")
n8 = build("nd8", "--threads", "8", "--no-debug")
compare("--no-debug, threads 1 against threads 8", n1, n8)
